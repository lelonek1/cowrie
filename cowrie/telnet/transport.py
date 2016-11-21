# Copyright (C) 2015, 2016 GoSecure Inc.
"""
Telnet Transport and Authentication for the Honeypot

@author: Olivier Bilodeau <obilodeau@gosecure.ca>
"""

import time
import uuid

from twisted.python import log
from twisted.internet import protocol
from twisted.conch.telnet import AuthenticatingTelnetProtocol, ECHO, TRAPSIG, \
                                 ITelnetProtocol, ProtocolTransportMixin, \
                                 SGA, NAWS, MODE, LINEMODE, TelnetTransport, OptionRefuseds
from twisted.protocols.policies import TimeoutMixin

from cowrie.core.credentials import UsernamePasswordIP

class HoneyPotTelnetFactory(protocol.ServerFactory):
    """
    This factory creates HoneyPotTelnetAuthProtocol instances
    They listen directly to the TCP port
    """
    tac = None # gets set later

    def __init__(self, cfg):
        self.cfg = cfg


    # TODO logging clarity can be improved: see what SSH does
    def logDispatch(self, *msg, **args):
        """
        Special delivery to the loggers to avoid scope problems
        """
        args['sessionno'] = 'T'+str(args['sessionno'])
        for dblog in self.tac.dbloggers:
            dblog.logDispatch(*msg, **args)
        for output in self.tac.output_plugins:
            output.logDispatch(*msg, **args)


    def startFactory(self):
        """
        """
        try:
            honeyfs = self.portal.realm.cfg.get('honeypot', 'contents_path')
            issuefile = honeyfs + "/etc/issue.net"
            self.banner = open(issuefile).read()
        except IOError:
            self.banner = ""

        # Interactive protocols are kept here for the interact feature
        self.sessions = {}

        # For use by the uptime command
        self.starttime = time.time()

        # hook protocol
        self.protocol = lambda: CowrieTelnetTransport(HoneyPotTelnetAuthProtocol,
                                         self.portal)
        protocol.ServerFactory.startFactory(self)
        log.msg("Ready to accept Telnet connections")


    def stopFactory(self):
        """
        Stop output plugins
        """
        protocol.ServerFactory.stopFactory(self)


class HoneyPotTelnetAuthProtocol(AuthenticatingTelnetProtocol):
    """
    TelnetAuthProtocol that takes care of Authentication. Once authenticated this
    protocol is replaced with HoneyPotTelnetSession.
    """

    loginPrompt = 'login: '
    passwordPrompt = 'Password: '

    def connectionMade(self):
        """
        """
        self.factory.sessions[self.transport.transport.sessionno] = self.transport.transportId

        def testErr(_stuff=None, _why=None, **kw):
            if _stuff.type is OptionRefused and _stuff.value.args[0] == ECHO:
                pass  # expected option refusal
            else:
                log.err(_stuff, _why, **kw)

        def willEcho(*args, **kwargs):
            print 'sending will echo'
            log.err('sending will echo')
            self.transport.will(ECHO).addErrback(testErr)

        # Initial option negotation. Want something at least for Mirai
        #for opt in (SGA,ECHO,):
        #    self.transport.will(opt).addErrback(log.err)
        for opt in (ECHO,NAWS,):
            deferred = self.transport.do(opt).addErrback(testErr)
            if opt is ECHO:
                deferred.addBoth(willEcho)

        #self.transport.will(ECHO).addErrback(testErr)
        # I need to doubly escape here since my underlying
        # CowrieTelnetTransport hack would remove it and leave just \n
        self.transport.write(self.factory.banner.replace('\n', '\r\r\n'))
        self.transport.write(self.loginPrompt)


    def connectionLost(self, reason):
        """
        Fires on pre-authentication disconnects
        """
        if self.transport.transport.sessionno in self.factory.sessions:
            del self.factory.sessions[self.transport.transport.sessionno]
        AuthenticatingTelnetProtocol.connectionLost(self, reason)


    def telnet_User(self, line):
        """
        Overridden to conditionally kill 'WILL ECHO' which confuses clients
        that don't implement a proper Telnet protocol (most malware)
        """
        self.username = line
        # only send ECHO option if we are chatting with a real Telnet client
        #if self.transport.options: <-- doesn't work
        self.transport.wont(ECHO)
        # FIXME: this should be configurable or provided via filesystem
        self.transport.write(self.passwordPrompt)
        return 'Password'


    def telnet_Password(self, line):
        username, password = self.username, line
        del self.username
        def login(ignored):
            self.src_ip = self.transport.getPeer().host
            creds = UsernamePasswordIP(username, password, self.src_ip)
            d = self.portal.login(creds, self.src_ip, ITelnetProtocol)
            d.addCallback(self._cbLogin)
            d.addErrback(self._ebLogin)

        # are we dealing with a real Telnet client?
        if self.transport.options:
            # stop ECHO
            # even if ECHO negotiation fails we still want to attempt a login
            # this allows us to support dumb clients which is common in malware
            # thus the addBoth: on success and on exception (AlreadyNegotiating)
            self.transport.wont(ECHO).addBoth(login)
        else:
            # process login
            login('')

        return 'Discard'

    def _cbLogin(self, ial):
        """
        Fired on a successful login
        """
        interface, protocol, logout = ial
        self.protocol = protocol
        self.logout = logout
        self.state = 'Command'

        # Remove the short timeout of the login prompt. Timeout will be
        # provided later by the HoneyPotBaseProtocol class.
        self.transport.setTimeout(None)

        # replace myself with avatar protocol
        protocol.makeConnection(self.transport)
        self.transport.protocol = protocol


    def _ebLogin(self, failure):
    # TODO: provide a way to have user configurable strings for wrong password
        self.transport.write("\nLogin incorrect\n")
        self.transport.write(self.loginPrompt)
        self.state = "User"


    def enableLocal(self, opt):
        if opt == ECHO:
            return True
        elif opt == SGA:
            return True
        else:
            return False


    def enableRemote(self, opt):
        if opt == LINEMODE:
            self.transport.requestNegotiation(LINEMODE, MODE + chr(TRAPSIG))
            return True
        elif opt == NAWS:
            return True
        elif opt == SGA:
            return True
        else:
            return False



class CowrieTelnetTransport(TelnetTransport, TimeoutMixin):
    """
    """
    def connectionMade(self):
        self.transportId = uuid.uuid4().hex[:8]
        sessionno = self.transport.sessionno
        self.startTime = time.time()
        self.setTimeout(300)

        log.msg(eventid='cowrie.session.connect',
           format='New connection: %(src_ip)s:%(src_port)s (%(dst_ip)s:%(dst_port)s) [session: T%(sessionno)s]',
           src_ip=self.transport.getPeer().host, src_port=self.transport.getPeer().port,
           dst_ip=self.transport.getHost().host, dst_port=self.transport.getHost().port,
           session=self.transportId, sessionno='T'+str(sessionno))
        TelnetTransport.connectionMade(self)

    def write(self, bytes):
        """
        Because of the presence of two ProtocolTransportMixin in the protocol
        stack once authenticated, I need to override write() and remove a \r
        otherwise we end up with \r\r\n on the wire.

        It is kind of a hack. I asked for a better solution here:
        http://stackoverflow.com/questions/35087250/twisted-telnet-server-how-to-avoid-nested-crlf
        """
        self.transport.write(bytes.replace('\r\n', '\n'))


    def connectionLost(self, reason):
        """
        Fires on pre-authentication disconnects
        """
        self.setTimeout(None)
        TelnetTransport.connectionLost(self, reason)
        duration = time.time() - self.startTime
        log.msg(eventid='cowrie.session.closed',
            format='Connection lost after %(duration)d seconds',
            duration=duration)
