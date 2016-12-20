# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

import re
import time

from twisted.conch.ssh import factory
from twisted.conch.ssh import keys
from twisted.python import log
from twisted.conch.openssh_compat import primes

from cowrie.core.config import getList
from cowrie.ssh import connection
from cowrie.ssh import userauth
from cowrie.ssh import transport
from cowrie.core import keys as cowriekeys


class CowrieSSHFactory(factory.SSHFactory):
    """
    This factory creates HoneyPotSSHTransport instances
    They listen directly to the TCP port
    """

    services = {
        'ssh-userauth': userauth.HoneyPotSSHUserAuthServer,
        'ssh-connection': connection.CowrieSSHConnection,
        }
    starttime = None
    privateKeys = None
    publicKeys = None
    primes = None
    tac = None # gets set later

    def __init__(self, cfg):
        self.cfg = cfg


    def logDispatch(self, *msg, **args):
        """
        Special delivery to the loggers to avoid scope problems
        """
        args['sessionno'] = 'S'+str(args['sessionno'])
        for output in self.tac.output_plugins:
            output.logDispatch(*msg, **args)


    def startFactory(self):
        """
        """
        # For use by the uptime command
        self.starttime = time.time()

        # Load/create keys
        rsaPubKeyString, rsaPrivKeyString = cowriekeys.getRSAKeys(self.cfg)
        dsaPubKeyString, dsaPrivKeyString = cowriekeys.getDSAKeys(self.cfg)
        self.publicKeys = {
          'ssh-rsa': keys.Key.fromString(data=rsaPubKeyString),
          'ssh-dss': keys.Key.fromString(data=dsaPubKeyString)}
        self.privateKeys = {
          'ssh-rsa': keys.Key.fromString(data=rsaPrivKeyString),
          'ssh-dss': keys.Key.fromString(data=dsaPrivKeyString)}

        # Precompute overridden settings so we can warn the user about what
        # was dropped due to missing Twisted support

        # Allow 'none' to be specified by profiles for ciphers and MACs
        twistedSupportedCiphers = transport.HoneyPotSSHTransport.supportedCiphers + ['none']
        twistedSupportedMACs = transport.HoneyPotSSHTransport.supportedMACs + ['none']
        twistedSupportedPublicKeys = transport.HoneyPotSSHTransport.supportedPublicKeys
        # zlib@openssh.com works despite not being in Twisted's initial list
        # so add it here to keep it from getting filtered out later
        twistedSupportedCompressions = transport.HoneyPotSSHTransport.supportedCompressions + ['zlib@openssh.com']
        twistedSupportedKeyExchanges = transport.HoneyPotSSHTransport.supportedKeyExchanges[:]

        _modulis = '/etc/ssh/moduli', '/private/etc/moduli'
        for _moduli in _modulis:
            try:
                self.primes = primes.parseModuliFile(_moduli)
                break
            except IOError as err:
                pass

        if not self.primes:
            if 'diffie-hellman-group-exchange-sha1' in twistedSupportedKeyExchanges:
                twistedSupportedKeyExchanges.remove('diffie-hellman-group-exchange-sha1')
                log.msg("No moduli, no diffie-hellman-group-exchange-sha1")
            if 'diffie-hellman-group-exchange-sha256' in twistedSupportedKeyExchanges:
                twistedSupportedKeyExchanges.remove('diffie-hellman-group-exchange-sha256')
                log.msg("No moduli, no diffie-hellman-group-exchange-sha256")

        # Reorder supported ciphers to resemble current openssh more
        self.options = {
            'keyExchanges': twistedSupportedKeyExchanges,
            'ciphers': ['aes128-ctr', 'aes192-ctr', 'aes256-ctr',
                        'aes128-cbc', '3des-cbc', 'blowfish-cbc',
                        'cast128-cbc', 'aes192-cbc', 'aes256-cbc'],
            'publicKeys': filter(lambda x: x in list(self.privateKeys.keys()),
                                 ['ssh-rsa', 'ssh-dss']),
            'MACs': ['hmac-md5', 'hmac-sha1'],
            'compressions': ['zlib@openssh.com', 'zlib', 'none'],
            'versionString': self.cfg.get('ssh', 'version_string',
                    fallback=self.cfg.get('honeypot', 'ssh_version_string',
                                          fallback="SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2")),
        }

        self.options['keyExchanges'] = getList(self.cfg, 'ssh', 'supported_key_exchanges',
                                               twistedSupportedKeyExchanges, self.options['keyExchanges'])

        self.options['ciphers'] = getList(self.cfg, 'ssh', 'supported_ciphers',
                                          twistedSupportedCiphers, self.options['ciphers'])

        self.options['publicKeys'] = getList(self.cfg, 'ssh', 'supported_public_keys',
                                             twistedSupportedPublicKeys, self.options['publicKeys'])

        self.options['MACs'] = getList(self.cfg, 'ssh', 'supported_MACs',
                                       twistedSupportedMACs, self.options['MACs'])

        self.options['compressions'] = getList(self.cfg, 'ssh', 'supported_compressions',
                                               twistedSupportedCompressions, self.options['compressions'])

        factory.SSHFactory.startFactory(self)
        log.msg("Ready to accept SSH connections")


    def stopFactory(self):
        """
        """
        factory.SSHFactory.stopFactory(self)


    def buildProtocol(self, addr):
        """
        Create an instance of the server side of the SSH protocol.

        @type addr: L{twisted.internet.interfaces.IAddress} provider
        @param addr: The address at which the server will listen.

        @rtype: L{cowrie.ssh.transport.HoneyPotSSHTransport}
        @return: The built transport.
        """

        t = transport.HoneyPotSSHTransport()

        t.ourVersionString = self.options['versionString']
        t.supportedKeyExchanges = self.options['keyExchanges']
        t.supportedCiphers = self.options['ciphers']
        t.supportedPublicKeys = self.options['publicKeys']
        t.supportedMACs = self.options['MACs']
        t.supportedCompressions = self.options['compressions']

        t.factory = self
        return t

