# -*- coding: utf-8 -*-

# Author: Claud Xiao


import os
import re
import time
import getopt
import hashlib
from ftplib import FTP

from cowrie.core.honeypot import HoneyPotCommand
from cowrie.core.fs import *
from twisted.python import log


"""
"""

commands = {}


class command_ftpget(HoneyPotCommand):
    """
    """
    def help(self):
        self.write("""BusyBox v1.20.2 (2016-06-22 15:12:53 EDT) multi-call binary.

Usage: ftpget [OPTIONS] HOST [LOCAL_FILE] REMOTE_FILE

Download a file via FTP

	-c	Continue previous transfer
	-v	Verbose
	-u USER	Username
	-p PASS	Password
	-P NUM	Port\n\n""")

    def start(self):
        try:
            optlist, args = getopt.getopt(self.args, 'cvu:p:P:')
        except getopt.GetoptError as err:
            self.help()
            self.exit()
            return

        if len(args) < 2:
            self.help()
            self.exit()
            return

        self.verbose = False
        self.username = ''
        self.password = ''
        self.port = 21
        self.host = ''
        self.local_file = ''
        self.remote_path = ''

        for opt in optlist:
            if opt[0] == '-v':
                self.verbose = True
            elif opt[0] == '-u':
                self.username = opt[1]
            elif opt[0] == '-p':
                self.password = opt[1]
            elif opt[0] == '-P':
                try:
                    self.port = int(opt[1])
                except ValueError:
                    pass

        if len(args) == 2:
            self.host, self.remote_path = args
        elif len(args) >= 3:
            self.host, self.local_file, self.remote_path = args[:3]

        self.remote_dir = os.path.dirname(self.remote_path)
        self.remote_file = os.path.basename(self.remote_path)
        if not self.local_file:
            self.local_file = self.remote_file

        fakeoutfile = self.fs.resolve_path(self.local_file, self.protocol.cwd)
        path = os.path.dirname(fakeoutfile)
        if not path or \
                not self.fs.exists(path) or \
                not self.fs.isdir(path):
            self.write('ftpget: can\'t open \'%s\': No such file or directory' % self.local_file)
            self.exit()
            return

        cfg = self.protocol.cfg
        url = 'ftp://%s/%s' % (self.host, self.remote_path)
        self.download_path = cfg.get('honeypot', 'download_path')
        self.safeoutfile = '%s/%s_%s' % \
                           (self.download_path,
                            time.strftime('%Y%m%d%H%M%S'),
                            re.sub('[^A-Za-z0-9]', '_', url))

        result = self.ftp_download(self.safeoutfile)

        if not result:
            self.exit()
            return

        if not os.path.isfile(self.safeoutfile):
            log.msg("there's no file " + self.safeoutfile)
            self.exit()
            return

        shasum = hashlib.sha256(open(self.safeoutfile, 'rb').read()).hexdigest()
        hash_path = '%s/%s' % (self.download_path, shasum)

        # If we have content already, delete temp file
        if not os.path.exists(hash_path):
            os.rename(self.safeoutfile, hash_path)
        else:
            os.remove(self.safeoutfile)
        os.symlink( shasum, self.safeoutfile )

        log.msg(eventid='cowrie.session.file_download',
                format='Downloaded URL (%(url)s) with SHA-256 %(shasum)s to %(outfile)s',
                url=url,
                outfile=hash_path,
                shasum=shasum)

        # Update the honeyfs to point to downloaded file
        self.fs.mkfile(fakeoutfile, 0, 0, os.path.getsize(hash_path), 33188)
        self.fs.update_realfile(self.fs.getfile(fakeoutfile), hash_path)

        self.exit()

    def ftp_download(self, safeoutfile):
        ftp = FTP()

        # connect
        if self.verbose:
            self.write('Connecting to %s\n' % self.host)  # TODO: add its IP address after the host

        try:
            ftp.connect(host=self.host, port=self.port, timeout=30)
        except Exception, e:
            log.msg('FTP connect failed: host=%s, port=%s, err=%s' % (self.host, self.port, str(e)))
            self.write('ftpget: can\'t connect to remote host: Connection refused\n')
            return False

        # login
        if self.verbose:
            self.write('ftpget: cmd (null) (null)\n')
            if self.username:
                self.write('ftpget: cmd USER %s\n' % self.username)
            else:
                self.write('ftpget: cmd USER anonymous\n')
            if self.password:
                self.write('ftpget: cmd PASS %s\n' % self.password)
            else:
                self.write('ftpget: cmd PASS busybox@\n')

        try:
            ftp.login(user=self.username, passwd=self.password)
        except Exception, e:
            log.msg('FTP login failed: user=%s, passwd=%s, err=%s' % (self.username, self.password, str(e)))
            self.write('ftpget: unexpected server response to USER: %s\n' % str(e))
            ftp.quit()
            return False

        # download
        if self.verbose:
            self.write('ftpget: cmd TYPE I (null)\n')
            self.write('ftpget: cmd PASV (null)\n')
            self.write('ftpget: cmd SIZE %s\n' % self.remote_path)
            self.write('ftpget: cmd RETR %s\n' % self.remote_path)

        try:
            ftp.cwd(self.remote_dir)
            ftp.retrbinary('RETR %s' % self.remote_file, open(safeoutfile, 'wb').write)
        except Exception, e:
            log.msg('FTP retrieval failed: %s' % str(e))
            self.write('ftpget: unexpected server response to USER: %s\n' % str(e))
            ftp.quit()
            return False

        # quit
        if self.verbose:
            self.write('ftpget: cmd (null) (null)\n')
            self.write('ftpget: cmd QUIT (null)\n')

        ftp.quit()
        return True


commands['ftpget'] = command_ftpget
commands['/usr/bin/ftpget'] = command_ftpget
