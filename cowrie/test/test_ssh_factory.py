# -*- test-case-name: Cowrie SSH Factory Test Cases -*-

# Copyright (c) 2016 Benjamin Lelonek
# See LICENSE for details.

from twisted.trial import unittest

from cowrie.core import config
from cowrie.ssh.factory import CowrieSSHFactory
import json
import os
import shutil


class SSHFactoryTests(unittest.TestCase):

    def setUp(self):
        if '_trial_temp' in os.getcwd():
            if not os.path.exists('etc'):
                shutil.copytree('../etc', 'etc')
        with open('../cowrie/test/expected_results.json') as data_file:
            self.data = json.load(data_file)
        self.cfg = config.readConfigFile("../cowrie/test/unittests.cfg")
        self.defaults = {'MACs': ['hmac-md5', 'hmac-sha1'],
                         'ciphers': ['aes128-ctr',
                                     'aes192-ctr',
                                     'aes256-ctr',
                                     'aes128-cbc',
                                     '3des-cbc',
                                     'blowfish-cbc',
                                     'cast128-cbc',
                                     'aes192-cbc',
                                     'aes256-cbc'],
                         'compressions': ['zlib@openssh.com', 'zlib', 'none'],
                         'keyExchanges': ['diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1'],
                         'publicKeys': ['ssh-rsa', 'ssh-dss'],
                         'versionString': u'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2'}


    def test_factory_defaults(self):
        factory = CowrieSSHFactory(self.cfg)
        factory.startFactory()
        t = factory.buildProtocol(None)

        self.assertEqual(t.supportedMACs,self.defaults['MACs'])
        self.assertEqual(t.supportedCiphers,self.defaults['ciphers'])
        self.assertEqual(t.supportedCompressions,self.defaults['compressions'])
        self.assertEqual(t.supportedKeyExchanges,self.defaults['keyExchanges'])
        self.assertEqual(t.supportedPublicKeys,self.defaults['publicKeys'])
        self.assertEqual(t.ourVersionString,self.defaults['versionString'])


    def test_factory_ignores_unsupported(self):
        self.cfg.read_string(u"""
[ssh]
supported_key_exchanges = {keyExchanges},noexist
supported_ciphers = {ciphers},noexist
supported_public_keys = {publicKeys},noexist
supported_MACs = {MACs},noexist
supported_compressions = {compressions},noexist
        """.format(
            keyExchanges=','.join(self.defaults['keyExchanges']),
            ciphers=','.join(self.defaults['ciphers']),
            publicKeys=','.join(self.defaults['publicKeys']),
            MACs=','.join(self.defaults['MACs']),
            compressions=','.join(self.defaults['compressions']),
        ))

        factory = CowrieSSHFactory(self.cfg)
        factory.startFactory()
        t = factory.buildProtocol(None)

        self.assertEqual(t.supportedMACs,self.defaults['MACs'])
        self.assertEqual(t.supportedCiphers,self.defaults['ciphers'])
        self.assertEqual(t.supportedCompressions,self.defaults['compressions'])
        self.assertEqual(t.supportedKeyExchanges,self.defaults['keyExchanges'])
        self.assertEqual(t.supportedPublicKeys,self.defaults['publicKeys'])


    def test_factory_uses_default_when_all_unsupported(self):
        self.cfg.read_string(u"""
[ssh]
supported_key_exchanges = noexist
supported_ciphers = noexist
supported_public_keys = noexist
supported_MACs = noexist
supported_compressions = noexist
        """)

        factory = CowrieSSHFactory(self.cfg)
        factory.startFactory()
        t = factory.buildProtocol(None)

        self.assertEqual(t.supportedMACs,self.defaults['MACs'])
        self.assertEqual(t.supportedCiphers,self.defaults['ciphers'])
        self.assertEqual(t.supportedCompressions,self.defaults['compressions'])
        self.assertEqual(t.supportedKeyExchanges,self.defaults['keyExchanges'])
        self.assertEqual(t.supportedPublicKeys,self.defaults['publicKeys'])


    def test_factory_uses_only_listed(self):
        self.cfg.read_string(u"""
[ssh]
supported_key_exchanges = {keyExchanges}
supported_ciphers = {ciphers}
supported_public_keys = {publicKeys}
supported_MACs = {MACs}
supported_compressions = {compressions}
        """.format(
            keyExchanges=self.defaults['keyExchanges'][0],
            ciphers=self.defaults['ciphers'][0],
            publicKeys=self.defaults['publicKeys'][0],
            MACs=self.defaults['MACs'][0],
            compressions=self.defaults['compressions'][0],
        ))

        factory = CowrieSSHFactory(self.cfg)
        factory.startFactory()
        t = factory.buildProtocol(None)

        self.assertEqual(t.supportedMACs, [self.defaults['MACs'][0]])
        self.assertEqual(t.supportedCiphers, [self.defaults['ciphers'][0]])
        self.assertEqual(t.supportedCompressions, [self.defaults['compressions'][0]])
        self.assertEqual(t.supportedKeyExchanges, [self.defaults['keyExchanges'][0]])
        self.assertEqual(t.supportedPublicKeys, [self.defaults['publicKeys'][0]])


    def test_factory_accepts_multi_line(self):
        self.cfg.read_string(u"""
[ssh]
supported_key_exchanges = {keyExchanges}
supported_ciphers = {ciphers}
supported_public_keys = {publicKeys}
supported_MACs = {MACs}
supported_compressions = {compressions}
        """.format(
            keyExchanges='\n '.join(self.defaults['keyExchanges']),
            ciphers='\n '.join(self.defaults['ciphers']),
            publicKeys='\n '.join(self.defaults['publicKeys']),
            MACs='\n '.join(self.defaults['MACs']),
            compressions='\n '.join(self.defaults['compressions']),
        ))

        factory = CowrieSSHFactory(self.cfg)
        factory.startFactory()
        t = factory.buildProtocol(None)

        self.assertEqual(t.supportedMACs,self.defaults['MACs'])
        self.assertEqual(t.supportedCiphers,self.defaults['ciphers'])
        self.assertEqual(t.supportedCompressions,self.defaults['compressions'])
        self.assertEqual(t.supportedKeyExchanges,self.defaults['keyExchanges'])
        self.assertEqual(t.supportedPublicKeys,self.defaults['publicKeys'])
