# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

import configparser
import os
import re

from twisted.python import log


def readConfigFile(cfgfile):
    config = configparser.ConfigParser(
        interpolation=configparser.ExtendedInterpolation(),
        defaults={
            'empty': '',  # Prevent whitespace from being stripped: 'value: ${empty}' => 'value: '
            '\\n': '\n',  # New line: '${\n}'
            '\\r': '\r',  # Carriage return: '${\r}'
            '\\r\\n': '\r\n',  # CRLF: '${\r\n}'
            't\\r\\n': '\r\r\n',  # CRLF for telnet (see CowrieTelnetTransport.write()): '${t\r\n}'
            ' ': ' ',  # A single space character: '${ }'
            '\\t': '\t',  # Tab escape: '${\t}'
            '\t': '\t',  # Literal tab character: '${	}'
        })
    config.read(cfgfile)
    return config


def profilesEnabled(cfg):
    return cfg.getboolean('profile', 'enabled', fallback=False)


def getProfileNames(cfg):
    if profilesEnabled(cfg) and cfg.has_option('profile', 'enabled_profiles'):
        return cfg.get('profile', 'enabled_profiles').split('\n')
    return []


def loadProfiles(cfg):
    if cfg.has_option('profile', 'profile_directory'):
        profile_directory = cfg.get('profile', 'profile_directory')
    else:
        profile_directory = 'etc/profiles'
        cfg.set('profile', 'profile_directory', profile_directory)

    enabled_profiles = getProfileNames(cfg)
    for profile_path in enabled_profiles:
        try:
            cfg.read(os.path.join(profile_directory, profile_path, 'profile.cfg'))
        except configparser.Error as e:
            log.msg('WARNING: Profile %s could not be loaded due to error: %r'
                  % (profile_path, e))

    return cfg

def getList(cfg, section, option, twistedSupported, default):
    keep = []
    skip = []
    if cfg.has_option(section, option):
        for value in re.split(',\s*|\n', str(cfg.get(section, option))):
            if value in twistedSupported:
                keep.append(value)
            else:
                skip.append(value)

        if skip:
            log.msg("WARNING: the following %s values were ignored because they are not supported by twisted:\n[%s]" %
                    (option, ', '.join(skip)))

        if keep:
            return keep
        else:
            log.msg("WARNING: all listed %s values were unsupported, keeping default set" % option)
    return default
