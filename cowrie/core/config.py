# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

import configparser
import os

def readConfigFile(cfgfile):
    config = configparser.ConfigParser()
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
            print('WARNING: Profile %s could not be loaded due to error: %r'
                  % (profile_path, e))

    return cfg
