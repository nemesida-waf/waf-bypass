#!/usr/bin/python3

import sys
import configparser
from requests.exceptions import MissingSchema
from bypass import waf_bypass

options = {}
settings_file = 'settings.conf'

config = configparser.ConfigParser()
try:
    config.read(settings_file)
    host = config['main']['TARGET']
    proxy = config['main']['PROXY']
except FileNotFoundError:
    print('File not found: {}'.format(settings_file))
    sys.exit()

test = waf_bypass(host, proxy)

try:
    test.start_test()
except MissingSchema:
    print('The protocol is not set for TARGET or PROXY')
