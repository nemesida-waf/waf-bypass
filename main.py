#!/usr/bin/python3

import sys
import configparser
from requests.exceptions import MissingSchema
from bypass import waf_bypass
from logger import logger_stat
from colorama import Fore, Style
from table_out import print_table
from table_out import bypass_table

options = {}
settings_file = 'settings.conf'

config = configparser.ConfigParser()
try:
    config.read(settings_file)
    host = config['main']['TARGET']
    proxy = config['main']['PROXY']
    print("Target: ",host)
except FileNotFoundError:
    print('File not found: {}'.format(settings_file))
    sys.exit()

test = waf_bypass(host, proxy)

try:
    test.start_test()
    print_table()
    print('\n')
    bypass_table()

except MissingSchema:
    print('The protocol is not set for TARGET or PROXY')
print("\n")
