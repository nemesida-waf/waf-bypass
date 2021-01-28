#!/usr/bin/env python3

import getopt
import sys

from bypass import WAFBypass
from requests.exceptions import MissingSchema
from table_out import bypass_table
from table_out import print_table

# init default
host = ''
proxy = ''

# Processing args from cmd
try:

    # read args from input
    args = sys.argv[1:]

    # input to lowercase
    for i in range(len(args)):
        args[i] = args[i].lower()

    # options
    args_options = ['host=', 'proxy=']

    # parsing args
    optlist, values = getopt.getopt(args, '', args_options)
    for k, v in optlist:
        if k == '--host':
            host = str(v)
        elif k == '--proxy':
            proxy = str(v)

except Exception as e:
    print('An error occurred while processing the target/proxy: {}'.format(e))
    sys.exit()

# check host
if not host:
    print("ERROR: the host is not set. Syntax: main.py --host=example.com:80 --proxy='http://proxy.example.com:3128'")
    sys.exit()

print('\n')
print('##')
print('# Target: ', host)
print('# Proxy: ', proxy)
print('##')
print('\n')

test = WAFBypass(host, proxy)

try:
    test.start_test()
    print_table()
    print('\n')
    bypass_table()

except MissingSchema:
    print('The protocol is not set for TARGET or PROXY')

print("\n")
