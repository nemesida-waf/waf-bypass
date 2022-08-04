#!/usr/bin/env python3

import getopt
import os
import re
import sys

from requests.exceptions import MissingSchema
from bypass import WAFBypass
from table_out import table_payload_zone, table_status_count_accuracy
from urllib3 import connectionpool, poolmanager


def patch_http_connection_pool(**constructor_kwargs):
    """
    This allows to override the default parameters of the
    HTTPConnectionPool constructor.
    For example, to increase the pool size to fix problems
    with "HttpConnectionPool is full, discarding connection"
    """
    class MyHTTPConnectionPool(connectionpool.HTTPConnectionPool):
        def __init__(self, *args, **kwargs):
            kwargs.update(constructor_kwargs)
            super(MyHTTPConnectionPool, self).__init__(*args, **kwargs)
    poolmanager.pool_classes_by_scheme['http'] = MyHTTPConnectionPool

    class MyHTTPSConnectionPool(connectionpool.HTTPSConnectionPool):
        def __init__(self, *args, **kwargs):
            kwargs.update(constructor_kwargs)
            super(MyHTTPSConnectionPool, self).__init__(*args, **kwargs)
    poolmanager.pool_classes_by_scheme['https'] = MyHTTPSConnectionPool

def help():
    print("Syntax: main.py --host=example.com:80 --proxy='http://proxy.example.com:3128'")
    print("To add an HTTP header to all requests: --header='foo: bar' [--header=...]")
    print("To set HTTP status codes as meaning 'waf blocked': --block=403 [--block=...].  If none given, default is 403.")

# Increasing max pool size
patch_http_connection_pool(maxsize=50)

# Init args
host = ''
proxy = ''

# Processing args from cmd
try:

    # read args from input
    launch_args = sys.argv[1:]

    # options
    launch_args_options = ['help', 'host=', 'proxy=', 'header=', 'block=']

    # parsing args
    headers = {}
    blockStatuses = {}
    optlist, values = getopt.getopt(launch_args, '', launch_args_options)
    for k, v in optlist:
        if k == '--help':
            help()
            sys.exit()
        if k == '--host':
            host = str(v).lower()
            # check host's schema
            if not re.search(r'^http[s]?://', host):
                host = 'http://' + host
        elif k == '--proxy':
            proxy = str(v).lower()
        elif k == '--header':
            hname, hval = str(v).split(':')
            hname = hname.strip()
            hval = hval.strip()
            headers[hname] = hval
        elif k == '--block':
            blockStatuses[int(v)] = True
    if len(blockStatuses) == 0:
        blockStatuses[403] = True

except Exception as e:
    print('An error occurred while processing the target/proxy: {}'.format(e))
    sys.exit()

# check host
if not host:
    print("ERROR: the host is not set.")
    help()
    sys.exit()

# create log. dir
try:
    log_dir = '/tmp/waf-bypass-log/'
    os.mkdir(log_dir)
except OSError:
    pass

print('\n')
print('##')
print('# Target: ', host)
print('# Proxy: ', proxy)
print('# Block: ', blockStatuses)
if len(headers) > 0:
    print('# Headers: ', headers)
print('##')
print('\n')

test = WAFBypass(host, proxy, blockStatuses, headers)

try:
    test.start_test()
    table_status_count_accuracy()
    table_payload_zone()
except KeyboardInterrupt:
    print('\nKeyboard Interrupt')

except MissingSchema:
    print('The protocol is not set for TARGET or PROXY')

print("\n")
