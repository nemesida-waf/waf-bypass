#!/usr/bin/env python3

import getopt
import re
import sys

from requests.exceptions import MissingSchema
from bypass import WAFBypass
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


def get_help():
    print("Usage: python3 /opt/waf-bypass/main.py --host=example.com:80 [OPTION]")
    print("")
    print("Mandatory arguments:")
    print("--proxy      - set proxy-server (e.g. --proxy='http://1.2.3.4:3128)") 
    print("--header     - add the HTTP header to all requests (e.g. --header='Authorization: Basic YWRtaW46YWRtaW4=')")
    print("--block-code - set the HTTP status codes as meaning 'WAF blocked' (e.g. --block-code=222, default: 403)")
    print("--threads    - set the number of parallel scan threads (e.g. --threads=10, default: 4)")
    print("--timeout    - set the request processing timeout in sec. (e.g. --timeout=10, default: 30)")
    

# Increasing max pool size
patch_http_connection_pool(maxsize=50)

# Init args
host = ''
proxy = ''
threads = 5
timeout = 30
headers = {}
processing_result = {}
ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'

# Processing args from cmd
try:

    # read args from input
    launch_args = sys.argv[1:]

    # options
    launch_args_options = ['help', 'host=', 'proxy=', 'header=', 'block-code=', 'threads=', 'timeout=']

    # parsing args
    block_code = {}
    optlist, values = getopt.getopt(launch_args, '', launch_args_options)
    
    for k, v in optlist:
        
        if k == '--help':
            get_help()
            sys.exit()
        
        if k == '--host':
            host = str(v).lower()
            # check host's schema
            if not re.search(r'^https?://', host):
                host = 'http://' + host
        
        elif k == '--proxy':
            proxy = str(v).lower()
        
        elif k == '--header':
            hname, hval = str(v).split(':')
            hname = hname.strip()
            hval = hval.strip()
            headers[hname] = hval
        
        elif k == '--block-code':
            block_code[int(v)] = True

        elif k == '--threads':
            threads = int(v)

        elif k == '--timeout':
            timeout = int(v)
    
    if len(block_code) == 0:
        block_code[403] = True

except Exception as e:
    print('An error occurred while processing the target/proxy: {}'.format(e))
    sys.exit()

# check host
if not host:
    print("ERROR: the host is not set.")
    get_help()
    sys.exit()

print('\n')
print('##')
print('# Target: {}'.format(host))

if len(proxy):
    print('# Proxy: {}'.format(proxy))
else:
    print('# Proxy: not used')

print('# Block status code: {}'.format(list(block_code.keys())[0]))

if len(headers) > 0:
    print('# Headers: {}'.format(headers))

print('##')

waf_bypass = WAFBypass(host, proxy, headers, ua, block_code, timeout, threads)

try:
    waf_bypass.start()
except KeyboardInterrupt:
    print('\nKeyboard Interrupt')

except MissingSchema:
    print('The protocol is not set for TARGET or PROXY')

print('\n')
