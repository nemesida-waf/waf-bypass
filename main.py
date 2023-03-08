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
    class WBHTTPConnectionPool(connectionpool.HTTPConnectionPool):
        def __init__(self, *args, **kwargs):
            kwargs.update(constructor_kwargs)
            super(WBHTTPConnectionPool, self).__init__(*args, **kwargs)
    poolmanager.pool_classes_by_scheme['http'] = WBHTTPConnectionPool

    class WBHTTPSConnectionPool(connectionpool.HTTPSConnectionPool):
        def __init__(self, *args, **kwargs):
            kwargs.update(constructor_kwargs)
            super(WBHTTPSConnectionPool, self).__init__(*args, **kwargs)
    poolmanager.pool_classes_by_scheme['https'] = WBHTTPSConnectionPool


def get_help():
    print("Usage: python3 /opt/waf-bypass/main.py --host=example.com:80 [OPTION]")
    print("")
    print("Mandatory arguments:")
    print("--proxy       - set proxy-server (e.g. --proxy='http://1.2.3.4:3128)") 
    print("--header      - add the HTTP header to all requests (e.g. --header='Authorization: Basic YWRtaW46YWRtaW4='). Multiple use is allowed.")
    print("--user-agent  - set the HTTP User-Agent to send with all requests, except when the User-Agent is set by the payload (e.g. --user-agent='MyUserAgent 1/1')")
    print("--block-code  - set the HTTP status codes as meaning 'WAF blocked' (e.g. --block-code=222, default: 403). Multiple use is allowed.")
    print("--threads     - set the number of parallel scan threads (e.g. --threads=10, default: 4)")
    print("--timeout     - set the request processing timeout in sec. (e.g. --timeout=10, default: 30)")
    print("--json-format - display the result of the work in JSON format")
    print("--details     - display the False Positive and False Negative payloads (not available in JSON format)")
    print("--exclude-dir - exclude the payload's directory (e.g., --exclude-dir='FP'). Multiple use is allowed.")
    

# increasing max pool size
patch_http_connection_pool(maxsize=50)

# init params
host = ''
proxy = {}
headers = {}
threads = 5
timeout = 30
wb_result = {}
wb_result_json = False
details = False
exclude_dir = []

# set user-agent
headers['User-Agent'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'

# Processing args from cmd
try:

    # read args from input
    launch_args = sys.argv[1:]

    # options
    launch_args_options = [
        'help', 'host=', 'proxy=', 'header=', 'user-agent=', 'block-code=', 'threads=', 'timeout=', 'json-format', 'details', 'exclude-dir='
    ]

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

        elif k == '--user-agent':
            headers['User-Agent'] = v
        
        elif k == '--block-code':
            block_code[int(v)] = True

        elif k == '--threads':
            threads = int(v)

        elif k == '--timeout':
            timeout = int(v)

        elif k == '--json-format':
            wb_result_json = True

        elif k == '--details':
            details = True

        elif k == '--exclude-dir':
            exclude_dir.extend(v.replace(',', ' ').split())
    
    if len(block_code) == 0:
        block_code[403] = True

    # convert to uppercase
    exclude_dir = [x.upper() for x in exclude_dir]

except Exception as e:
    print('An error occurred while processing the TARGET/PROXY: {}'.format(e))
    sys.exit()

# check host
if not host:
    print('An error occurred: the TARGET is not set')
    get_help()
    sys.exit()

# print basic info
if not wb_result_json:

    print('')
    print('##')
    print('# Target:       {}'.format(host))
    print('# Proxy:        {}'.format(proxy)) if len(proxy) else print('# Proxy:')
    print('# Timeout:      {}s'.format(timeout))
    print('# Threads:      {}'.format(threads))
    print('# Block code:   {}'.format(list(block_code.keys())[0]))
    print('# Exclude dirs: {}'.format(' '.join(exclude_dir)))

    if len(headers) > 0:
        for k, v in headers.items():
            if k.lower() == 'user-agent':
                continue
            else:    
                print('# Headers:      {}: {}'.format(k, v))

    print('# User-Agent:   {}'.format(headers['User-Agent']))
    print('##')
    print('')

# update result dictionary
else:

    wb_result['TARGET'] = host
    wb_result['PROXY'] = proxy
    wb_result['HEADERS'] = headers
    wb_result['BLOCK-CODE'] = list(block_code.keys())
    wb_result['THREADS'] = threads
    wb_result['TIMEOUT'] = timeout
    wb_result['EXCLUDE-DIR'] = exclude_dir

# launch WAF Bypass
waf_bypass = WAFBypass(host, proxy, headers, block_code, timeout, threads, wb_result, wb_result_json, details, exclude_dir)

try:
    waf_bypass.start()
except KeyboardInterrupt:
    print('\nKeyboard Interrupt')

except MissingSchema:
    print('An error occurred: protocol is not set for TARGET or PROXY')

if not wb_result_json:
    print('')
