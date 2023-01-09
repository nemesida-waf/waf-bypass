#!/usr/bin/env python3

import os
import re
import requests
import secrets

from colorama import Fore
from colorama import Style
from multiprocessing.dummy import Pool as ThreadPool
from urllib.parse import urljoin

from payloads import get_payload
from tables import get_result_details, table_get_result_accuracy

requests.packages.urllib3.disable_warnings()


class WAFBypass:

    def __init__(self, host, proxy, headers, ua, block_code, timeout, threads):
        
        # init
        self.host = host
        self.proxy = {'http': proxy, 'https': proxy}
        self.block_code = block_code
        self.headers = headers
        self.ua = ua
        self.timeout = timeout
        self.threads = threads
        self.name_pattern = re.compile(r'\d+\.json')
        self.wb_result = {}
        self.calls = 0

        # init
        status_1, status_2, status_3, status_4 = 'PASSED', 'ERROR', 'FP', 'FN'
        self.statuses = ['', status_1, status_2, status_3, status_4]
        self.zones = ['URL', 'ARGS', 'BODY', 'COOKIE', 'USER-AGENT', 'REFERER', 'HEADER']

    def start(self):
       
        # init path
        relative_path = ''
        work_dir = os.path.dirname(os.path.realpath(__file__))
        work_dir_payload = work_dir + '/payload'

        def test_payload(json_path):
            try:

                payload = get_payload(json_path)
                if payload:
                    
                    # extract method
                    method = payload['METHOD']

                    # processing the payload of each zone
                    for z in payload:

                        # skip specific zone (e.g. boundary, method etc.)
                        if z not in self.zones:
                            continue

                        # skip empty
                        if not payload[z]:
                            continue

                        # MFD (multipart/form-data) dir
                        # (BODY processing only)
                        if z == 'BODY' and payload['BODY'] and '/MFD/' in json_path:

                            # processing request
                            if z == 'BOUNDARY':
                                k, v = test_body(self.host, self.ua, self.headers, self.proxy, self.timeout, self.statuses, self.block_code, payload, json_path, method, payload['BODY'], payload['BOUNDARY'])
                                self.wb_result[k] = v
                            else:
                                boundary = secrets.token_hex(30)  # 60 symbols
                                nl = '\r\n'
                                body_hdrs = 'Content-Disposition: form-data; name="' + secrets.token_urlsafe(5) + '"'
                                body = '--' + boundary + nl + body_hdrs + nl + nl + payload['BODY'] + nl + '--' + boundary + '--' + nl
                                k, v = test_body(self.host, self.ua, self.headers, self.proxy, self.timeout, self.statuses, self.block_code, payload, json_path, method, body, boundary)
                                self.wb_result[k] = v

                        # Other dirs
                        else:

                            if z == 'URL':
                                k, v = test_url(self.host, self.ua, self.headers, self.proxy, self.timeout, self.statuses, self.block_code, payload, json_path, method)
                                self.wb_result[k] = v

                            elif z == 'ARGS':
                                k, v = test_args(self.host, self.ua, self.headers, self.proxy, self.timeout, self.statuses, self.block_code, payload, json_path, method)
                                self.wb_result[k] = v

                            elif z == 'BODY':
                                k, v = test_body(self.host, self.ua, self.headers, self.proxy, self.timeout, self.statuses, self.block_code, payload, json_path, method, payload['BODY'], None)
                                self.wb_result[k] = v

                            elif z == 'COOKIE':
                                k, v = test_cookie(self.host, self.ua, self.headers, self.proxy, self.timeout, self.statuses, self.block_code, payload, json_path, method)
                                self.wb_result[k] = v

                            elif z == 'USER-AGENT':
                                k, v = test_ua(self.host, self.headers, self.proxy, self.timeout, self.statuses, self.block_code, payload, json_path, method)
                                self.wb_result[k] = v

                            elif z == 'REFERER':
                                k, v = test_referer(self.host, self.ua, self.headers, self.proxy, self.timeout, self.statuses, self.block_code, payload, json_path, method)
                                self.wb_result[k] = v

                            elif z == 'HEADER':
                                k, v = test_headers(self.host, self.ua, self.headers, self.proxy, self.timeout, self.statuses, self.block_code, payload, json_path, method)
                                self.wb_result[k] = v

            except Exception as e:
                print(f'{Fore.YELLOW}An error occurred while processing file {relative_path}: {e}{Style.RESET_ALL}')

        # Append all .json paths in one list
        all_files_list = []
        for (dir_path, _, filenames) in os.walk(work_dir_payload):
            for filename in filenames:
                relative_path = os.path.join(dir_path, filename)
                all_files_list.append(dir_path + '/' + filename)

        # Multithreading
        pool = ThreadPool(processes=self.threads)
        pool.map(test_payload, all_files_list)

        table_get_result_accuracy(self.wb_result, self.statuses)
        get_result_details(self.wb_result, self.statuses)
    

def test_url(host, ua, headers, proxy, timeout, statuses, block_code, payload, json_path, method):
    
    z = 'URL'
    url = urljoin(host, payload[z])
    headers = {'User-Agent': ua, **headers}
    method = 'get' if not method else method
    
    try:

        s = init_session()
        result = s.request(method, url, headers=headers, proxies=proxy, timeout=timeout, verify=False)
        
        k = str(str(json_path) + ':' + z)
        v = test_result_processing(payload['BLOCKED'], statuses, block_code, result.status_code)

        if v[0] == statuses[2]:
            v = v[1]
            print(f"{Fore.YELLOW}An incorrect response was received while processing request from file {json_path} in {z}: {v}{Style.RESET_ALL}")

    except Exception as error:
        k = str(str(json_path) + ':' + z)
        v = statuses[2]
        print(f"{Fore.YELLOW}An error occurred while processing file {json_path} in {z}: {error}{Style.RESET_ALL}")

    return k, v


def test_args(host, ua, headers, proxy, timeout, statuses, block_code, payload, json_path, method):
    
    z = 'ARGS'
    params = payload[z]
    headers = {'User-Agent': ua, **headers}
    method = 'get' if not method else method
    
    try:
        
        s = init_session()
        result = s.request(method, host, headers=headers, params=params, proxies=proxy, timeout=timeout, verify=False)

        k = str(str(json_path) + ':' + z)
        v = test_result_processing(payload['BLOCKED'], statuses, block_code, result.status_code)

        if v[0] == statuses[2]:
            v = v[1]
            print(f"{Fore.YELLOW}An incorrect response was received while processing request from file {json_path} in {z}: {v}{Style.RESET_ALL}")

    except Exception as error:
        k = str(str(json_path) + ':' + z)
        v = statuses[2]
        print(f"{Fore.YELLOW}An error occurred while processing file {json_path} in {z}: {error}{Style.RESET_ALL}")

    return k, v


def test_body(host, ua, headers, proxy, timeout, statuses, block_code, payload, json_path, method, data, boundary):
    
    z = 'BODY'
    headers = {f"Content-Type": 'multipart/form-data; boundary=' + boundary, **headers} if boundary else headers
    headers = {'User-Agent': ua, **headers}
    method = 'post' if not method else method
    
    try:
        
        s = init_session()
        result = s.request(method, host, headers=headers, data=data, proxies=proxy, timeout=timeout, verify=False)

        k = str(str(json_path) + ':' + z)
        v = test_result_processing(payload['BLOCKED'], statuses, block_code, result.status_code)

        if v[0] == statuses[2]:
            v = v[1]
            print(f"{Fore.YELLOW}An incorrect response was received while processing request from file {json_path} in {z}: {v}{Style.RESET_ALL}")

    except Exception as error:
        k = str(str(json_path) + ':' + z)
        v = statuses[2]
        print(f"{Fore.YELLOW}An error occurred while processing file {json_path} in {z}: {error}{Style.RESET_ALL}")

    return k, v


def test_cookie(host, ua, headers, proxy, timeout, statuses, block_code, payload, json_path, method):
    
    z = 'COOKIE'
    cookies = {f"WBC-{secrets.token_urlsafe(6)}": payload[z]}
    headers = {'User-Agent': ua, **headers}
    method = 'get' if not method else method
    
    try:
        
        s = init_session()
        result = s.request(method, host, headers=headers, cookies=cookies, proxies=proxy, timeout=timeout, verify=False)

        k = str(str(json_path) + ':' + z)
        v = test_result_processing(payload['BLOCKED'], statuses, block_code, result.status_code)

        if v[0] == statuses[2]:
            v = v[1]
            print(f"{Fore.YELLOW}An incorrect response was received while processing request from file {json_path} in {z}: {v}{Style.RESET_ALL}")

    except Exception as error:
        k = str(str(json_path) + ':' + z)
        v = statuses[2]
        print(f"{Fore.YELLOW}An error occurred while processing file {json_path} in {z}: {error}{Style.RESET_ALL}")

    return k, v


def test_ua(host, headers, proxy, timeout, statuses, block_code, payload, json_path, method):
    
    z = 'USER-AGENT'
    headers = {'User-Agent': payload[z], **headers}
    method = 'get' if not method else method
    
    try:
        
        s = init_session()
        result = s.request(method, host, headers=headers, proxies=proxy, timeout=timeout, verify=False)

        k = str(str(json_path) + ':' + z)
        v = test_result_processing(payload['BLOCKED'], statuses, block_code, result.status_code)

        if v[0] == statuses[2]:
            v = v[1]
            print(f"{Fore.YELLOW}An incorrect response was received while processing request from file {json_path} in {z}: {v}{Style.RESET_ALL}")

    except Exception as error:
        k = str(str(json_path) + ':' + z)
        v = statuses[2]
        print(f"{Fore.YELLOW}An error occurred while processing file {json_path} in {z}: {error}{Style.RESET_ALL}")

    return k, v


def test_referer(host, ua, headers, proxy, timeout, statuses, block_code, payload, json_path, method):
    
    z = 'REFERER'
    headers = {'Referer': payload['REFERER'], **headers}
    headers = {'User-Agent': ua, **headers}
    method = 'get' if not method else method
    
    try:
    
        s = init_session()
        result = s.request(method, host, headers=headers, proxies=proxy, timeout=timeout, verify=False)

        k = str(str(json_path) + ':' + z)
        v = test_result_processing(payload['BLOCKED'], statuses, block_code, result.status_code)

        if v[0] == statuses[2]:
            v = v[1]
            print(f"{Fore.YELLOW}An incorrect response was received while processing request from file {json_path} in {z}: {v}{Style.RESET_ALL}")

    except Exception as error:
        k = str(str(json_path) + ':' + z)
        v = statuses[2]
        print(f"{Fore.YELLOW}An error occurred while processing file {json_path} in {z}: {error}{Style.RESET_ALL}")

    return k, v


def test_headers(host, ua, headers, proxy, timeout, statuses, block_code, payload, json_path, method):
    
    z = 'HEADER'
    headers = {f"WBH-{secrets.token_urlsafe(6)}": payload[z], **headers}
    headers = {'User-Agent': ua, **headers}
    method = 'get' if not method else method
    
    try:
        
        s = init_session()
        result = s.request(method, host, headers=headers, proxies=proxy, timeout=timeout, verify=False)

        k = str(str(json_path) + ':' + z)
        v = test_result_processing(payload['BLOCKED'], statuses, block_code, result.status_code)

        if v[0] == statuses[2]:
            v = v[1]
            print(f"{Fore.YELLOW}An incorrect response was received while processing request from file {json_path} in {z}: {v}{Style.RESET_ALL}")

    except Exception as error:
        k = str(str(json_path) + ':' + z)
        v = statuses[2]
        print(f"{Fore.YELLOW}An error occurred while processing file {json_path} in {z}: {error}{Style.RESET_ALL}")

    return k, v


def init_session():
    s = requests.Session()
    s.trust_env = False
    return s


def test_result_processing(blocked, statuses, block_code, status_code):
    
    # if status code is not 20x and not in block codes list (403, 222 etc.) 
    if not str(status_code).startswith('20') and status_code not in block_code:
        status = [statuses[2], status_code]
    
    else:
        
        if blocked:
            
            if status_code in block_code:
                status = [statuses[1], status_code]
            else:
                status = [statuses[4], status_code]
        
        else:
            
            if status_code not in block_code:
                status = [statuses[1], status_code]
            else:
                status = [statuses[3], status_code]
    
    return status
