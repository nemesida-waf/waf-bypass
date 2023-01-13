#!/usr/bin/env python3

import os
import requests
import secrets

from colorama import Fore
from colorama import Style
from multiprocessing.dummy import Pool as ThreadPool
from urllib.parse import urljoin

from payloads import get_payload
from tables import get_result_details, table_get_result_accuracy

requests.packages.urllib3.disable_warnings()


def init_session():
    s = requests.Session()
    s.trust_env = False
    return s


def processing_result(blocked, statuses, block_code, status_code):
    
    # if status code is not 20x and not in block codes list (403, 222 etc.) 
    if (not str(status_code).startswith('20') or status_code == 404) and status_code not in block_code:
        status = [statuses[2], str(status_code) + ' RESPONSE CODE']
    else:
        if blocked:
            status = [statuses[1], status_code] if status_code in block_code else [statuses[4], status_code]        
        else:
            status = [statuses[1], status_code] if status_code not in block_code else [statuses[3], status_code]
    
    return status


class WAFBypass:

    def __init__(self, host, proxy, headers, block_code, timeout, threads):
        
        # init
        self.host = host
        self.proxy = {'http': proxy, 'https': proxy}
        self.block_code = block_code
        self.headers = headers
        self.timeout = timeout
        self.threads = threads
        self.wb_result = {}

        # init statuses
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
                
                # init
                body = ''
                headers = {}
                payload = get_payload(json_path)

                # if payload is empty
                if not payload:
                    print(f"{Fore.YELLOW}No payloads found during processing file {json_path}{Style.RESET_ALL}")
                    return
                    
                # API dir processing
                if '/API/' in json_path:
                    # (add a JSON header)
                    headers['Content-Type'] = 'application/json'

                # MFD (multipart/form-data) dir processing
                elif '/MFD/' in json_path:
                    
                    # if BODY is set
                    if payload['BODY']:

                        # if boundary is set
                        if payload['BOUNDARY']:

                            # set body/headers
                            body = payload['BODY']
                            headers['Content-Disposition'] = 'multipart/form-data; boundary=' + payload['BOUNDARY']

                        else:
                            
                            # header/boundary processing
                            boundary = secrets.token_hex(30)  # 60 symbols
                            nl = '\r\n'
                            body_cont_disp = 'Content-Disposition: form-data; name="' + secrets.token_urlsafe(5) + '"'

                            # set body/headers
                            body = '--' + boundary + nl + body_cont_disp + nl + nl + payload['BODY'] \
                                   + nl + '--' + boundary + '--' + nl
                            headers['Content-Disposition'] = 'multipart/form-data; boundary=' + boundary

                    else:
                        print(f"{Fore.YELLOW}An error occurred while processing payload from file {json_path}: empty BODY{Style.RESET_ALL}")
                        return
                
                # processing the payload of each zone
                for z in payload:

                    # skip specific zone (e.g. boundary, method etc.)
                    if z not in self.zones:
                        continue

                    # skip empty
                    if not payload[z]:
                        continue

                    # reset the method
                    default_method = 'post' if z == 'BODY' else 'get'
                    method = default_method if not payload['METHOD'] else payload['METHOD']

                    ##
                    # Processing the payloads
                    ##

                    if z == 'URL':
                        k = str(str(json_path) + ':' + z)
                        v = self.test_url(json_path, z, payload, method, headers)
                        self.wb_result[k] = v

                    elif z == 'ARGS':
                        k = str(str(json_path) + ':' + z)
                        v = self.test_args(json_path, z, payload, method, headers)
                        self.wb_result[k] = v

                    elif z == 'BODY':
                        k = str(str(json_path) + ':' + z)
                        v = self.test_body(json_path, z, payload, method, body, headers)
                        self.wb_result[k] = v

                    elif z == 'COOKIE':
                        k = str(str(json_path) + ':' + z)
                        v = self.test_cookie(json_path, z, payload, method, headers)
                        self.wb_result[k] = v

                    elif z == 'USER-AGENT':
                        k = str(str(json_path) + ':' + z)
                        v = self.test_ua(json_path, z, payload, method, headers)
                        self.wb_result[k] = v

                    elif z == 'REFERER':
                        k = str(str(json_path) + ':' + z)
                        v = self.test_referer(json_path, z, payload, method, headers)
                        self.wb_result[k] = v

                    elif z == 'HEADER':
                        k = str(str(json_path) + ':' + z)
                        v = self.test_header(json_path, z, payload, method, headers)
                        self.wb_result[k] = v

            except Exception as e:
                print(f'{Fore.YELLOW}An error occurred while processing file {relative_path}: {e}{Style.RESET_ALL}')
                return

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

    def test_url(self, json_path, z, payload, method, headers):            
        try:

            host = urljoin(self.host, payload[z])
            headers = {**self.headers, **headers}

            s = init_session()
            result = s.request(method, host, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)
            result = processing_result(payload['BLOCKED'], self.statuses, self.block_code, result.status_code)
            v = result[0]

            if v == self.statuses[2]:
                print(f"{Fore.YELLOW}An incorrect response was received while processing request from file {json_path} in {z}: {result[1]}{Style.RESET_ALL}")

        except Exception as error:
            v = self.statuses[2]
            print(f"{Fore.YELLOW}An error occurred while processing file {json_path} in {z}: {error}{Style.RESET_ALL}")

        return v

    def test_args(self, json_path, z, payload, method, headers):
        try:
            
            headers = {**self.headers, **headers}

            s = init_session()
            result = s.request(method, self.host, headers=headers, params=payload[z], proxies=self.proxy, timeout=self.timeout, verify=False)
            result = processing_result(payload['BLOCKED'], self.statuses, self.block_code, result.status_code)
            v = result[0]

            if v == self.statuses[2]:
                print(f"{Fore.YELLOW}An incorrect response was received while processing request from file {json_path} in {z}: {result[1]}{Style.RESET_ALL}")

        except Exception as error:
            v = self.statuses[2]
            print(f"{Fore.YELLOW}An error occurred while processing file {json_path} in {z}: {error}{Style.RESET_ALL}")

        return v

    def test_body(self, json_path, z, payload, method, body, headers):
        try:

            headers = {**self.headers, **headers}

            s = init_session()
            result = s.request(method, self.host, headers=headers, data=body, proxies=self.proxy, timeout=self.timeout, verify=False)
            result = processing_result(payload['BLOCKED'], self.statuses, self.block_code, result.status_code)
            v = result[0]

            if v == self.statuses[2]:
                print(f"{Fore.YELLOW}An incorrect response was received while processing request from file {json_path} in {z}: {result[1]}{Style.RESET_ALL}")

        except Exception as error:
            v = self.statuses[2]
            print(f"{Fore.YELLOW}An error occurred while processing file {json_path} in {z}: {error}{Style.RESET_ALL}")

        return v

    def test_cookie(self, json_path, z, payload, method, headers):
        try:
            
            headers = {**self.headers, **headers}
            cookies = {f"WBC-{secrets.token_hex(3)}": payload[z]}

            s = init_session()
            result = s.request(method, self.host, headers=headers, cookies=cookies, proxies=self.proxy, timeout=self.timeout, verify=False)
            result = processing_result(payload['BLOCKED'], self.statuses, self.block_code, result.status_code)
            v = result[0]

            if v == self.statuses[2]:
                print(f"{Fore.YELLOW}An incorrect response was received while processing request from file {json_path} in {z}: {result[1]}{Style.RESET_ALL}")

        except Exception as error:
            v = self.statuses[2]
            print(f"{Fore.YELLOW}An error occurred while processing file {json_path} in {z}: {error}{Style.RESET_ALL}")

        return v

    def test_ua(self, json_path, z, payload, method, headers):
        try:
            
            headers = {**self.headers, **headers, 'User-Agent': payload[z]}

            s = init_session()
            result = s.request(method, self.host, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)
            result = processing_result(payload['BLOCKED'], self.statuses, self.block_code, result.status_code)
            v = result[0]

            if v == self.statuses[2]:
                print(f"{Fore.YELLOW}An incorrect response was received while processing request from file {json_path} in {z}: {result[1]}{Style.RESET_ALL}")

        except Exception as error:
            v = self.statuses[2]
            print(f"{Fore.YELLOW}An error occurred while processing file {json_path} in {z}: {error}{Style.RESET_ALL}")

        return v

    def test_referer(self, json_path, z, payload, method, headers):
        try:

            headers = {**self.headers, **headers, 'Referer': payload[z]}

            s = init_session()
            result = s.request(method, self.host, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)
            result = processing_result(payload['BLOCKED'], self.statuses, self.block_code, result.status_code)
            v = result[0]

            if v == self.statuses[2]:
                print(f"{Fore.YELLOW}An incorrect response was received while processing request from file {json_path} in {z}: {result[1]}{Style.RESET_ALL}")

        except Exception as error:
            v = self.statuses[2]
            print(f"{Fore.YELLOW}An error occurred while processing file {json_path} in {z}: {error}{Style.RESET_ALL}")

        return v

    def test_header(self, json_path, z, payload, method, headers):            
        try:

            headers = {**self.headers, **headers, f"WBH-{secrets.token_hex(3)}": payload[z]}

            s = init_session()
            result = s.request(method, self.host, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)
            result = processing_result(payload['BLOCKED'], self.statuses, self.block_code, result.status_code)
            v = result[0]

            if v == self.statuses[2]:
                print(f"{Fore.YELLOW}An incorrect response was received while processing request from file {json_path} in {z}: {result[1]}{Style.RESET_ALL}")

        except Exception as error:
            v = self.statuses[2]
            print(f"{Fore.YELLOW}An error occurred while processing file {json_path} in {z}: {error}{Style.RESET_ALL}")

        return v
