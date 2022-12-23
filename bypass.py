#!/usr/bin/env python3

import os
import re
import requests
import secrets

from colorama import Fore
from colorama import Style
from logger import log_all, log_errors
from multiprocessing.dummy import Pool as ThreadPool
from urllib.parse import urljoin

from payloads import PayloadProcessing

requests.packages.urllib3.disable_warnings()


class WAFBypass:
    
    def __init__(self, host, proxy, block_status, headers, ua):
        
        # init
        self.host = host
        self.proxy = {'http': proxy, 'https': proxy}
        self.block_status = block_status
        self.headers = headers
        self.ua = ua
        self.session = requests.Session()
        self.session.trust_env = False
        self.name_pattern = re.compile(r'\d+\.json')
        self.timeout = 150
        self.calls = 0

    def start_test(self):
       
        # init path
        relative_path = ''
        work_dir = os.path.dirname(os.path.realpath(__file__))
        work_dir_payload = work_dir + '/payload'

        def test_request_data(json_path):
            
            """
            Extracting data from .json, testing it, logging test results
            :type json_path: str
            """
            try:

                request_data = PayloadProcessing(json_path)
                if request_data:

                    # extract method
                    method = request_data.method

                    # MFD (multipart/form-data) dir
                    if 'MFD' in json_path:

                        # processing if body exists
                        if request_data.body:
                        
                            # processing request
                            if request_data.boundary:
                                self.test_body(request_data, method, request_data.boundary)
                            else:
                                boundary = secrets.token_hex(30)  # 60 symbols
                                body = '--' + boundary + request_data.body + '--' + boundary + '--\\x0D\\x0A'
                                self.test_body(body, method, boundary)

                    # Other dirs
                    else:

                        if request_data.url:
                            self.test_url(request_data, method)

                        elif request_data.args:
                            self.test_args(request_data, method)

                        elif request_data.body:
                            self.test_body(request_data, method, None)

                        elif request_data.cookie:
                            self.test_cookie(request_data, method)

                        elif request_data.ua:
                            self.test_ua(request_data, method)

                        elif request_data.referer:
                            self.test_referer(request_data, method)

                        elif request_data.headers:
                            self.test_headers(request_data, method)

            except Exception as e:
                print(f'{Fore.RED}Error: {e}. More details in file {relative_path}{Style.RESET_ALL} {PayloadProcessing(json_path)}')

        # Append all .json paths in one list
        all_files_list = []
        for (dir_path, _, filenames) in os.walk(work_dir_payload):
            for filename in filenames:
                relative_path = os.path.join(dir_path, filename)
                all_files_list.append(dir_path + '/' + filename)

        # Create threads
        needed_number_of_threads = 10
        processes = needed_number_of_threads - 4
        pool = ThreadPool(processes=processes)
        pool.map(test_request_data, all_files_list)

    @staticmethod
    def output(test_type, request_data, request, block_status):

        def base_str(colour, status_test):
            print(f"{colour}{request_data.json_path} in {test_type}: {status_test}{Style.RESET_ALL}")

        if request_data.blocked:

            if request.status_code in block_status:
                log_status_test = 'PASSED'
                dynamic_scan_status = 'PASSED'
                log_all(request_data.json_path, test_type, log_status_test)
                base_str(Fore.WHITE, dynamic_scan_status)
            else:
                log_status_test = 'FAILED_FN'
                dynamic_scan_status = 'FAILED'
                log_all(request_data.json_path, test_type, log_status_test)
                base_str(Fore.RED, dynamic_scan_status)

        elif not request_data.blocked:

            if request.status_code not in block_status:
                log_status_test = 'PASSED'
                dynamic_scan_status = 'PASSED'
                log_all(request_data.json_path, test_type, log_status_test)
                base_str(Fore.WHITE, dynamic_scan_status)
            else:
                log_status_test = 'FAILED_FP'
                dynamic_scan_status = 'FAILED'
                log_all(request_data.json_path, test_type, log_status_test)
                base_str(Fore.RED, dynamic_scan_status)

        else:
            log_status_test = 'ERROR'
            log_all(request_data.json_path, test_type, log_status_test)
            log_errors(request_data, test_type, log_status_test)
            print(f'{Fore.RED}Decoding JSON {request_data.json_path} has failed{Style.RESET_ALL}')

    def test_url(self, request_data, method):
        url = urljoin(self.host, request_data.url)
        headers = {'User-Agent': self.ua, **self.headers}
        method = 'get' if not method else method
        request = self.session.request(
            method, url, headers=headers, proxies=self.proxy,
            timeout=self.timeout, verify=False
        )
        self.output('URL', request_data, request, self.block_status)

    def test_args(self, request_data, method):
        params = request_data.args
        headers = {'User-Agent': self.ua, **self.headers}
        method = 'get' if not method else method
        request = self.session.request(
            method, self.host, headers=headers, params=params, proxies=self.proxy,
            timeout=self.timeout, verify=False
        )
        self.output('ARGS', request_data, request, self.block_status)

    def test_body(self, request_data, method, boundary):
        data = request_data.body
        headers = {f"Content-Type": 'multipart/form-data; boundary=' + boundary, **self.headers} if boundary else self.headers
        headers = {'User-Agent': self.ua, **headers}
        method = 'post' if not method else method
        request = self.session.request(
            method, self.host, headers=headers, data=data, proxies=self.proxy,
            timeout=self.timeout, verify=False
        )
        self.output('Body', request_data, request, self.block_status)

    def test_cookie(self, request_data, method):
        cookies = {f"CustomCookie{secrets.token_urlsafe(12)}": request_data.cookie}
        headers = {'User-Agent': self.ua, **self.headers}
        method = 'get' if not method else method
        request = self.session.request(
            method, self.host, headers=headers, cookies=cookies, proxies=self.proxy,
            timeout=self.timeout, verify=False
        )
        self.output('Cookie', request_data, request, self.block_status)

    def test_ua(self, request_data, method):
        headers = {'User-Agent': request_data.ua, **self.headers}
        method = 'get' if not method else method
        request = self.session.request(
            method, self.host, headers=headers, proxies=self.proxy,
            timeout=self.timeout, verify=False
        )
        self.output('User-Agent', request_data, request, self.block_status)

    def test_referer(self, request_data, method):
        headers = {'Referer': request_data.referer, **self.headers}
        headers = {'User-Agent': self.ua, **headers}
        method = 'get' if not method else method
        request = self.session.request(
            method, self.host, headers=headers, proxies=self.proxy,
            timeout=self.timeout, verify=False
        )
        self.output('Referer', request_data, request, self.block_status)

    def test_headers(self, request_data, method):
        headers = {f"CustomHeader": request_data.headers, **self.headers}
        headers = {'User-Agent': self.ua, **headers}
        method = 'get' if not method else method
        request = self.session.request(
            method, self.host, headers=headers, proxies=self.proxy,
            timeout=self.timeout, verify=False
        )
        self.output('Headers', request_data, request, self.block_status)
