#!/usr/bin/env python3

import os
import re
import requests
import secrets

from colorama import Fore
from colorama import Style
from multiprocessing.dummy import Pool as ThreadPool
from urllib.parse import urljoin

from payloads import PayloadProcessing

requests.packages.urllib3.disable_warnings()


class WAFBypass:
    
    def __init__(self, host, proxy, block_code, headers, ua, timeout, threads):
        
        # init
        self.host = host
        self.proxy = {'http': proxy, 'https': proxy}
        self.block_code = block_code
        self.headers = headers
        self.ua = ua
        self.session = requests.Session()
        self.session.trust_env = False
        self.name_pattern = re.compile(r'\d+\.json')
        self.timeout = timeout
        self.threads = threads
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
                                self.test_body(json_path, request_data.body, method, request_data.boundary)
                            else:
                                boundary = secrets.token_hex(30)  # 60 symbols
                                nl = '\r\n'
                                body_hdrs = 'Content-Disposition: form-data; name="' + secrets.token_urlsafe(5) + '"'
                                body = '--' + boundary + nl + body_hdrs + nl + nl + request_data.body + nl + '--' + boundary + '--' + nl
                                self.test_body(json_path, body, method, boundary)

                    # Other dirs
                    else:

                        if request_data.url:
                            self.test_url(request_data, json_path, method)

                        elif request_data.args:
                            self.test_args(request_data, json_path, method)

                        elif request_data.body:
                            self.test_body(request_data.body, json_path, method, None)

                        elif request_data.cookie:
                            self.test_cookie(request_data, json_path, method)

                        elif request_data.ua:
                            self.test_ua(request_data, json_path, method)

                        elif request_data.referer:
                            self.test_referer(request_data, json_path, method)

                        elif request_data.headers:
                            self.test_headers(request_data, json_path, method)

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
        pool.map(test_request_data, all_files_list)

    @staticmethod
    def output_processing(test_type, json_path, error):
        print(f"{Fore.YELLOW}An error occurred while processing file {json_path} in {test_type}: {error}{Style.RESET_ALL}")

    def test_url(self, request_data, json_path, method):
        url = urljoin(self.host, request_data.url)
        headers = {'User-Agent': self.ua, **self.headers}
        method = 'get' if not method else method
        try:
            self.session.request(
                method, url, headers=headers, proxies=self.proxy,
                timeout=self.timeout, verify=False
            )
        except Exception as error:
            self.output_processing('URL', json_path, error)

    def test_args(self, request_data, json_path, method):
        params = request_data.args
        headers = {'User-Agent': self.ua, **self.headers}
        method = 'get' if not method else method
        try:
            self.session.request(
                method, self.host, headers=headers, params=params, proxies=self.proxy,
                timeout=self.timeout, verify=False
            )
        except Exception as error:
            self.output_processing('ARGS', json_path, error)

    def test_body(self, data, json_path, method, boundary):
        headers = {f"Content-Type": 'multipart/form-data; boundary=' + boundary, **self.headers} if boundary else self.headers
        headers = {'User-Agent': self.ua, **headers}
        method = 'post' if not method else method
        try:
            self.session.request(
                method, self.host, headers=headers, data=data, proxies=self.proxy,
                timeout=self.timeout, verify=False
            )
        except Exception as error:
            self.output_processing('BODY', json_path, error)

    def test_cookie(self, request_data, json_path, method):
        cookies = {f"WBC-{secrets.token_urlsafe(6)}": request_data.cookie}
        headers = {'User-Agent': self.ua, **self.headers}
        method = 'get' if not method else method
        try:
            self.session.request(
                method, self.host, headers=headers, cookies=cookies, proxies=self.proxy,
                timeout=self.timeout, verify=False
            )
        except Exception as error:
            self.output_processing('COOKIE', json_path, error)

    def test_ua(self, request_data, json_path, method):
        headers = {'User-Agent': request_data.ua, **self.headers}
        method = 'get' if not method else method
        try:
            self.session.request(
                method, self.host, headers=headers, proxies=self.proxy,
                timeout=self.timeout, verify=False
            )
        except Exception as error:
            self.output_processing('USER-AGENT', json_path, error)

    def test_referer(self, request_data, json_path, method):
        headers = {'Referer': request_data.referer, **self.headers}
        headers = {'User-Agent': self.ua, **headers}
        method = 'get' if not method else method
        try:
            self.session.request(
                method, self.host, headers=headers, proxies=self.proxy,
                timeout=self.timeout, verify=False
            )
        except Exception as error:
            self.output_processing('REFERER', json_path, error)

    def test_headers(self, request_data, json_path, method):
        headers = {f"WBH-{secrets.token_urlsafe(6)}": request_data.headers, **self.headers}
        headers = {'User-Agent': self.ua, **headers}
        method = 'get' if not method else method
        try:
            self.session.request(
                method, self.host, headers=headers, proxies=self.proxy,
                timeout=self.timeout, verify=False
            )
        except Exception as error:
            self.output_processing('HEADERS', json_path, error)
