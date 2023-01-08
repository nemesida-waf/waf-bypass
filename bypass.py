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
from table_out import table_payload_zone, table_status_count_accuracy

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
        self.session = requests.Session()
        self.session.trust_env = False
        self.name_pattern = re.compile(r'\d+\.json')
        self.processing_result = {}
        self.calls = 0

        # init
        status_1, status_2, status_3, status_4 = 'PASSED', 'ERROR', 'FP', 'FN'
        self.statuses = ['', status_1, status_2, status_3, status_4]

    def start(self):
       
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
                                self.test_body(json_path, request_data.blocked, request_data.body, method, request_data.boundary)
                            else:
                                boundary = secrets.token_hex(30)  # 60 symbols
                                nl = '\r\n'
                                body_hdrs = 'Content-Disposition: form-data; name="' + secrets.token_urlsafe(5) + '"'
                                body = '--' + boundary + nl + body_hdrs + nl + nl + request_data.body + nl + '--' + boundary + '--' + nl
                                self.test_body(json_path, request_data.blocked, body, method, boundary)

                    # Other dirs
                    else:

                        if request_data.url:
                            self.test_url(request_data, json_path, method)

                        elif request_data.args:
                            self.test_args(request_data, json_path, method)

                        elif request_data.body:
                            self.test_body(request_data.blocked, request_data.body, json_path, method, None)

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

        table_status_count_accuracy(self.processing_result, self.statuses)
        table_payload_zone(self.processing_result, self.statuses)

    @staticmethod
    def test_error_processing(self, z, json_path, error):
        self.processing_result[str(json_path) + ':' + z] = self.statuses[2]
        print(f"{Fore.YELLOW}An error occurred while processing file {json_path} in {z}: {error}{Style.RESET_ALL}")

    @staticmethod
    def test_result_processing(self, blocked, status_code):
        
        if blocked:
            status = self.statuses[1] if status_code in self.block_code else self.statuses[4]
        else:
            status = self.statuses[1] if status_code not in self.block_code else self.statuses[3]
        
        return status

    def test_url(self, request_data, json_path, method):
        
        z = 'URL'
        url = urljoin(self.host, request_data.url)
        headers = {'User-Agent': self.ua, **self.headers}
        method = 'get' if not method else method
        
        try:

            result = self.session.request(
                method, url, headers=headers, proxies=self.proxy,
                timeout=self.timeout, verify=False
            )
            
            status = self.test_result_processing(self, request_data.blocked, result.status_code)
            self.processing_result[str(json_path) + ':' + z] = status
            
        except Exception as error:
            self.test_error_processing(self, z, json_path, error)

    def test_args(self, request_data, json_path, method):
        
        z = 'ARGS'
        params = request_data.args
        headers = {'User-Agent': self.ua, **self.headers}
        method = 'get' if not method else method
        
        try:
            
            result = self.session.request(
                method, self.host, headers=headers, params=params, proxies=self.proxy,
                timeout=self.timeout, verify=False
            )

            status = self.test_result_processing(self, request_data.blocked, result.status_code)
            self.processing_result[str(json_path) + ':' + z] = status

        except Exception as error:
            self.test_error_processing(self, z, json_path, error)

    def test_body(self, blocked, data, json_path, method, boundary):
        
        z = 'BODY'
        headers = {f"Content-Type": 'multipart/form-data; boundary=' + boundary, **self.headers} if boundary else self.headers
        headers = {'User-Agent': self.ua, **headers}
        method = 'post' if not method else method
        
        try:
            
            result = self.session.request(
                method, self.host, headers=headers, data=data, proxies=self.proxy,
                timeout=self.timeout, verify=False
            )

            status = self.test_result_processing(self, blocked, result.status_code)
            self.processing_result[str(json_path) + ':' + z] = status

        except Exception as error:
            self.test_error_processing(self, z, json_path, error)

    def test_cookie(self, request_data, json_path, method):
        
        z = 'COOKIE'
        cookies = {f"WBC-{secrets.token_urlsafe(6)}": request_data.cookie}
        headers = {'User-Agent': self.ua, **self.headers}
        method = 'get' if not method else method
        
        try:
            
            result = self.session.request(
                method, self.host, headers=headers, cookies=cookies, proxies=self.proxy,
                timeout=self.timeout, verify=False
            )

            status = self.test_result_processing(self, request_data.blocked, result.status_code)
            self.processing_result[str(json_path) + ':' + z] = status

        except Exception as error:
            self.test_error_processing(self, z, json_path, error)

    def test_ua(self, request_data, json_path, method):
        
        z = 'USER-AGENT'
        headers = {'User-Agent': request_data.ua, **self.headers}
        method = 'get' if not method else method
        
        try:
            
            result = self.session.request(
                method, self.host, headers=headers, proxies=self.proxy,
                timeout=self.timeout, verify=False
            )

            status = self.test_result_processing(self, request_data.blocked, result.status_code)
            self.processing_result[str(json_path) + ':' + z] = status

        except Exception as error:
            self.test_error_processing(self, z, json_path, error)

    def test_referer(self, request_data, json_path, method):
        
        z = 'REFERER'
        headers = {'Referer': request_data.referer, **self.headers}
        headers = {'User-Agent': self.ua, **headers}
        method = 'get' if not method else method
        
        try:
        
            result = self.session.request(
                method, self.host, headers=headers, proxies=self.proxy,
                timeout=self.timeout, verify=False
            )

            status = self.test_result_processing(self, request_data.blocked, result.status_code)
            self.processing_result[str(json_path) + ':' + z] = status

        except Exception as error:
            self.test_error_processing(self, z, json_path, error)

    def test_headers(self, request_data, json_path, method):
        
        z = 'HEADER'
        headers = {f"WBH-{secrets.token_urlsafe(6)}": request_data.headers, **self.headers}
        headers = {'User-Agent': self.ua, **headers}
        method = 'get' if not method else method
        
        try:
            
            result = self.session.request(
                method, self.host, headers=headers, proxies=self.proxy,
                timeout=self.timeout, verify=False
            )

            status = self.test_result_processing(self, request_data.blocked, result.status_code)
            self.processing_result[str(json_path) + ':' + z] = status

        except Exception as error:
            self.test_error_processing(self, z, json_path, error)
