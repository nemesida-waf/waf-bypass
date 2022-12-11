#!/usr/bin/env python3

import os
import re
import secrets

import requests

from colorama import Fore
from colorama import Style
from logger import log_all, log_errors
from multiprocessing.dummy import Pool as ThreadPool
from os import walk
from request import Request
from urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urljoin

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class WAFBypass:
    def __init__(self, host, proxy, block_status, headers):
        self.host = host
        if not proxy:
            self.proxy = {'http': None, 'https': None}
        else:
            self.proxy = {'http': proxy, 'https': proxy}
        self.block_status = block_status
        self.headers = headers
        self.session = requests.Session()
        self.session.trust_env = False
        self.name_pattern = re.compile(r'\d+\.json')
        self.timeout = 150
        self.calls = 0

    def start_test(self):
        relative_path = ''
        work_dir = os.path.dirname(os.path.realpath(__file__))
        work_dir_payload = work_dir + '/payload'

        def test_request_data(json_path):
            """
            Extracting data from .json, testing it, logging test results
            :type json_path: str
            """
            try:
                request_data = Request(json_path)
                if request_data:
                    if request_data.req_body is not None:
                        self.test_body(request_data)
                    if request_data.ref is not None:
                        self.test_ref(request_data)
                    if request_data.args is not None:
                        self.test_args(request_data)
                    if request_data.ua is not None:
                        self.test_ua(request_data)
                    if request_data.cookie is not None:
                        self.test_cookie(request_data)
                    if request_data.req_header is not None:
                        self.test_header(request_data)
                    if request_data.url is not None:
                        self.test_url(request_data)
            except Exception as e:
                print(f'{Fore.RED}Error: {e}. More details in file {relative_path}{Style.RESET_ALL} {Request(json_path)}')

        # Append all .json paths in one list
        all_files_list = []
        for (dir_path, _, filenames) in walk(work_dir_payload):
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
            print(f'{colour}{request_data.path} in {test_type}: {status_test}{Style.RESET_ALL}')

        if request_data.blocked is True or request_data.blocked is None:
            if request.status_code in block_status:
                log_status_test = 'PASSED'
                dynamic_scan_status = 'PASSED'
                log_all(request_data.path, test_type, log_status_test)
                base_str(Fore.WHITE, dynamic_scan_status)
            else:
                log_status_test = 'FAILED_FN'
                dynamic_scan_status = 'FAILED'
                log_all(request_data.path, test_type, log_status_test)
                base_str(Fore.RED, dynamic_scan_status)

        elif request_data.blocked is False:
            if request.status_code not in block_status:
                log_status_test = 'PASSED'
                dynamic_scan_status = 'PASSED'
                log_all(request_data.path, test_type, log_status_test)
                base_str(Fore.WHITE, dynamic_scan_status)
            else:
                log_status_test = 'FAILED_FP'
                dynamic_scan_status = 'FAILED'
                log_all(request_data.path, test_type, log_status_test)
                base_str(Fore.RED, dynamic_scan_status)

        elif request_data.blocked is not True and request_data.blocked is not None and request_data.blocked is not False:
            log_status_test = 'ERROR'
            log_all(request_data.path, test_type, log_status_test)
            log_errors(request_data, test_type, log_status_test)
            print(f'{Fore.RED}Decoding JSON {request_data.path} has failed{Style.RESET_ALL}')

    def test_args(self, request_data):
        request = self.session.get(
            self.host, headers=self.headers, params=request_data.args, proxies=self.proxy, timeout=self.timeout, verify=False
        )
        self.output('ARGS', request_data, request, self.block_status)

    def test_ua(self, request_data):
        request = self.session.get(
            self.host, headers={'User-Agent': request_data.ua, **self.headers}, proxies=self.proxy, timeout=self.timeout, verify=False
        )
        self.output('UA', request_data, request, self.block_status)

    def test_ref(self, request_data):
        request = self.session.get(
            self.host, headers={'Referer': request_data.ref, **self.headers}, proxies=self.proxy, timeout=self.timeout, verify=False
        )
        self.output('Referer', request_data, request, self.block_status)

    def test_body(self, request_data):
        request = self.session.post(
            self.host, headers=self.headers, data=request_data.req_body, proxies=self.proxy, timeout=self.timeout, verify=False
        )
        self.output('Body', request_data, request, self.block_status)

    def test_cookie(self, request_data):
        request = self.session.get(
            self.host, headers=self.headers, cookies={f"CustomCookie{secrets.token_urlsafe(12)}": request_data.cookie}, proxies=self.proxy,
            timeout=self.timeout, verify=False
        )
        self.output('Cookie', request_data, request, self.block_status)

    def test_header(self, request_data):
        request = self.session.get(
            self.host, headers={f"CustomHeader": request_data.req_header, **self.headers}, proxies=self.proxy, timeout=self.timeout, verify=False
        )
        self.output('Header', request_data, request, self.block_status)

    def test_url(self, request_data):
        payload_url = urljoin(self.host, request_data.url)
        request = self.session.get(
            payload_url, headers=self.headers, proxies=self.proxy, timeout=self.timeout, verify=False
        )
        self.output('URL', request_data, request, self.block_status)
