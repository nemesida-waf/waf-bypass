#!/usr/bin/env python3

import os
import re
import secrets

import requests

from multiprocessing.dummy import Pool as ThreadPool
from colorama import Fore as f
from colorama import Style as s
from logger import log_all, log_errors
from os import walk
from request import Request
from urllib.parse import urljoin


class WAFBypass:
    def __init__(self, host, proxy):
        self.host = host
        if proxy == '':
            self.proxy = {'http': proxy, 'https': proxy}
        else:
            self.proxy = {'http': None, 'https': None}
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
            """Extracting data from .json, testing it, logging test results
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
                print(f'{f.RED}Error: {e}. Using file: {relative_path}{s.RESET_ALL} {Request(json_path)}')

        # Append all .json paths in one list
        all_files_list = []
        for (dir_path, _, filenames) in walk(work_dir_payload):
            for filename in filenames:
                relative_path = os.path.join(dir_path, filename)
                all_files_list.append(dir_path + '/' + filename)

        # Create threads
        NEEDED_NUMBER_OF_THREADS = 30
        processes = NEEDED_NUMBER_OF_THREADS - 4
        pool = ThreadPool(processes=processes)
        pool.map(test_request_data, all_files_list)

    @staticmethod
    def output(test_type, request_data, request):
        def base_str(colour, status_test):
            print(f'{colour}{request_data.path} in {test_type}: {status_test}{s.RESET_ALL}')
        if request_data.blocked is True or request_data.blocked is None:
            if request.status_code == 403:
                log_status_test = 'PASSED'
                dynamic_scan_status = 'PASSED'
                log_all(request_data.path, test_type, log_status_test)
                base_str(f.WHITE, dynamic_scan_status)
            else:
                log_status_test = 'FAILED_FN'
                dynamic_scan_status = 'FAILED'
                log_all(request_data.path, test_type, log_status_test)
                base_str(f.RED, dynamic_scan_status)

        elif request_data.blocked is False:
            if request.status_code != 403:
                log_status_test = 'PASSED'
                dynamic_scan_status = 'PASSED'
                log_all(request_data.path, test_type, log_status_test)
                base_str(f.WHITE, dynamic_scan_status)
            else:
                log_status_test = 'FAILED_FP'
                dynamic_scan_status = 'FAILED'
                log_all(request_data.path, test_type, log_status_test)
                base_str(f.RED, dynamic_scan_status)
        elif request_data.blocked is not True and request_data.blocked is not None and request_data.blocked is not False:
            status_test = 'ERROR'
            log_all(request_data.path, test_type, status_test)
            log_errors(request_data, test_type, status_test)
            print(f'{f.RED}Decoding JSON {request_data.path} has failed{s.RESET_ALL}')

    def test_args(self, request_data):
        request = self.session.get(
            self.host, params=request_data.args, proxies=self.proxy, timeout=self.timeout
        )
        self.output('ARGS', request_data, request)

    def test_ua(self, request_data):
        request = self.session.get(
            self.host, headers={'User-Agent': request_data.ua}, proxies=self.proxy, timeout=self.timeout
        )
        self.output('UA', request_data, request)

    def test_ref(self, request_data):
        request = self.session.get(
            self.host, headers={'Referer': request_data.ref}, proxies=self.proxy, timeout=self.timeout
        )
        self.output('Referer', request_data, request)

    def test_body(self, request_data):
        request = self.session.post(
            self.host, data=request_data.req_body, proxies=self.proxy, timeout=self.timeout
        )
        self.output('Body', request_data, request)

    def test_cookie(self, request_data):
        request = self.session.get(
            self.host, cookies={f"CustomCookie{secrets.token_urlsafe(12)}": request_data.cookie}, proxies=self.proxy,
            timeout=self.timeout
        )
        self.output('Cookie', request_data, request)

    def test_header(self, request_data):
        request = self.session.get(
            self.host, headers={f"CustomHeader": request_data.req_header}, proxies=self.proxy, timeout=self.timeout
        )
        self.output('Header', request_data, request)

    def test_url(self, request_data):
        payload_url = urljoin(self.host, request_data.url)
        request = self.session.get(
            payload_url, proxies=self.proxy, timeout=self.timeout
        )
        self.output('URL', request_data, request)
