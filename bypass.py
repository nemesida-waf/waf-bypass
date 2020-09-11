from os import walk
import os.path
from colorama import Fore, Style
import requests
from request import Request
import re
from urllib.parse import urljoin
from logger import log_in


class waf_bypass:
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

    def start_test(self):
        for (dirpath, _, filenames) in walk('payload'):
            for filename in filenames:
                if self.name_pattern.match(filename):
                    try:
                        relative_path = os.path.join(dirpath, filename)
                        absolute_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), relative_path)
                        request_data = Request(relative_path, absolute_path)
                        if request_data.req_type == 'ALL':

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

                        elif request_data.req_type == 'ARGS':
                            self.test_args(request_data)

                        elif request_data.req_type == 'UA':
                            self.test_ua(request_data)

                        elif request_data.req_type == 'Referer':
                            self.test_ref(request_data)

                        elif request_data.req_type == 'Body':
                            self.test_body(request_data)

                        elif request_data.req_type == 'Cookie':
                            self.test_cookie(request_data)

                        elif request_data.req_type == 'Headers':
                            self.test_header(request_data)

                        elif request_data.url == 'URL':
                            self.test_url(request_data)

                    except Exception as e:
                        print('{}Error: {}. Using file: {}{}'.format(Fore.RED, e, relative_path, Style.RESET_ALL))


    def output(self, test_type, request_data, request):
        base_str = '{{}}{} in {}: {{}}{}'.format(request_data.path.replace("payload/", ""), test_type, Style.RESET_ALL)

        if request.status_code == 403:
            log_in(request_data.path.replace("payload/",""),test_type,'BLOCKED')
            print(base_str.format(Fore.GREEN, 'BLOCKED'))
        else:
            log_in(request_data.path.replace("payload/", ""),test_type,'BYPASSED')
            print(base_str.format(Fore.RED, 'BYPASSED'))


    def test_args(self, request_data):
        request = self.session.get(self.host, params=request_data.args, proxies=self.proxy, timeout=self.timeout)
        self.output('ARGS', request_data, request)


    def test_ua(self, request_data):
        request = self.session.get(self.host, headers={'User-Agent':request_data.ua}, proxies=self.proxy, timeout=self.timeout)
        self.output('UA', request_data, request)


    def test_ref(self, request_data):
        request = self.session.get(self.host, headers={'referer':request_data.ref}, proxies=self.proxy, timeout=self.timeout)
        self.output('Referer', request_data, request)


    def test_body(self, request_data):
        request = self.session.post(self.host, data=request_data.req_body, proxies=self.proxy, timeout=self.timeout)
        self.output('Body', request_data, request)


    def test_cookie(self, request_data):
        request = self.session.get(self.host, cookies={ "CustomCookie" : request_data.cookie }, proxies=self.proxy, timeout=self.timeout)
        self.output('Cookie', request_data, request)


    def test_header(self, request_data):
        request = self.session.get(self.host, headers={ "CustomHeader" : request_data.req_header }, proxies=self.proxy, timeout=self.timeout)
        self.output('Header', request_data, request)


    def test_url(self, request_data):
        payload_url = urljoin(self.host, request_data.url)
        request = self.session.get(payload_url, proxies=self.proxy, timeout=self.timeout)
        self.output('URL', request_data, request)
