#!/usr/bin/env python3

import os
import requests
import secrets

from colorama import Fore
from colorama import Style
from multiprocessing.dummy import Pool as ThreadPool
from urllib.parse import urljoin

from payloads import get_payload
from tables import table_get_result_details, table_get_result_summary

requests.packages.urllib3.disable_warnings()


def init_session():
    s = requests.Session()
    s.trust_env = False
    return s


def processing_result(blocked, block_code, status_code):
    
    # if status code is not 20x and not in block codes list (403, 222 etc.) 
    if (not str(status_code).startswith('20') or status_code == 404) and status_code not in block_code:
        status = ['ERROR', str(status_code) + ' RESPONSE CODE']
    else:
        if blocked:
            status = ['PASSED', status_code] if status_code in block_code else ['FN', status_code]
        else:
            status = ['PASSED', status_code] if status_code not in block_code else ['FP', status_code]
    
    return status


class WAFBypass:

    def __init__(self, host, proxy, headers, block_code, timeout, threads, wb_result, wb_result_json):
        
        # init
        self.host = host
        self.proxy = {'http': proxy, 'https': proxy}
        self.block_code = block_code
        self.headers = headers
        self.timeout = timeout
        self.threads = threads
        self.wb_result = wb_result
        self.wb_result_json = wb_result_json

        # add extra keys for JSON format
        if self.wb_result_json:
            self.wb_result['error'] = []

        # init statuses
        self.statuses = ['PASSED', 'ERROR', 'FP', 'FN']
        self.zones = ['URL', 'ARGS', 'BODY', 'COOKIE', 'USER-AGENT', 'REFERER', 'HEADER']

    def start(self):
       
        # init path
        relative_path = ''
        work_dir = os.path.dirname(os.path.realpath(__file__))
        work_dir_payload = work_dir + '/payload'

        def send_payload(json_path):
            try:
                
                # extract payload data
                payload = get_payload(json_path)

                # init
                body = payload['BODY']
                headers = {}

                # if payload is empty
                if not payload:
                    err = 'No payloads found during processing file {}: no payload found'.format(json_path)
                    if self.wb_result_json:
                        self.wb_result['error'].append(err)
                    print(
                        '{}{}{}'
                        .format(Fore.YELLOW, err, Style.RESET_ALL)
                    )
                    return
                
                # no-blocked validation without payload
                self.test_noblocked('get', headers)

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
                            # set headers
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
                        print(
                            '{}'
                            'An error occurred while processing payload from file {}: empty BODY'
                            '{}'
                            .format(Fore.YELLOW, json_path, Style.RESET_ALL)
                        )
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
                        
                        if self.wb_result_json:
                            self.test_resp_status_processing(k, v)
                        else:
                            self.wb_result[k] = v

                    elif z == 'ARGS':
                        
                        k = str(str(json_path) + ':' + z)
                        v = self.test_args(json_path, z, payload, method, headers)
                        
                        if self.wb_result_json:
                            self.test_resp_status_processing(k, v)
                        else:
                            self.wb_result[k] = v

                    elif z == 'BODY':
                        
                        k = str(str(json_path) + ':' + z)
                        v = self.test_body(json_path, z, payload, method, body, headers)
                        
                        if self.wb_result_json:
                            self.test_resp_status_processing(k, v)
                        else:
                            self.wb_result[k] = v

                    elif z == 'COOKIE':
                        
                        k = str(str(json_path) + ':' + z)
                        v = self.test_cookie(json_path, z, payload, method, headers)
                        
                        if self.wb_result_json:
                            self.test_resp_status_processing(k, v)
                        else:
                            self.wb_result[k] = v

                    elif z == 'USER-AGENT':
                        
                        k = str(str(json_path) + ':' + z)
                        v = self.test_ua(json_path, z, payload, method, headers)
                        
                        if self.wb_result_json:
                            self.test_resp_status_processing(k, v)
                        else:
                            self.wb_result[k] = v

                    elif z == 'REFERER':
                        
                        k = str(str(json_path) + ':' + z)
                        v = self.test_referer(json_path, z, payload, method, headers)
                        
                        if self.wb_result_json:
                            self.test_resp_status_processing(k, v)
                        else:
                            self.wb_result[k] = v

                    elif z == 'HEADER':
                        
                        k = str(str(json_path) + ':' + z)
                        v = self.test_header(json_path, z, payload, method, headers)
                        
                        if self.wb_result_json:
                            self.test_resp_status_processing(k, v)
                        else:
                            self.wb_result[k] = v

            except Exception as e:
                err = 'An error occurred while processing payload from file {}: {}'.format(relative_path, e)
                if self.wb_result_json:
                    self.wb_result['error'].append(err)
                else:
                    print(
                        '{}{}{}'
                        .format(Fore.YELLOW, err, Style.RESET_ALL)
                    )
                return

        # Append all .json paths in one list
        all_files_list = []
        for (dir_path, _, filenames) in os.walk(work_dir_payload):
            for filename in filenames:
                relative_path = os.path.join(dir_path, filename)
                all_files_list.append(dir_path + '/' + filename)

        # Multithreading
        pool = ThreadPool(processes=self.threads)
        pool.map(send_payload, all_files_list)

        if self.wb_result_json:
            print(self.wb_result)
        else:
            table_get_result_summary(self.wb_result)
            table_get_result_details(self.wb_result)

    def test_resp_status_processing(self, k, v):
        try:

            if v[0] in ['FP', 'FN']:
                self.wb_result[v[0]].append({k: v[1]})
            else:
                self.wb_result['FX'].append({k: v[1]})
        
        except Exception as e:
            print(
                '{}'
                'An error occurred while processing test\'s status: {}'
                '{}'
                .format(Fore.YELLOW, e, Style.RESET_ALL)
            )

    def test_err_resp_code_processing(self, json_path, z, result):
        try:
            
            err = 'An incorrect response was received while processing request from file {} in {}: {}' \
                .format(json_path, z, result[1])
            
            if self.wb_result_json:
                self.wb_result['error'].append(err)
            else:
                print('{}{}{}'.format(Fore.YELLOW, err, Style.RESET_ALL))
        
        except Exception as e:
            print(
                '{}'
                'An error occurred while processing test\'s error response code: {}'
                '{}'
                .format(Fore.YELLOW, e, Style.RESET_ALL)
            )

    def test_fail_response_processing(self, json_path, z, error):
        try:
            
            err = 'An error occurred while processing file {} in {}: {}'.format(json_path, z, error)
            
            if self.wb_result_json:
                self.wb_result['fail'].append(err)
            else:
                print('{}{}{}'.format(Fore.YELLOW, err, Style.RESET_ALL))
        
        except Exception as e:
            print(
                '{}'
                'An error occurred while processing test\'s fail response code: {}'
                '{}'
                .format(Fore.YELLOW, e, Style.RESET_ALL)
            )

    def test_noblocked(self, method, headers):
        try:

            headers = {**self.headers, **headers}

            s = init_session()
            result = s.request(method, self.host, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)
            result = processing_result(False, self.block_code, result.status_code)

            # check status code
            if result[0] == 'PASSED':
                return
            elif result[0] == 'ERROR':
                print(
                    '{}'
                    'An incorrect response was received while processing test request to {}: {}'
                    '{}'
                    .format(Fore.YELLOW, self.host, result[1], Style.RESET_ALL)
                )
            else:
                print(
                    '{}'
                    'An error occurred while processing test request to {}: access blocked ({})'
                    ' (the auto-ban policy might be enabled)'
                    '{}'
                    .format(Fore.YELLOW, self.host, result[1], Style.RESET_ALL)
                )

        except Exception as error:
            err = 'An incorrect response was received while test request: {}'.format(error)
            if self.wb_result_json:
                self.wb_result['error'].append(err)
            else:
                print('{}{}{}'.format(Fore.YELLOW, err, Style.RESET_ALL))

    def test_url(self, json_path, z, payload, method, headers):            
        try:

            host = urljoin(self.host, payload[z])
            headers = {**self.headers, **headers}

            s = init_session()
            result = s.request(method, host, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)
            result = processing_result(payload['BLOCKED'], self.block_code, result.status_code)
            v = result[0]

            if v == 'ERROR':
                self.test_err_resp_code_processing(json_path, z, result[1])

        except Exception as error:
            v = 'ERROR'
            self.test_fail_response_processing(json_path, z, error)

        return v

    def test_args(self, json_path, z, payload, method, headers):
        try:
            
            headers = {**self.headers, **headers}

            s = init_session()
            result = s.request(method, self.host, headers=headers, params=payload[z], proxies=self.proxy, timeout=self.timeout, verify=False)
            result = processing_result(payload['BLOCKED'], self.block_code, result.status_code)
            v = result[0]

            if v == 'ERROR':
                self.test_err_resp_code_processing(json_path, z, result[1])

        except Exception as error:
            v = 'ERROR'
            self.test_fail_response_processing(json_path, z, error)

        return v

    def test_body(self, json_path, z, payload, method, body, headers):
        try:

            headers = {**self.headers, **headers}

            s = init_session()
            result = s.request(method, self.host, headers=headers, data=body, proxies=self.proxy, timeout=self.timeout, verify=False)
            result = processing_result(payload['BLOCKED'], self.block_code, result.status_code)
            v = result[0]

            if v == 'ERROR':
                self.test_err_resp_code_processing(json_path, z, result[1])

        except Exception as error:
            v = 'ERROR'
            self.test_fail_response_processing(json_path, z, error)

        return v

    def test_cookie(self, json_path, z, payload, method, headers):
        try:
            
            headers = {**self.headers, **headers}
            cookies = {f"WBC-{secrets.token_hex(3)}": payload[z]}

            s = init_session()
            result = s.request(method, self.host, headers=headers, cookies=cookies, proxies=self.proxy, timeout=self.timeout, verify=False)
            result = processing_result(payload['BLOCKED'], self.block_code, result.status_code)
            v = result[0]

            if v == 'ERROR':
                self.test_err_resp_code_processing(json_path, z, result[1])

        except Exception as error:
            v = 'ERROR'
            self.test_fail_response_processing(json_path, z, error)

        return v

    def test_ua(self, json_path, z, payload, method, headers):
        try:
            
            headers = {**self.headers, **headers, 'User-Agent': payload[z]}

            s = init_session()
            result = s.request(method, self.host, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)
            result = processing_result(payload['BLOCKED'], self.block_code, result.status_code)
            v = result[0]

            if v == 'ERROR':
                self.test_err_resp_code_processing(json_path, z, result[1])

        except Exception as error:
            v = 'ERROR'
            self.test_fail_response_processing(json_path, z, error)

        return v

    def test_referer(self, json_path, z, payload, method, headers):
        try:

            headers = {**self.headers, **headers, 'Referer': payload[z]}

            s = init_session()
            result = s.request(method, self.host, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)
            result = processing_result(payload['BLOCKED'], self.block_code, result.status_code)
            v = result[0]

            if v == 'ERROR':
                self.test_err_resp_code_processing(json_path, z, result[1])

        except Exception as error:
            v = 'ERROR'
            self.test_fail_response_processing(json_path, z, error)

        return v

    def test_header(self, json_path, z, payload, method, headers):            
        try:

            headers = {**self.headers, **headers, f"WBH-{secrets.token_hex(3)}": payload[z]}

            s = init_session()
            result = s.request(method, self.host, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)
            result = processing_result(payload['BLOCKED'], self.block_code, result.status_code)
            v = result[0]

            if v == 'ERROR':
                self.test_err_resp_code_processing(json_path, z, result[1])

        except Exception as error:
            v = 'ERROR'
            self.test_fail_response_processing(json_path, z, error)

        return v
