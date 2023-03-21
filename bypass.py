#!/usr/bin/env python3

import base64
import json
import os
import requests
import secrets

from colorama import Fore
from colorama import Style
from html import escape
from multiprocessing.dummy import Pool as ThreadPool
from urllib.parse import urljoin, quote_plus

from payloads import get_payload
from tables import table_get_result_details, table_get_result_summary

requests.packages.urllib3.disable_warnings()


def init_session():
    s = requests.Session()
    s.trust_env = False
    return s


def get_delimiter(p):
    try:
        # Set the path separator depending on the OS
        return '\\' if '\\' in p else '/'
    except Exception as e:
        print(
            '{}'
            'An error occurred while processing path delimiter for {}: {}'
            '{}'
            .format(Fore.RED, p, e, Style.RESET_ALL)
        )
        return '/'
        

def zone_combining(data):
    
    # init
    res = {}

    # skip empty list
    if not len(data):
        return res
    
    # list processing
    for item in data:
        k = item.split(':', 1)[0]
        v = item.split(':', 1)[1]
        if k not in res:
            res[k] = []
        res[k].append(v)
    
    # dictionary processing
    for k, v in res.items():
        res[k] = '|'.join(v)

    # return result
    return res


def json_processing(result):
    
    # processing FX (convert list of 'payload:zone' to list of dict. 'payload:z1|z2')
    result['PASSED'] = zone_combining(result['PASSED'])
    result['FALSED'] = zone_combining(result['FALSED'])
    result['BYPASSED'] = zone_combining(result['BYPASSED'])

    # print result in JSON
    print(json.dumps(result))


def table_processing(result, details, pdl):

    # print summary table
    table_get_result_summary(result, pdl)

    # print FALSED/BYPASSED tables
    if details:

        fp = [k for k, v in result.items() if v == 'FALSED']
        fn = [k for k, v in result.items() if v == 'BYPASSED']
        fp.sort()
        fn.sort()
        fp = zone_combining(fp)
        fn = zone_combining(fn)
        table_get_result_details(fp, fn)


def processing_result(blocked, block_code, status_code):
    
    # if status code is not 20x and not in block codes list (403, 222 etc.) 
    if (not str(status_code).startswith('20') or status_code == 404) and status_code not in block_code:
        status = ['FAILED', str(status_code) + ' RESPONSE CODE']
    else:
        if blocked:
            status = ['PASSED', status_code] if status_code in block_code else ['BYPASSED', status_code]
        else:
            status = ['PASSED', status_code] if status_code not in block_code else ['FALSED', status_code]
    
    return status


def payload_encoding(z, payload, encode):
    try:

        if not encode:
            return payload
        else:

            # init
            data_list = []

            # split by &
            if z.upper() in ['ARGS', 'BODY']:

                # processing data list by k/v
                for item in payload.split('&'):
                    # key/value
                    if '=' in item:
                        # extract k/v
                        k = item.split('=', 1)[0]
                        v = item.split('=', 1)[1]
                        # update data list
                        data_list.append([k, v])
                    # value only
                    else:
                        # update data list
                        data_list.append([item])

            if encode.upper() == 'HTML-ENTITY':
                if not data_list:
                    return quote_plus(escape(payload))
                else:
                    res = []
                    for item in data_list:
                        # key/value
                        if len(item) > 1:
                            k = str(item[0])
                            v = quote_plus(escape(str(item[1])))
                            res.append(k + '=' + v)
                        # value only
                        else:
                            res.append(
                                quote_plus(escape(str(item[0])))
                            )
                    return '&'.join(res)

            elif encode.upper() == 'UTF-16':
                if not data_list:
                    return ''.join([hex(ord(x)).replace('0x', '\\u00') for x in payload])
                else:
                    res = []
                    for item in data_list:
                        # key/value
                        if len(item) > 1:
                            k = str(item[0])
                            v = ''.join([hex(ord(x)).replace('0x', '\\u00') for x in str(item[1])])
                            res.append(k + '=' + v)
                        # value only
                        else:
                            res.append(
                                ''.join([hex(ord(x)).replace('0x', '\\u00') for x in str(item[0])])
                            )
                    return '&'.join(res)
            
            elif encode.upper() == 'BASE64':
                if not data_list:
                    return base64.b64encode(payload.encode('UTF-8')).decode('UTF-8')
                else:
                    res = []
                    for item in data_list:
                        # key/value
                        if len(item) > 1:
                            k = str(item[0])
                            v = base64.b64encode(str(item[1]).encode('UTF-8')).decode('UTF-8')
                            res.append(k + '=' + v)
                        # value only
                        else:
                            res.append(
                                base64.b64encode(str(item[0]).encode('UTF-8')).decode('UTF-8')
                            )
                    return '&'.join(res)

            else:
                print(
                    '{}'
                    'An error occurred while encoding payload ({}) with {}: incorrect encoding type'
                    '{}'
                    .format(Fore.YELLOW, payload, encode, Style.RESET_ALL)
                )
                return payload
    
    except Exception as e:
        print(
            '{}'
            'An error occurred while encoding payload ({}) with {}: {}'
            '{}'
            .format(Fore.YELLOW, payload, encode, e, Style.RESET_ALL)
        )
        return payload


class WAFBypass:

    def __init__(self, host, proxy, headers, block_code, timeout, threads, wb_result, wb_result_json, details, exclude_dir):
        
        # init
        self.host = host
        self.proxy = {'http': proxy, 'https': proxy}
        self.block_code = block_code
        self.headers = headers
        self.timeout = timeout
        self.threads = threads
        self.wb_result = wb_result
        self.wb_result_json = wb_result_json
        self.details = details
        self.exclude_dir = exclude_dir

        # init statuses
        self.statuses = [
            'PASSED',    # OK
            'FAILED',    # Failed requests (e.g.,cannot connect to server, incorrect response code etc.)
            'FALSED',    # False Positive
            'BYPASSED',  # False Negative
        ]
        self.zones = ['URL', 'ARGS', 'BODY', 'COOKIE', 'USER-AGENT', 'REFERER', 'HEADER']

        # add extra keys for JSON format
        if self.wb_result_json:
            for k in self.statuses:
                self.wb_result[k] = []

    def start(self):
       
        # init path
        relative_path = ''
        work_dir = os.path.dirname(os.path.realpath(__file__))
        work_dir_payload = os.path.join(work_dir, 'payload')
        pdl = get_delimiter(work_dir)
        
        def send_payload(json_path):
            try:

                # skip payload if it in exclude_dir
                if json_path.split(pdl + 'payload' + pdl, 1)[1].split(pdl)[0].upper() in self.exclude_dir:
                    return

                # extract payload data
                payload = get_payload(json_path)
                
                # if payload is empty
                if not payload:
                    err = 'No payloads found during processing file {}'.format(json_path)
                    if self.wb_result_json:
                        self.wb_result['FAILED'].append({json_path.split(pdl + 'payload' + pdl, 1)[1]: 'No payloads found'})
                    print(
                        '{}{}{}'
                        .format(Fore.YELLOW, err, Style.RESET_ALL)
                    )
                    return

                # init
                encode_list = payload['ENCODE']
                body = payload['BODY']
                headers = {}

                # no-blocked validation without payload
                self.test_noblocked('get', headers)

                # JSON parameter processing
                if payload['JSON']:

                    # add a JSON header
                    headers['Content-Type'] = 'application/json'

                    # check ENCODE
                    if payload['ENCODE']:
                        print(
                                '{}'
                                'An error occurred while processing payload from file {}:'
                                ' simultaneous use of "JSON" and "ENCODE" is prohibited'
                                '{}'
                                .format(Fore.YELLOW, json_path, Style.RESET_ALL)
                            )
                        return

                # API dir processing
                if pdl + 'API' + pdl in json_path:
                    # add a JSON header
                    headers['Content-Type'] = 'application/json'
                    # reset encode
                    encode_list = []

                # MFD (multipart/form-data) dir processing
                elif pdl + 'MFD' + pdl in json_path:
                    
                    # if BODY is set
                    if payload['BODY']:

                        # reset encode
                        encode_list = []

                        # if boundary is set
                        if payload['BOUNDARY']:
                            # set headers
                            headers['Content-Type'] = 'multipart/form-data; boundary=' + payload['BOUNDARY']

                        else:
                            
                            # set body/headers
                            boundary = secrets.token_hex(30)  # 60 symbols
                            body = '--' + boundary + '\r\n' \
                                + 'Content-Disposition: form-data; name="' + secrets.token_urlsafe(5) + '"' \
                                + '\r\n\r\n' + payload['BODY'] + '\r\n' + '--' + boundary + '--' + '\r\n'
                            headers['Content-Type'] = 'multipart/form-data; boundary=' + boundary

                    else:
                        print(
                            '{}'
                            'An error occurred while processing payload from file {}: empty BODY'
                            '{}'
                            .format(Fore.YELLOW, json_path, Style.RESET_ALL)
                        )
                        return

                # encode list processing
                encode_list.append('')

                # processing the payload of each zone
                for z in payload:

                    # skip specific zone (e.g., boundary, method etc.)
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

                    for encode in encode_list:

                        if z == 'URL':
                            
                            if not encode:
                                k = ':'.join([str(json_path), str(z).upper()])
                            else:
                                continue

                            v = self.test_url(json_path, z, payload, method, headers, encode)
                            
                            if self.wb_result_json:
                                self.test_resp_status_processing(k.split(pdl + 'payload' + pdl, 1)[1], v)
                            else:
                                self.wb_result[k] = v

                        elif z == 'ARGS':
                            
                            if not encode:
                                k = ':'.join([str(json_path), str(z).upper()])
                            else:
                                k = ':'.join([str(json_path), str(z).upper(), encode.upper()])

                            v = self.test_args(json_path, z, payload, method, headers, encode)
                            
                            if self.wb_result_json:
                                self.test_resp_status_processing(k.split(pdl + 'payload' + pdl, 1)[1], v)
                            else:
                                self.wb_result[k] = v

                        elif z == 'BODY':
                            
                            if not encode:
                                k = ':'.join([str(json_path), str(z).upper()])
                            else:
                                k = ':'.join([str(json_path), str(z).upper(), encode.upper()])

                            v = self.test_body(json_path, z, payload, method, body, headers, encode)
                            
                            if self.wb_result_json:
                                self.test_resp_status_processing(k.split(pdl + 'payload' + pdl, 1)[1], v)
                            else:
                                self.wb_result[k] = v

                        elif z == 'COOKIE':
                            
                            if not encode:
                                k = ':'.join([str(json_path), str(z).upper()])
                            else:
                                k = ':'.join([str(json_path), str(z).upper(), encode.upper()])

                            v = self.test_cookie(json_path, z, payload, method, headers, encode)
                            
                            if self.wb_result_json:
                                self.test_resp_status_processing(k.split(pdl + 'payload' + pdl, 1)[1], v)
                            else:
                                self.wb_result[k] = v

                        elif z == 'USER-AGENT':
                            
                            if not encode:
                                k = ':'.join([str(json_path), str(z).upper()])
                            else:
                                continue

                            v = self.test_ua(json_path, z, payload, method, headers, encode)
                            
                            if self.wb_result_json:
                                self.test_resp_status_processing(k.split(pdl + 'payload' + pdl, 1)[1], v)
                            else:
                                self.wb_result[k] = v

                        elif z == 'REFERER':
                            
                            if not encode:
                                k = ':'.join([str(json_path), str(z).upper()])
                            else:
                                continue

                            v = self.test_referer(json_path, z, payload, method, headers, encode)
                            
                            if self.wb_result_json:
                                self.test_resp_status_processing(k.split(pdl + 'payload' + pdl, 1)[1], v)
                            else:
                                self.wb_result[k] = v

                        elif z == 'HEADER':
                            
                            if not encode:
                                k = ':'.join([str(json_path), str(z).upper()])
                            else:
                                k = ':'.join([str(json_path), str(z).upper(), encode.upper()])

                            v = self.test_header(json_path, z, payload, method, headers, encode)
                            
                            if self.wb_result_json:
                                self.test_resp_status_processing(k.split(pdl + 'payload' + pdl, 1)[1], v)
                            else:
                                self.wb_result[k] = v

            except Exception as e:
                if self.wb_result_json:
                    err = 'An error occurred while processing payload: {}'.format(e)
                    self.wb_result['FAILED'].append({relative_path.split(pdl + 'payload' + pdl, 1)[1]: err})
                else:
                    err = 'An error occurred while processing payload from file {}: {}'.format(relative_path, e)
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
                all_files_list.append(
                    os.path.join(dir_path, filename)
                )

        # Multithreading
        pool = ThreadPool(processes=self.threads)
        pool.map(send_payload, all_files_list)

        # Processing result
        if self.wb_result_json:
            json_processing(self.wb_result)
        else:
            table_processing(self.wb_result, self.details, pdl)

    def test_resp_status_processing(self, k, v):
        try:

            if v in ['PASSED', 'FALSED', 'BYPASSED']:
                self.wb_result[v].append(k)
            elif v == 'FAILED':
                return
            else:
                print(
                    '{}'
                    'An error occurred while processing request status: {} ({}) not in PASSED/FAILED/FALSED/BYPASSED'
                    '{}'
                    .format(Fore.YELLOW, v, k, Style.RESET_ALL)
                )
        
        except Exception as e:
            print(
                '{}'
                'An error occurred while processing test\'s status: {}'
                '{}'
                .format(Fore.YELLOW, e, Style.RESET_ALL)
            )

    def test_err_resp_code_processing(self, json_path, z, encode, result):
        try:

            if self.wb_result_json:
                z = z if not encode else ':'.join([z, encode])
                err = 'An incorrect response was received while processing request: {}'.format(result[1])
                pdl = get_delimiter(json_path)
                self.wb_result['FAILED'].append(
                    {json_path.split(pdl + 'payload' + pdl, 1)[1] + ' in ' + z: err}
                )
            else:
                err = 'An incorrect response was received while processing request from file {} in {}: {}' \
                    .format(json_path, z, result[1])
                print('{}{}{}'.format(Fore.YELLOW, err, Style.RESET_ALL))
        
        except Exception as e:
            print(
                '{}'
                'An error occurred while processing test\'s error response code: {}'
                '{}'
                .format(Fore.YELLOW, e, Style.RESET_ALL)
            )

    def test_fail_response_processing(self, json_path, z, encode, error):
        try:
            if self.wb_result_json:
                z = z if not encode else ':'.join([z, encode])
                pdl = get_delimiter(json_path)
                self.wb_result['FAILED'].append({json_path.split(pdl + 'payload' + pdl, 1)[1] + ' in ' + z: str(error)})
            else:
                err = 'An error occurred while processing file {} in {}: {}'.format(json_path, z, error)
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
            elif result[0] == 'FAILED':
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
            if self.wb_result_json:
                self.wb_result['FAILED'].append({'Test request': str(error)})
            else:
                err = 'An incorrect response was received while test request: {}'.format(error)
                print('{}{}{}'.format(Fore.YELLOW, err, Style.RESET_ALL))

    def test_url(self, json_path, z, payload, method, headers, encode):            
        try:

            # init
            encoded_payload = payload_encoding(z, payload[z], encode)
            host = urljoin(self.host, encoded_payload)
            headers = {**self.headers, **headers}

            s = init_session()
            result = s.request(method, host, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)
            result = processing_result(payload['BLOCKED'], self.block_code, result.status_code)
            v = result[0]

            if v == 'FAILED':
                self.test_err_resp_code_processing(json_path, z, encode, result[1])

        except Exception as error:
            v = 'FAILED'
            self.test_fail_response_processing(json_path, z, encode, error)

        return v

    def test_args(self, json_path, z, payload, method, headers, encode):
        try:
            
            # init
            encoded_payload = payload_encoding(z, payload[z], encode)
            headers = {**self.headers, **headers}

            s = init_session()
            result = s.request(method, self.host, headers=headers, params=encoded_payload, proxies=self.proxy, timeout=self.timeout, verify=False)
            result = processing_result(payload['BLOCKED'], self.block_code, result.status_code)
            v = result[0]

            if v == 'FAILED':
                self.test_err_resp_code_processing(json_path, z, encode, result[1])

        except Exception as error:
            v = 'FAILED'
            self.test_fail_response_processing(json_path, z, encode, error)

        return v

    def test_body(self, json_path, z, payload, method, body, headers, encode):
        try:

            # init
            encoded_payload = payload_encoding(z, body, encode)
            headers = {**self.headers, **headers}

            s = init_session()
            result = s.request(method, self.host, headers=headers, data=encoded_payload, proxies=self.proxy, timeout=self.timeout, verify=False)
            result = processing_result(payload['BLOCKED'], self.block_code, result.status_code)
            v = result[0]

            if v == 'FAILED':
                self.test_err_resp_code_processing(json_path, z, encode, result[1])

        except Exception as error:
            v = 'FAILED'
            self.test_fail_response_processing(json_path, z, encode, error)

        return v

    def test_cookie(self, json_path, z, payload, method, headers, encode):
        try:
            
            # init
            encoded_payload = payload_encoding(z, payload[z], encode)
            headers = {**self.headers, **headers}
            cookies = {f"WBC-{secrets.token_hex(3)}": encoded_payload}

            s = init_session()
            result = s.request(method, self.host, headers=headers, cookies=cookies, proxies=self.proxy, timeout=self.timeout, verify=False)
            result = processing_result(payload['BLOCKED'], self.block_code, result.status_code)
            v = result[0]

            if v == 'FAILED':
                self.test_err_resp_code_processing(json_path, z, encode, result[1])

        except Exception as error:
            v = 'FAILED'
            self.test_fail_response_processing(json_path, z, encode, error)

        return v

    def test_ua(self, json_path, z, payload, method, headers, encode):
        try:
            
            # init
            encoded_payload = payload_encoding(z, payload[z], encode)
            headers = {**self.headers, **headers, 'User-Agent': encoded_payload}

            s = init_session()
            result = s.request(method, self.host, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)
            result = processing_result(payload['BLOCKED'], self.block_code, result.status_code)
            v = result[0]

            if v == 'FAILED':
                self.test_err_resp_code_processing(json_path, z, encode, result[1])

        except Exception as error:
            v = 'FAILED'
            self.test_fail_response_processing(json_path, z, encode, error)

        return v

    def test_referer(self, json_path, z, payload, method, headers, encode):
        try:

            # init
            encoded_payload = payload_encoding(z, payload[z], encode)
            headers = {**self.headers, **headers, 'Referer': encoded_payload}

            s = init_session()
            result = s.request(method, self.host, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)
            result = processing_result(payload['BLOCKED'], self.block_code, result.status_code)
            v = result[0]

            if v == 'FAILED':
                self.test_err_resp_code_processing(json_path, z, encode, result[1])

        except Exception as error:
            v = 'FAILED'
            self.test_fail_response_processing(json_path, z, encode, error)

        return v

    def test_header(self, json_path, z, payload, method, headers, encode):            
        try:

            # init
            encoded_payload = payload_encoding(z, payload[z], encode)
            headers = {**self.headers, **headers, f"WBH-{secrets.token_hex(3)}": encoded_payload}

            s = init_session()
            result = s.request(method, self.host, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)
            result = processing_result(payload['BLOCKED'], self.block_code, result.status_code)
            v = result[0]

            if v == 'FAILED':
                self.test_err_resp_code_processing(json_path, z, encode, result[1])

        except Exception as error:
            v = 'FAILED'
            self.test_fail_response_processing(json_path, z, encode, error)

        return v
