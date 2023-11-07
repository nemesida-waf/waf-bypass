#!/usr/bin/env python3

import base64
import curlify
import json
import os
import requests
import secrets

from colorama import Fore
from colorama import Style
from html import escape
from multiprocessing.dummy import Pool as ThreadPool
from urllib.parse import urljoin, quote_plus

from .payloads import get_payload
from .tables import table_get_result_details
from .tables import table_get_result_replay
from .tables import table_get_result_summary

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
    if not data:
        return res

    # list processing
    for item in data:

        path = item[0]
        zone = item[1]
        error = item[2]

        if path not in res:
            res[path] = {zone: error}
        else:
            res[path] = {**res[path], **{zone: error}}

    # return result
    return res


def json_processing(statuses, result):

    # basic data processing
    for k in statuses:
        result[k] = zone_combining(result[k])

    # other data processing
    for col in ['cURL', 'TestRequest']:
        for k in result[col]:
            result[col][k] = zone_combining(result[col][k])

    # print result in JSON
    print(json.dumps(result))


def table_processing(statuses, wb_result, details, replay):

    # print summary table
    table_get_result_summary(statuses, wb_result)

    # show FALSED/BYPASSED details
    if details:

        fp = {x[0]: x[1] for x in wb_result['FALSED']}
        fn = {x[0]: x[1] for x in wb_result['BYPASSED']}
        fp = dict(sorted(fp.items()))
        fn = dict(sorted(fn.items()))
        table_get_result_details(fp, fn)

    # show cURL command output
    if replay:
        table_get_result_replay(wb_result)


def processing_result(plp, zone, wb_result_json, blocked, block_code, status_code):

    # if status code is not 20x and not in block codes list (403, 222 etc.)
    if (not str(status_code).startswith('20') or status_code == 404) and status_code not in block_code:
        status = ['FAILED', status_code]
        if not wb_result_json:
            err = (
                'An incorrect response was received while processing payload {} in {}: {}'
                .format(plp, zone, status_code)
            )
            print('{}{}{}'.format(Fore.YELLOW, err, Style.RESET_ALL))
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

    def __init__(self, host, proxy, headers, block_code, timeout, threads, wb_result, wb_result_json, details, replay, exclude_dir):

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
        self.replay = replay
        self.exclude_dir = exclude_dir

        # init statuses
        self.statuses = [
            'FAILED',     # Failed requests (incorrect response code, can not connect to server) etc.)
            'PASSED',     # OK
            'FALSED',     # False Positive
            'BYPASSED',   # False Negative
        ]

        # init zones
        self.zones = ['URL', 'ARGS', 'BODY', 'COOKIE', 'USER-AGENT', 'REFERER', 'HEADER']

        # basic output init
        for k in self.statuses:
            self.wb_result[k] = []

        # cURL command output init
        col = 'TestRequest'
        self.wb_result[col] = {}
        for k in self.statuses:
            if k not in ['PASSED', 'BYPASSED']:
                self.wb_result[col][k] = []

        # cURL command output init
        col = 'cURL'
        self.wb_result[col] = {}
        for k in self.statuses:
            if k not in ['FAILED', 'PASSED']:
                self.wb_result[col][k] = []

    def start(self):

        # init path
        relative_path = ''
        work_dir = os.path.dirname(os.path.realpath(__file__))
        work_dir_payload = os.path.join(work_dir, 'payload')
        pdl = get_delimiter(work_dir)

        def send_payload(json_path):
            try:

                # init
                k = json_path.split(pdl + 'payload' + pdl, 1)[1]

                # skip payload if it in exclude_dir
                if k.split(pdl)[0].upper() in self.exclude_dir:
                    return

                # extract payload data
                payload = get_payload(json_path)

                # if payload is empty
                if not payload:
                    if not self.wb_result_json:
                        err = 'No payloads found during processing file {}'.format(json_path)
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

                # set payload path
                plp = json_path.split(pdl + 'payload' + pdl, 1)[1]

                # processing the payload of each zone
                for zone in payload:

                    # skip specific zone (e.g., boundary, method etc.)
                    if zone not in self.zones:
                        continue

                    # skip empty
                    if not payload[zone]:
                        continue

                    # reset the method
                    default_method = 'post' if zone == 'BODY' else 'get'
                    method = default_method if not payload['METHOD'] else payload['METHOD']

                    ##
                    # Processing the payloads
                    ##

                    for encode in encode_list:

                        if zone == 'URL':

                            if not encode:
                                k = ':'.join([str(json_path), str(zone).upper()])
                            else:
                                continue

                            result, curl = self.test_url(plp, zone, payload, method, headers, encode)
                            self.test_resp_status_processing(k.split(pdl + 'payload' + pdl, 1)[1], result, curl)

                        elif zone == 'ARGS':

                            if not encode:
                                k = ':'.join([str(json_path), str(zone).upper()])
                            else:
                                k = ':'.join([str(json_path), str(zone).upper(), encode.upper()])

                            result, curl = self.test_args(plp, zone, payload, method, headers, encode)
                            self.test_resp_status_processing(k.split(pdl + 'payload' + pdl, 1)[1], result, curl)

                        elif zone == 'BODY':

                            if not encode:
                                k = ':'.join([str(json_path), str(zone).upper()])
                            else:
                                k = ':'.join([str(json_path), str(zone).upper(), encode.upper()])

                            result, curl = self.test_body(plp, zone, payload, method, body, headers, encode)
                            self.test_resp_status_processing(k.split(pdl + 'payload' + pdl, 1)[1], result, curl)

                        elif zone == 'COOKIE':

                            if not encode:
                                k = ':'.join([str(json_path), str(zone).upper()])
                            else:
                                k = ':'.join([str(json_path), str(zone).upper(), encode.upper()])

                            result, curl = self.test_cookie(plp, zone, payload, method, headers, encode)
                            self.test_resp_status_processing(k.split(pdl + 'payload' + pdl, 1)[1], result, curl)

                        elif zone == 'USER-AGENT':

                            if not encode:
                                k = ':'.join([str(json_path), str(zone).upper()])
                            else:
                                continue

                            result, curl = self.test_ua(plp, zone, payload, method, headers, encode)
                            self.test_resp_status_processing(k.split(pdl + 'payload' + pdl, 1)[1], result, curl)

                        elif zone == 'REFERER':

                            if not encode:
                                k = ':'.join([str(json_path), str(zone).upper()])
                            else:
                                continue

                            result, curl = self.test_referer(plp, zone, payload, method, headers, encode)
                            self.test_resp_status_processing(k.split(pdl + 'payload' + pdl, 1)[1], result, curl)

                        elif zone == 'HEADER':

                            if not encode:
                                k = ':'.join([str(json_path), str(zone).upper()])
                            else:
                                k = ':'.join([str(json_path), str(zone).upper(), encode.upper()])

                            result, curl = self.test_header(plp, zone, payload, method, headers, encode)
                            self.test_resp_status_processing(k.split(pdl + 'payload' + pdl, 1)[1], result, curl)

            except Exception as e:
                if not self.wb_result_json:
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

        # JSON output
        if self.wb_result_json:
            json_processing(self.statuses, self.wb_result)
        # Normal output
        else:
            table_processing(self.statuses, self.wb_result, self.details, self.replay)

    def test_resp_status_processing(self, k, result, curl):
        try:
        
            if result:

                # init
                plp = k.split(':', 1)[0]
                zone = k.split(':', 1)[1]
                status = result[0]

                # update with basic data
                self.wb_result[status].append([plp, zone, str(result[1]) + ' RESPONSE CODE'])

                # update with cURL data
                if status not in ['PASSED', 'FAILED']:
                    self.wb_result['cURL'][status].append([plp, zone, curl])

        except Exception as e:
            print(
                '{}'
                'An error occurred while processing the status of the request: {}'
                '{}'
                .format(Fore.YELLOW, e, Style.RESET_ALL)
            )

    def test_error_response_processing(self, plp, zone, encode, error):
        try:

            # init
            status = 'FAILED'
            zone = zone if not encode else ':'.join([zone, encode])

            # update with basic data
            self.wb_result[status].append([plp, zone, str(error)])

            # Normal output
            if not self.wb_result_json:
                err = 'An error occurred while processing payload {} in {}: {}'.format(plp, zone, error)
                print('{}{}{}'.format(Fore.YELLOW, err, Style.RESET_ALL))

        except Exception as e:

            if not self.wb_result_json:
                print(
                    '{}'
                    'An error occurred while processing fail response code of the request: {}'
                    '{}'
                    .format(Fore.YELLOW, e, Style.RESET_ALL)
                )

    def test_noblocked(self, method, headers):

        # init
        k = 'TestRequest-{}'.format(method)
        z = 'DEFAULT'

        # send test request
        try:

            # send the request
            s = init_session()
            headers = {**self.headers, **headers}
            result = s.request(method, self.host, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)
            curl = curlify.to_curl(result.request).replace('\r\n', '\\r\\n')
            result = processing_result(k, z, self.wb_result_json, False, self.block_code, result.status_code)

            # FALSED/FAILED
            if result[0] in ['FAILED', 'FALSED']:

                # init
                status = result[0]

                # Normal output
                if not self.wb_result_json:

                    # FAILED
                    if status == 'FAILED':
                        print(
                            '{}'
                            'An error occurred while processing test request to {}: access blocked ({})'
                            ' (the auto-ban policy might be enabled)'
                            '{}'
                            .format(Fore.YELLOW, self.host, result[1], Style.RESET_ALL)
                        )

                    # BYPASSED/FALSED
                    else:
                        print(
                            '{}'
                            'An incorrect response was received while processing test request to {}: {}'
                            '{}'
                            .format(Fore.YELLOW, self.host, result[1], Style.RESET_ALL)
                        )

                    # cURL data
                    print('Replay with cURL: {}'.format(curl))

            else:
                return

        except Exception as error:

            # Normal output
            if not self.wb_result_json:
                err = 'An incorrect response was received while sending test request to {}: {}'.format(self.host, error)
                print('{}{}{}'.format(Fore.YELLOW, err, Style.RESET_ALL))

    def test_url(self, plp, zone, payload, method, headers, encode):
        try:

            # init
            encoded_payload = payload_encoding(zone, payload[zone], encode)
            host = urljoin(self.host, encoded_payload)
            headers = {**self.headers, **headers}

            s = init_session()
            result = s.request(method, host, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)
            curl = curlify.to_curl(result.request).replace('\r\n', '\\r\\n')
            result = processing_result(plp, zone, self.wb_result_json, payload['BLOCKED'], self.block_code, result.status_code)
            return result, curl

        except Exception as error:
            self.test_error_response_processing(plp, zone, encode, error)
            return None, None

    def test_args(self, plp, zone, payload, method, headers, encode):
        try:

            # init
            encoded_payload = payload_encoding(zone, payload[zone], encode)
            headers = {**self.headers, **headers}

            s = init_session()
            result = s.request(method, self.host, headers=headers, params=encoded_payload, proxies=self.proxy, timeout=self.timeout, verify=False)
            curl = curlify.to_curl(result.request).replace('\r\n', '\\r\\n')
            result = processing_result(plp, zone, self.wb_result_json, payload['BLOCKED'], self.block_code, result.status_code)
            return result, curl

        except Exception as error:
            self.test_error_response_processing(plp, zone, encode, error)
            return None, None

    def test_body(self, plp, zone, payload, method, body, headers, encode):
        try:

            # init
            encoded_payload = payload_encoding(zone, body, encode)
            headers = {**self.headers, **headers}

            s = init_session()
            result = s.request(method, self.host, headers=headers, data=encoded_payload, proxies=self.proxy, timeout=self.timeout, verify=False)
            curl = curlify.to_curl(result.request).replace('\r\n', '\\r\\n')
            result = processing_result(plp, zone, self.wb_result_json, payload['BLOCKED'], self.block_code, result.status_code)
            return result, curl

        except Exception as error:
            self.test_error_response_processing(plp, zone, encode, error)
            return None, None

    def test_cookie(self, plp, zone, payload, method, headers, encode):
        try:

            # init
            encoded_payload = payload_encoding(zone, payload[zone], encode)
            headers = {**self.headers, **headers}
            cookies = {f"WBC-{secrets.token_hex(3)}": encoded_payload}

            s = init_session()
            result = s.request(method, self.host, headers=headers, cookies=cookies, proxies=self.proxy, timeout=self.timeout, verify=False)
            curl = curlify.to_curl(result.request).replace('\r\n', '\\r\\n')
            result = processing_result(plp, zone, self.wb_result_json, payload['BLOCKED'], self.block_code, result.status_code)
            return result, curl

        except Exception as error:
            self.test_error_response_processing(plp, zone, encode, error)
            return None, None

    def test_ua(self, plp, zone, payload, method, headers, encode):
        try:

            # init
            encoded_payload = payload_encoding(zone, payload[zone], encode)
            headers = {**self.headers, **headers, 'User-Agent': encoded_payload}

            s = init_session()
            result = s.request(method, self.host, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)
            curl = curlify.to_curl(result.request).replace('\r\n', '\\r\\n')
            result = processing_result(plp, zone, self.wb_result_json, payload['BLOCKED'], self.block_code, result.status_code)
            return result, curl

        except Exception as error:
            self.test_error_response_processing(plp, zone, encode, error)
            return None, None

    def test_referer(self, plp, zone, payload, method, headers, encode):
        try:

            # init
            encoded_payload = payload_encoding(zone, payload[zone], encode)
            headers = {**self.headers, **headers, 'Referer': encoded_payload}

            s = init_session()
            result = s.request(method, self.host, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)
            curl = curlify.to_curl(result.request).replace('\r\n', '\\r\\n')
            result = processing_result(plp, zone, self.wb_result_json, payload['BLOCKED'], self.block_code, result.status_code)
            return result, curl

        except Exception as error:
            self.test_error_response_processing(plp, zone, encode, error)
            return None, None

    def test_header(self, plp, zone, payload, method, headers, encode):
        try:

            # init
            encoded_payload = payload_encoding(zone, payload[zone], encode)
            headers = {**self.headers, **headers, f"WBH-{secrets.token_hex(3)}": encoded_payload}

            s = init_session()
            result = s.request(method, self.host, headers=headers, proxies=self.proxy, timeout=self.timeout, verify=False)
            curl = curlify.to_curl(result.request).replace('\r\n', '\\r\\n')
            result = processing_result(plp, zone, self.wb_result_json, payload['BLOCKED'], self.block_code, result.status_code)
            return result, curl

        except Exception as error:
            self.test_error_response_processing(plp, zone, encode, error)
            return None, None
