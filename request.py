import re
import json


class Request:
    def __init__(self, path, payload):
        self._path = path
        with open(payload) as f:
            data = json.load(f)['req'][0]
        # Type
        req_type = self.extract_value(data, 'Type')
        self._req_type = None if req_type == 'null' else req_type
        # UA
        ua = self.extract_value(data, 'UA')
        self._ua = None if ua == 'null' else ua
        # Body
        body = self.extract_value(data, 'Body')
        self._req_body = None if body == 'null' else self.parse_pairs(body, '&')
        #ARGS
        args = self.extract_value(data, 'ARGS')
        self._args = None if args == 'null' else self.parse_pairs(args, '&')
        # Header
        req_header = self.extract_value(data, 'Headers')
        self._req_header = None if req_header == 'null' else {'test':req_header}
        # Cookie
        cookie = self.extract_value(data, 'Cookie')
        self._cookie = None if cookie == 'null' else self.parse_pairs(cookie)
        # URL
        url = self.extract_value(data, 'URL')
        self._url = None if url == 'null' else url

    @property
    def path(self):
        return self._path

    @property
    def req_type(self):
        return self._req_type

    @property
    def ua(self):
        return self._ua

    @property
    def req_body(self):
        return self._req_body

    @property
    def args(self):
        return self._args

    @property
    def req_header(self):
        return self._req_header

    @property
    def cookie(self):
        return self._cookie

    @property
    def url(self):
        return self._url

    @staticmethod
    def parse_pairs(data, separator):
        result = {}
        if separator == '&':
            return data
        for pair in data.split(separator):
            if '=' in pair:
                name, value = pair.split('=', 1)
                if re.match(r'\w+', name):
                    result[name] = value
                else:
                    result['test'] = pair
            else:
                result['test'] = pair
        return result

    @staticmethod
    def extract_value(json_data, key):
        return json_data.get(key, 'null')

    def __str__(self):
        return 'path: {}; req_type: {}; ua: {}; req_body: {}; args: {}; req_header: {}; req_cookie: {}'.format(self.path, self.req_type, self.ua, self.req_body, self.args, self.req_header, self.cookie)
