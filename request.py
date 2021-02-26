#!/usr/bin/env python3

import json
import secrets


class Request:
    def __init__(self, json_path):
        self._path = json_path
        with open(json_path) as opened_json:
            json_data = json.load(opened_json)['req'][0]

        # URL
        url = self.extract_value(json_data, 'URL')
        self._url = None if (url is None or not url) else url.replace("%RND%", secrets.token_urlsafe(12))

        # ARGS
        args = self.extract_value(json_data, 'ARGS')
        self._args = None if (args is None or not args) else args.replace("%RND%", secrets.token_urlsafe(12))

        # Referer
        ref = self.extract_value(json_data, 'Referer')
        self._ref = None if (ref is None or not ref) else ref.replace("%RND%", secrets.token_urlsafe(12))

        # UA
        ua = self.extract_value(json_data, 'UA')
        self._ua = None if (ua is None or not ua) else ua.replace("%RND%", secrets.token_urlsafe(12))

        # Body
        body = self.extract_value(json_data, 'Body')
        self._req_body = None if (body is None or not body) else body.replace("%RND%", secrets.token_urlsafe(12))

        # Cookie
        cookie = self.extract_value(json_data, 'Cookie')
        self._cookie = None if (cookie is None or not cookie) else cookie.replace("%RND%", secrets.token_urlsafe(12))

        # Header
        req_header = self.extract_value(json_data, 'Headers')
        self._req_header = None if (req_header is None or not req_header) \
            else req_header.replace("%RND%", secrets.token_urlsafe(12))

        # Blocked
        blocked = self.extract_value(json_data, 'Blocked')
        self._blocked = blocked

    @property
    def ref(self):
        return self._ref

    @property
    def path(self):
        return self._path

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

    @property
    def blocked(self):
        return self._blocked

    @staticmethod
    def extract_value(json_data, key):
        return json_data.get(key, None)

    def __str__(self):
        resp = 'path: {}; ua: {}; req_body: {}; args: {}; req_header: {}; req_cookie: {}'.format(
                self._path, self._ua, self._req_body, self._args, self._req_header, self._cookie
                )
        return resp
