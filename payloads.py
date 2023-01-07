#!/usr/bin/env python3

import json
import secrets


class PayloadProcessing:
    
    def __init__(self, json_path):
        
        # init
        json_data = {}
        self._json_path = json_path

        # processing JSON file
        with open(json_path) as f:
            try:
                json_data = json.load(f)['req'][0]
            except Exception as e:
                print(
                    'An error occurred while loading file {}: file not in JSON format ({})'
                    .format(json_path, e)
                )

        # url
        url = self.extract_value(json_data, 'URL')
        self._url = None if not url else url.replace("%RND%", secrets.token_urlsafe(6))

        # args
        args = self.extract_value(json_data, 'ARGS')
        self._args = None if not args else args.replace("%RND%", secrets.token_urlsafe(6))

        # body
        body = self.extract_value(json_data, 'BODY')
        self._body = None if not body else body.replace("%RND%", secrets.token_urlsafe(6))

        # cookie
        cookie = self.extract_value(json_data, 'COOKIE')
        self._cookie = None if not cookie else cookie.replace("%RND%", secrets.token_urlsafe(6))

        # ua
        ua = self.extract_value(json_data, 'USER-AGENT')
        self._ua = None if not ua else ua.replace("%RND%", secrets.token_urlsafe(6))

        # referer
        referer = self.extract_value(json_data, 'REFERER')
        self._referer = None if not referer else referer.replace("%RND%", secrets.token_urlsafe(6))

        # header
        headers = self.extract_value(json_data, 'HEADER')
        self._headers = None if not headers else headers.replace("%RND%", secrets.token_urlsafe(6))

        # boundary
        boundary = self.extract_value(json_data, 'BOUNDARY')
        self._boundary = None if not boundary else boundary

        # method
        method = self.extract_value(json_data, 'METHOD')
        self._method = None if not method else method.lower()

        # blocked
        blocked = self.extract_value(json_data, 'BLOCKED')
        self._blocked = blocked if isinstance(blocked, bool) else True

    @property
    def json_path(self):
        return self._json_path

    @property
    def url(self):
        return self._url

    @property
    def args(self):
        return self._args

    @property
    def body(self):
        return self._body

    @property
    def cookie(self):
        return self._cookie

    @property
    def ua(self):
        return self._ua

    @property
    def referer(self):
        return self._referer

    @property
    def headers(self):
        return self._headers

    @property
    def boundary(self):
        return self._boundary

    @property
    def method(self):
        return self._method

    @property
    def blocked(self):
        return self._blocked

    @staticmethod
    def extract_value(json_data, key):
        return json_data.get(key, None)
