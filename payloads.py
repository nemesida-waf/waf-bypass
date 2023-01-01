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

        # URL
        url = self.extract_value(json_data, 'URL')
        self._url = None if not url else url.replace("%RND%", secrets.token_urlsafe(12))

        # ARGS
        args = self.extract_value(json_data, 'ARGS')
        self._args = None if not args else args.replace("%RND%", secrets.token_urlsafe(12))

        # Body
        body = self.extract_value(json_data, 'Body')
        self._body = None if not body else body.replace("%RND%", secrets.token_urlsafe(12))

        # Cookie
        cookie = self.extract_value(json_data, 'Cookie')
        self._cookie = None if not cookie else cookie.replace("%RND%", secrets.token_urlsafe(12))

        # UA
        ua = self.extract_value(json_data, 'UA')
        self._ua = None if not ua else ua.replace("%RND%", secrets.token_urlsafe(12))

        # Referer
        referer = self.extract_value(json_data, 'Referer')
        self._referer = None if not referer else referer.replace("%RND%", secrets.token_urlsafe(12))

        # Headers
        headers = self.extract_value(json_data, 'Headers')
        self._headers = None if not headers else headers.replace("%RND%", secrets.token_urlsafe(12))

        # Boundary
        boundary = self.extract_value(json_data, 'Boundary')
        self._boundary = None if not boundary else boundary

        # Method
        method = self.extract_value(json_data, 'Method')
        self._method = None if not method else method.lower()

        # Blocked (True if not set)
        blocked = self.extract_value(json_data, 'Blocked')
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
