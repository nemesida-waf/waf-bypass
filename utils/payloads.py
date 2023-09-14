#!/usr/bin/env python3

import json
import secrets


def get_payload(json_path):
        
    # init
    ret = {}

    # processing JSON file
    with open(json_path) as f:
        try:
            jdata = json.load(f)['payload'][0]
        except Exception as e:
            print(
                'An error occurred while loading file {}: file not in JSON format ({})'
                .format(json_path, e)
            )
            return {}

    # url
    url = jdata.get('URL', None)
    ret['URL'] = None if not url else url.replace("%RND%", secrets.token_hex(3))

    # args
    args = jdata.get('ARGS', None)
    ret['ARGS'] = None if not args else args.replace("%RND%", secrets.token_hex(3))

    # body
    body = jdata.get('BODY', None)
    ret['BODY'] = None if not body else body.replace("%RND%", secrets.token_hex(3))

    # cookie
    cookie = jdata.get('COOKIE', None)
    ret['COOKIE'] = None if not cookie else cookie.replace("%RND%", secrets.token_hex(3))

    # ua
    ua = jdata.get('USER-AGENT', None)
    ret['USER-AGENT'] = None if not ua else ua.replace("%RND%", secrets.token_hex(3))

    # referer
    referer = jdata.get('REFERER', None)
    ret['REFERER'] = None if not referer else referer.replace("%RND%", secrets.token_hex(3))

    # header
    header = jdata.get('HEADER', None)
    ret['HEADER'] = None if not header else header.replace("%RND%", secrets.token_hex(3))

    # boundary
    boundary = jdata.get('BOUNDARY', None)
    ret['BOUNDARY'] = None if not boundary else boundary

    # method
    method = jdata.get('METHOD', None)
    ret['METHOD'] = None if not method else method.lower()

    # encode
    encode = jdata.get('ENCODE', None)
    ret['ENCODE'] = [] if not encode else encode.replace(',', ' ').split()

    # json
    is_json = jdata.get('JSON', None)
    ret['JSON'] = is_json if isinstance(is_json, bool) else False

    # blocked
    blocked = jdata.get('BLOCKED', None)
    ret['BLOCKED'] = blocked if isinstance(blocked, bool) else True

    # return dictionary
    return ret
