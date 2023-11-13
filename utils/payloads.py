#!/usr/bin/env python3

import json
import secrets


def get_payload(json_path):
    # processing JSON file
    with open(json_path) as f:
        try:
            jdata = json.load(f)['payload'][0]
        except Exception as e:
            print(
                f'An error occurred while loading file {json_path}: file not in JSON format ({e})'
            )
            return {}

    # url
    url = jdata.get('URL', None)
    ret = {'URL': url.replace("%RND%", secrets.token_hex(3)) if url else None}
    # args
    args = jdata.get('ARGS', None)
    ret['ARGS'] = args.replace("%RND%", secrets.token_hex(3)) if args else None

    # body
    body = jdata.get('BODY', None)
    ret['BODY'] = body.replace("%RND%", secrets.token_hex(3)) if body else None

    # cookie
    cookie = jdata.get('COOKIE', None)
    ret['COOKIE'] = cookie.replace("%RND%", secrets.token_hex(3)) if cookie else None

    # ua
    ua = jdata.get('USER-AGENT', None)
    ret['USER-AGENT'] = ua.replace("%RND%", secrets.token_hex(3)) if ua else None

    # referer
    referer = jdata.get('REFERER', None)
    ret['REFERER'] = referer.replace("%RND%", secrets.token_hex(3)) if referer else None

    # header
    header = jdata.get('HEADER', None)
    ret['HEADER'] = header.replace("%RND%", secrets.token_hex(3)) if header else None

    # boundary
    boundary = jdata.get('BOUNDARY', None)
    ret['BOUNDARY'] = boundary or None

    # method
    method = jdata.get('METHOD', None)
    ret['METHOD'] = method.lower() if method else None

    # encode
    encode = jdata.get('ENCODE', None)
    ret['ENCODE'] = encode.replace(',', ' ').split() if encode else []

    # json
    is_json = jdata.get('JSON', None)
    ret['JSON'] = is_json if isinstance(is_json, bool) else False

    # blocked
    blocked = jdata.get('BLOCKED', None)
    ret['BLOCKED'] = blocked if isinstance(blocked, bool) else True

    # return dictionary
    return ret
