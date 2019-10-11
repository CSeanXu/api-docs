#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import time
import json
import uuid
import hashlib
import hmac

from sodabot.http_utils import get, post

from urllib import request, parse, error


class ApiClient(object):

    def __init__(self, api_key, api_secret, host, https=True, timeout=10, enable_debug=False):
        if host is None or api_key is None or api_secret is None:
            raise ValueError("Missing required arg: api_key, api_secret, host")
        self._api_key = api_key
        self._api_secret = api_secret.encode('utf-8')
        self._host = host.lower()
        self._protocol = 'https' if https else 'http'
        self._timeout = timeout
        self._debug = enable_debug

    @property
    def _hostname(self):
        n = self._host.find(':')
        if n > 0:
            return self._host[:n]
        return self._host

    async def get(self, path, **params):
        return await self._http('GET', path, params, None)

    async def post(self, path, obj=None):
        data = json.dumps(obj) if obj is not None else None
        return await self._http('POST', path, {}, data)

    async def _http(self, method, path, params, data):
        # build payload:
        param_list = ['%s=%s' % (k, v) for k, v in params.items()]
        param_list.sort()
        payload = [method, self._hostname, path, '&'.join(param_list)]
        headers = {
            'API-Key': self._api_key,
            'API-Signature-Method': 'HmacSHA256',
            'API-Signature-Version': '1',
            'API-Timestamp': str(int(time.time() * 1000))
        }
        if method == 'POST' and path.startswith('/v1/trade/'):
            headers['API-Unique-ID'] = uuid.uuid4().hex
        headers_list = ['%s: %s' % (k.upper(), v) for k, v in headers.items()]
        headers_list.sort()
        payload.extend(headers_list)
        payload.append(data if data else '')
        payload_str = '\n'.join(payload)
        # signature:
        sign = hmac.new(self._api_secret, payload_str.encode('utf-8'), hashlib.sha256).hexdigest()
        self.debug('payload:\n----\n' + payload_str + '----\nsignature: ' + sign)
        headers['API-Signature'] = sign
        # build request:
        if data:
            data = data.encode('utf-8')
        else:
            data = None
        url = '%s://%s%s?%s' % (self._protocol, self._host, path, parse.urlencode(params))
        self.debug('%s: %s' % (method, url))

        if method == "POST":
            headers["Content-Type"] = "application/json"
            resp = await post(url, headers=headers, data=data, timeout=self._timeout)
        elif method == "GET":
            resp = await get(url, headers=headers, timeout=self._timeout)
        else:
            raise ValueError("HTTP Method Not Implemented: {}".format(method))

        self.debug('--- URL %s RESPONSE %s ' % (url, resp))

        return resp

    def debug(self, msg):
        if self._debug:
            print(msg)
