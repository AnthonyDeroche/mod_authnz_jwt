import unittest
import requests
import jwt
import json
import sys
from contextlib import contextmanager
from functools import wraps
import base64


class TestJWT(unittest.TestCase):

    BASE_URL = "http://testjwt.local/"

    USERNAME = "test"
    PASSWORD = "test"
    HMAC_SHARED_SECRET_BASE64 = "bnVsbGNoYXIAc2VjcmV0"
    USERNAME_ATTRIBUTE = "user"
    USERNAME_FIELD = "user"
    PASSWORD_FIELD = "password"
    JWT_EXPDELAY = 1800
    JWT_NBF_DELAY = 0
    JWT_ISS = "testjwt.local"
    JWT_AUD = "tests"
    JWT_LEEWAY = 10
    ALGORITHMS = ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]

    @classmethod
    def with_all_algorithms(cls, algorithms=None, delivery="json"):
        if algorithms is None:
            algorithms = cls.ALGORITHMS
        def decorator(func):
            @wraps(func)
            def handler(_self):
                for alg in algorithms:
                    baseUrl = cls.BASE_URL + alg + '/' + delivery;
                    secured_url = baseUrl + '/secured'
                    login_url = baseUrl + '/login'
                    if alg in ("HS256", "HS384", "HS512"):
                        private_key = base64.b64decode(cls.HMAC_SHARED_SECRET_BASE64)
                        public_key = private_key
                    elif alg in ("RS256", "RS384", "RS512"):
                        f_priv = open("/opt/mod_jwt_tests/rsa-priv.pem")
                        private_key = f_priv.read()
                        f_priv.close()
                        f_pub = open("/opt/mod_jwt_tests/rsa-pub.pem")
                        public_key = f_pub.read()
                        f_pub.close()
                    elif alg in ("ES256", "ES384", "ES512"):
                        f_priv = open("/opt/mod_jwt_tests/ec-priv.pem")
                        private_key = f_priv.read()
                        f_priv.close()
                        f_pub = open("/opt/mod_jwt_tests/ec-pub.pem")
                        public_key = f_pub.read()
                        f_pub.close()
                    with _self.subTest(alg=alg, public_key=public_key, private_key=private_key):
                        func(_self, alg, public_key, private_key, secured_url, login_url)
            return handler
        return decorator

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def http_get(self, url, token=None):
        headers = {}
        if token is not None:
            headers = {"Authorization": "Bearer %s" % token}
        r = requests.get(url, headers=headers)
        return r.status_code, r.content.decode('utf-8'), r.headers

    def http_post(self, url, data, token=None, headers=None):
        if headers is None:
            headers = {}
        if "Content-Type" not in headers:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if "Authorization" not in headers and token is not None:
            headers["Authorization"] = "Bearer %s" % token
        r = requests.post(url, data=data, headers=headers)
        return r.status_code, r.content.decode('utf-8'), r.headers, r.cookies

    def decode_jwt(self, token, key, algorithm):
        return jwt.decode(token, key, audience="tests", algorithms=[algorithm])

    def encode_jwt(self, payload, key, algorithm):
        return jwt.encode(payload, key, algorithm=algorithm).decode('utf-8')
