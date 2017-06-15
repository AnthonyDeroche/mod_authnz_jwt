import unittest
import requests
import jwt
import json
import sys
from contextlib import contextmanager
from functools import wraps

class TestJWT(unittest.TestCase):

    HMAC_SECURED_URL = "http://testjwt.local/hmac_secured"
    RSA_SECURED_URL = "http://testjwt.local/rsa_secured"
    EC_SECURED_URL = "http://testjwt.local/ec_secured"
    LOGIN_PATH = "http://testjwt.local/jwt_login"
    USERNAME = "test"
    PASSWORD = "test"
    HMAC_SHARED_SECRET = "secret"
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
    def with_all_algorithms(cls, algorithms=None):
        if algorithms is None:
            algorithms = cls.ALGORITHMS
        def decorator(func):
            @wraps(func)
            def handler(_self):
                for alg in algorithms:
                    if alg in ("HS256", "HS384", "HS512"):
                        key = cls.HMAC_SHARED_SECRET
                        secured_url = cls.HMAC_SECURED_URL
                    elif alg in ("RS256", "RS384", "RS512"):
                        f = open("/opt/mod_jwt_tests/rsa-priv.pem")
                        key = f.read()
                        f.close()
                        secured_url = cls.RSA_SECURED_URL
                    elif alg in ("ES256", "ES384", "ES512"):
                        f = open("/opt/mod_jwt_tests/ec-priv.pem")
                        key = f.read()
                        f.close()
                        secured_url = cls.EC_SECURED_URL
                    with _self.subTest(alg=alg, key=key):
                        func(_self, alg, key, secured_url)
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
        return r.status_code, r.content.decode('utf-8'), r.headers

    def decode_jwt(self, token):
        return jwt.decode(token, self.HMAC_SHARED_SECRET, audience="tests")

    def encode_jwt(self, payload, key, algorithm):
        return jwt.encode(payload, key, algorithm=algorithm).decode('utf-8')
