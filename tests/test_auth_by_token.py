import time
import unittest
import json
from test_jwt import TestJWT


class TestAuthByToken(TestJWT):
    
    def test_login_with_urlencoded_should_success(self):
        code, content, headers = self.http_post(self.LOGIN_PATH, {self.USERNAME_FIELD:self.USERNAME, self.PASSWORD_FIELD:self.PASSWORD}, headers={"Content-Type":"application/x-www-form-urlencoded"})
        self.assertEqual(code, 200)

    def test_login_should_with_json_should_fail(self):
        code, content, headers = self.http_post(self.LOGIN_PATH, {self.USERNAME_FIELD:self.USERNAME, self.PASSWORD_FIELD:self.PASSWORD}, headers={"Content-Type":"application/json"})
        self.assertEqual(code, 415)

    @TestJWT.with_all_algorithms()
    def test_malformed_token_should_fail(self, alg, key, secured_url):
        token = self.encode_jwt({"iss":self.JWT_ISS, "aud":self.JWT_AUD, "user":"toto", "iat":int(time.time()), "nbf":int(time.time()), "exp":int(time.time())+1000}, key, alg)
        #we replace . by # for the token to be malformed
        token = token.replace('.', '#')
        code, content, headers = self.http_get(secured_url, token=token)
        self.assertEqual(code, 401)
        self.assertEqual(headers["WWW-Authenticate"], 'Bearer realm="private area", error="invalid_token", error_description="Token is malformed or signature is invalid"')

    @TestJWT.with_all_algorithms()
    def test_invalid_signature_should_fail(self, alg, key, secured_url):
        token = self.encode_jwt({"iss":self.JWT_ISS, "aud":self.JWT_AUD, "user":"toto", "iat":int(time.time()), "nbf":int(time.time()), "exp":int(time.time())+1000}, key, alg)
        #we remove last 10 characters for the signature to be invalid
        token = token[:-10]
        code, content, headers = self.http_get(secured_url, token=token)
        self.assertEqual(code, 401)
        self.assertEqual(headers["WWW-Authenticate"], 'Bearer realm="private area", error="invalid_token", error_description="Token is malformed or signature is invalid"')

    @TestJWT.with_all_algorithms()
    def test_invalid_iss_should_fail(self, alg, key, secured_url):
        token = self.encode_jwt({"iss":"invalid", "aud":self.JWT_AUD, "user":"toto", "iat":int(time.time()), "nbf":int(time.time()), "exp":int(time.time())+1000}, key, alg)
        code, content, headers = self.http_get(secured_url, token=token)
        self.assertEqual(code, 401)
        self.assertEqual(headers["WWW-Authenticate"], 'Bearer realm="private area", error="invalid_token", error_description="Issuer is not valid"')

    @TestJWT.with_all_algorithms()
    def test_invalid_aud_should_fail(self, alg, key, secured_url):
        token = self.encode_jwt({"iss":self.JWT_ISS, "aud":"invalid", "user":"toto", "iat":int(time.time()), "nbf":int(time.time()), "exp":int(time.time())+1000}, key, alg)
        code, content, headers = self.http_get(secured_url, token=token)
        self.assertEqual(code, 401)
        self.assertEqual(headers["WWW-Authenticate"], 'Bearer realm="private area", error="invalid_token", error_description="Audience is not valid"')
    
    @TestJWT.with_all_algorithms()
    def test_invalid_token_exp_missing_should_fail(self, alg, key, secured_url):
        token = self.encode_jwt({"iss":self.JWT_ISS, "aud":self.JWT_AUD, "user":"toto", "iat":int(time.time()), "nbf":int(time.time())}, key, alg)
        code, content, headers = self.http_get(secured_url, token=token)
        self.assertEqual(code, 401)
        self.assertEqual(headers["WWW-Authenticate"], 'Bearer realm="private area", error="invalid_token", error_description="Expiration is missing in token"')

    @TestJWT.with_all_algorithms()
    def test_invalid_nbf_should_fail(self, alg, key, secured_url):
        token = self.encode_jwt({"iss":self.JWT_ISS, "aud":self.JWT_AUD, "user":"toto", "iat":int(time.time()), "nbf":int(time.time())+1000, "exp":int(time.time())+1000}, key, alg)
        code, content, headers = self.http_get(secured_url, token=token)
        self.assertEqual(code, 401)
        self.assertEqual(headers["WWW-Authenticate"], 'Bearer realm="private area", error="invalid_token", error_description="Token can\'t be processed now due to nbf field"')

    @TestJWT.with_all_algorithms()
    def test_invalid_exp_should_fail(self, alg, key, secured_url):
        token = self.encode_jwt({"iss":self.JWT_ISS, "aud":self.JWT_AUD, "user":"toto", "iat":int(time.time()), "nbf":int(time.time()), "exp":int(time.time())-1000}, key, alg)
        code, content, headers = self.http_get(secured_url, token=token)
        self.assertEqual(code, 401)
        self.assertEqual(headers["WWW-Authenticate"], 'Bearer realm="private area", error="invalid_token", error_description="Token expired"')

    @TestJWT.with_all_algorithms()
    def test_with_leeway_should_success(self, alg, key, secured_url):
        token = self.encode_jwt({"iss":self.JWT_ISS, "aud":self.JWT_AUD, "user":"toto", "iat":int(time.time())-1000, "nbf":int(time.time())-1000, "exp":int(time.time())-self.JWT_LEEWAY+1}, key, alg)
        code, content, headers = self.http_get(secured_url, token=token)
        self.assertEqual(code, 200)

    @TestJWT.with_all_algorithms()
    def test_should_success(self, alg, key, secured_url):
        token = self.encode_jwt({"iss":self.JWT_ISS, "aud":self.JWT_AUD, "user":"toto", "iat":int(time.time())-1000, "nbf":int(time.time())-1000, "exp":int(time.time())+10}, key, alg)
        code, content, headers = self.http_get(secured_url, token=token)
        self.assertEqual(code, 200)

    
        
