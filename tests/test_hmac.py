import unittest
import requests
import jwt
import json
import time

class TestHMAC(unittest.TestCase):

    SECURED_PATH = "http://hmac.testjwt.local/jwt_secured/"
    LOGIN_PATH = "http://hmac.testjwt.local/jwt_login"
    USERNAME = "test"
    PASSWORD = "test"
    HMAC_SHARED_SECRET = "secret"
    USERNAME_ATTRIBUTE = "user"
    USERNAME_FIELD = "user"
    PASSWORD_FIELD = "password"
    JWT_EXPDELAY = 1800
    JWT_NBF_DELAY = 0
    JWT_ISS = "hmac.testjwt.local"

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def http_get(self, url, token=None):
        headers = {}
        if token is not None:
            headers = {"Authorization", "Bearer %s" % token}
        r = requests.get(url, headers=headers)
        return r.status_code, r.content

    def http_post(self, url, data, token=None, headers=None):
        if headers is None:
            headers = {"Content-Type":"application/json"}
        if token is not None:
            headers = {"Authorization", "Bearer %s" % token}
        r = requests.post(url, data=data)
        return r.status_code, r.content, r.headers

    def decode_jwt(self, token):
        return jwt.decode(token, self.HMAC_SHARED_SECRET, audience="tests")

    def test_login_should_success(self):
        code, content, headers = self.http_post(self.LOGIN_PATH, {self.USERNAME_FIELD:self.USERNAME, self.PASSWORD_FIELD:self.PASSWORD})
        
        # we expect return code 200, JSON content type
        self.assertEqual(code, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")

        # we check if the JSON object is correct and token is valid
        received_object = json.loads(content.decode("utf-8"))
        self.assertTrue("token" in received_object)
        jwt_fields = self.decode_jwt(received_object["token"])
        self.assertTrue(all(claim in jwt_fields for claim in [self.USERNAME_ATTRIBUTE, "exp", "nbf", "iat", "iss", "aud"]))
        self.assertEqual(jwt_fields[self.USERNAME_ATTRIBUTE], self.USERNAME)
        # we assume this test takes less than 1s
        self.assertTrue(int(jwt_fields["iat"]) - int(time.time())<1) 
        self.assertEqual(int(jwt_fields["exp"])-int(jwt_fields["iat"]), self.JWT_EXPDELAY)
        self.assertEqual(jwt_fields["iss"], self.JWT_ISS)
        self.assertEqual(int(jwt_fields["nbf"]), int(jwt_fields["iat"])+self.JWT_NBF_DELAY)


    def test_login_with_bad_credentials_should_fail(self):
        code, content, headers = self.http_post(self.LOGIN_PATH, {self.USERNAME_FIELD:self.USERNAME, self.PASSWORD_FIELD:"azerty"})
        self.assertEqual(code, 401)
        code, content, headers = self.http_post(self.LOGIN_PATH, {self.USERNAME_FIELD:self.USERNAME, self.PASSWORD_FIELD:""})
        self.assertEqual(code, 401)
        code, content, headers = self.http_post(self.LOGIN_PATH, {self.USERNAME_FIELD:self.USERNAME})
        self.assertEqual(code, 401)
        code, content, headers = self.http_post(self.LOGIN_PATH, {})
        self.assertEqual(code, 401)
        
    @unittest.skip
    def test_login_with_bad_content_type_should_fail(self):
        code, content, headers = self.http_post(self.LOGIN_PATH, {self.USERNAME_FIELD:self.USERNAME, self.PASSWORD_FIELD:self.PASSWORD}, headers={"Content-Type":"application/x-www-form-urlencoded"})
        self.assertEqual(code, 401)
    
    @unittest.skip
    def test_valid_token_should_success(self):
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9._pede1zX8pZuizVAHmG3hLwfmCsgWtB2WtF3Jo5ODrY"
