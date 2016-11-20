import time
import unittest
import json
from test_jwt import TestJWT


class TestLogin(TestJWT):

    def test_login_should_success(self):
        code, content, headers = self.http_post(self.LOGIN_PATH, {self.USERNAME_FIELD:self.USERNAME, self.PASSWORD_FIELD:self.PASSWORD})
        
        # we expect return code 200, JSON content type
        self.assertEqual(code, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")

        # we check if the JSON object is correct and token is valid
        received_object = json.loads(content)
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

    def test_get_on_login_path_should_fail(self):
        code, content, headers = self.http_get(self.LOGIN_PATH)
        self.assertEqual(code, 405)
