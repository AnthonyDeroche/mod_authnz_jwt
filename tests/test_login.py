import time
import unittest
import json
from test_jwt import TestJWT


class TestLogin(TestJWT):

    def assertToken(self, token, public_key, alg):
        jwt_fields = self.decode_jwt(token, public_key, alg)
        self.assertTrue(all(claim in jwt_fields for claim in [self.USERNAME_ATTRIBUTE, "exp", "nbf", "iat", "iss", "aud"]))
        self.assertEqual(jwt_fields[self.USERNAME_ATTRIBUTE], self.USERNAME)
        # we assume this test takes less than 1s
        self.assertTrue(int(jwt_fields["iat"]) - int(time.time())<1)
        self.assertEqual(int(jwt_fields["exp"])-int(jwt_fields["iat"]), self.JWT_EXPDELAY)
        self.assertEqual(jwt_fields["iss"], self.JWT_ISS)
        self.assertEqual(int(jwt_fields["nbf"]), int(jwt_fields["iat"])+self.JWT_NBF_DELAY)

    @TestJWT.with_all_algorithms(algorithms=("HS256", "RS256", "ES256"))
    def test_login_should_success_with_json(self, alg, public_key, private_key, secured_url, login_url):
        code, content, headers, cookies = self.http_post(login_url, {self.USERNAME_FIELD:self.USERNAME, self.PASSWORD_FIELD:self.PASSWORD})

        # we expect return code 200, JSON content type
        self.assertEqual(code, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")

        # we check if the JSON object is correct and token is valid
        received_object = json.loads(content)
        self.assertTrue("token" in received_object)

        self.assertToken(received_object["token"], public_key, alg)

    @TestJWT.with_all_algorithms(algorithms=("HS256", "RS256", "ES256"))
    def test_login_should_success_with_custom_token_name(self, alg, public_key, private_key, secured_url, login_url):
        code, content, headers, cookies = self.http_post(login_url + "/token_custom_name", {self.USERNAME_FIELD:self.USERNAME, self.PASSWORD_FIELD:self.PASSWORD})

        # we expect return code 200, JSON content type
        self.assertEqual(code, 200)
        self.assertEqual(headers.get("Content-Type"), "application/json")

        # we check if the JSON object is correct and token is valid
        received_object = json.loads(content)
        self.assertTrue("CustomToken" in received_object)

        self.assertToken(received_object["CustomToken"], public_key, alg)

    @TestJWT.with_all_algorithms(algorithms=("HS256", "RS256", "ES256"))
    def test_login_with_bad_credentials_should_fail(self, alg, public_key, private_key, secured_url, login_url):
        code, content, headers, cookies = self.http_post(login_url, {self.USERNAME_FIELD:self.USERNAME, self.PASSWORD_FIELD:"azerty"})
        self.assertEqual(code, 401)
        code, content, headers, cookies = self.http_post(login_url, {self.USERNAME_FIELD:self.USERNAME, self.PASSWORD_FIELD:""})
        self.assertEqual(code, 401)
        code, content, headers, cookies = self.http_post(login_url, {self.USERNAME_FIELD:self.USERNAME})
        self.assertEqual(code, 401)
        code, content, headers, cookies = self.http_post(login_url, {})
        self.assertEqual(code, 401)

    @TestJWT.with_all_algorithms(algorithms=("HS256", "RS256", "ES256"))
    def test_get_on_login_path_should_fail(self, alg, public_key, private_key, secured_url, login_url):
        code, content, headers = self.http_get(login_url)
        self.assertEqual(code, 405)

    # Cookie delivery tests #

    @TestJWT.with_all_algorithms(algorithms=("HS256", "RS256", "ES256"), delivery="cookie")
    def test_login_should_success_with_cookie(self, alg, public_key, private_key, secured_url, login_url):
        code, content, headers, cookies = self.http_post(login_url, {self.USERNAME_FIELD:self.USERNAME, self.PASSWORD_FIELD:self.PASSWORD})

        self.assertEqual(code, 200)

        self.assertTrue("AuthToken" in cookies)
        self.assertToken(cookies["AuthToken"], public_key, alg)

    # TODO add test when using bad cookie name
    @TestJWT.with_all_algorithms(algorithms=("HS256",), delivery="cookie")
    def test_login_should_success_with_custom_cookie_name(self, alg, public_key, private_key, secured_url, login_url):
        code, content, headers, cookies = self.http_post(login_url + "/cookie_custom_name", {self.USERNAME_FIELD:self.USERNAME, self.PASSWORD_FIELD:self.PASSWORD})

        self.assertEqual(code, 200)

        self.assertEqual(len(cookies), 1)

        # cookies.get("AuthToken") will return cookie.value not the cookie object
        for c in cookies:
            self.assertEqual(c.name, "CustomCookie")
            self.assertTrue(c.secure)
            self.assertTrue(c.has_nonstandard_attr("HttpOnly"))
            self.assertTrue(c.has_nonstandard_attr("SameSite"))

            self.assertToken(c.value, public_key, alg)

    @TestJWT.with_all_algorithms(algorithms=("HS256",), delivery="cookie")
    def test_login_should_success_with_custom_cookie_attributes(self, alg, public_key, private_key, secured_url, login_url):
        code, content, headers, cookies = self.http_post(login_url + "/cookie_custom_attr", {self.USERNAME_FIELD:self.USERNAME, self.PASSWORD_FIELD:self.PASSWORD})

        self.assertEqual(code, 200)

        self.assertEqual(len(cookies), 1)

        for c in cookies:
            self.assertEqual(c.name, "AuthToken")
            self.assertTrue(c.path, "/secure")
            self.assertTrue(c.has_nonstandard_attr('CustomAttr'))

            self.assertToken(c.value, public_key, alg)
