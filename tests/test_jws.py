import unittest
from jwt_interface import JWTInterface
from exceptions import InvalidToken


class JWSTokenTestCase(unittest.TestCase):
    def setUp(self):
        self.jws_interface = JWTInterface("jws")
        self.test_header = {"alg": "HS256", "typ": "JWT"}
        self.test_payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
        self.test_secret = "very-secret-secret"
        self.test_correct_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +\
                          ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ" +\
                          ".984b19f2992a6ffc7dd0c94281c8bcaaa6ef76b739d9ac8390d641580a8f6910"
        self.test_invalid_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +\
                          ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ" +\
                          ".invalid_signature"

    def test_correct_token_generation(self):
        generated_token = self.jws_interface.generate_token(self.test_payload, self.test_secret)
        self.assertEqual(generated_token, self.test_correct_token)

    def test_validate_correct_token(self):
        self.assertTrue(self.jws_interface.is_token_valid(self.test_correct_token, self.test_secret))

    def test_validate_invalid_token(self):
        self.assertFalse(self.jws_interface.is_token_valid(self.test_invalid_token, self.test_secret))

    def test_extract_correct_token(self):
        extracted_payload = self.jws_interface.extract_token(self.test_correct_token, self.test_secret)
        self.assertEqual(extracted_payload, self.test_payload)

    def test_extract_invalid_token(self):
        with self.assertRaises(InvalidToken):
            self.jws_interface.extract_token(self.test_invalid_token, self.test_secret)
