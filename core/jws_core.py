from base64 import urlsafe_b64encode, urlsafe_b64decode
from exceptions import TokenTypeNotFound, TokenSignAlgorithmNotFound, InvalidTokenType, InvalidToken
from core.encryption_core import Encryptor
import json
import ast


class JWSGenerator:
    DEFAULT_HEADER = {"alg": "HS256", "typ": "JWT"}
    SIGN_ALG_FIELD = "alg"
    TOKEN_TYPE_FIELD = "typ"
    JWT_TOKEN_TYPE = "JWT"

    def __init__(self, header=None):
        self.header = header if header is not None else self.DEFAULT_HEADER
        self.__encryptor = None
        self.__config_generator(self.header)

    def __set_sign_function(self, header):
        if self.SIGN_ALG_FIELD not in header.keys():
            raise TokenSignAlgorithmNotFound
        sign_alg = header[self.SIGN_ALG_FIELD]
        self.__encryptor = Encryptor(encryption_type=sign_alg)

    def __check_token_type(self, header):
        if self.TOKEN_TYPE_FIELD not in header.keys():
            raise TokenTypeNotFound
        token_type = header[self.TOKEN_TYPE_FIELD]
        if token_type != self.JWT_TOKEN_TYPE:
            raise InvalidTokenType

    def __config_generator(self, header):
        self.__set_sign_function(header)
        self.__check_token_type(header)

    @staticmethod
    def __convert_byte_to_base64_url_encoding(data):
        return urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

    @staticmethod
    def __convert_dict_to_str(dict):
        json_str = json.dumps(dict)
        result = ""
        is_delete_allowed = True
        for char in json_str:
            if char == " " and is_delete_allowed:
                continue
            if char == '\"':
                is_delete_allowed = not is_delete_allowed
            result += char
        return result

    def __generate_signature(self, base64_header, base64_payload, secret):
        data_base64url = f"{base64_header}.{base64_payload}"
        signature = self.__encryptor.encrypt(data=data_base64url, secret=secret)
        return signature

    def generate(self, payload, secret):
        header_byte = self.__convert_dict_to_str(self.header).encode("utf-8")
        header_base64url = self.__convert_byte_to_base64_url_encoding(header_byte)
        payload_byte = self.__convert_dict_to_str(payload).encode("utf-8")
        payload_base64url = self.__convert_byte_to_base64_url_encoding(payload_byte)

        signature = self.__generate_signature(base64_header=header_base64url, base64_payload=payload_base64url, secret=secret)
        return f"{header_base64url}.{payload_base64url}.{signature}"


class JWSExtractor:
    SIGN_ALG_FIELD = "alg"

    def __init__(self):
        pass

    @staticmethod
    def __convert_base64_to_dict(data):
        padding = '=' * (4 - len(data) % 4)
        data_str = urlsafe_b64decode(data + padding).decode("utf-8")
        return ast.literal_eval(data_str)

    def __get_token_encrypt_algorithm(self, header):
        if self.SIGN_ALG_FIELD not in header.keys():
            raise TokenSignAlgorithmNotFound
        sign_alg = header[self.SIGN_ALG_FIELD]
        return Encryptor(encryption_type=sign_alg)

    def is_token_valid(self, token, secret):
        header_base64, payload_base64, signature = token.split(".")
        header = self.__convert_base64_to_dict(header_base64)
        encryptor = self.__get_token_encrypt_algorithm(header)
        res_signature = encryptor.encrypt(f"{header_base64}.{payload_base64}", secret)
        return res_signature == signature

    def extract(self, token, secret):
        if not self.is_token_valid(token, secret):
            raise InvalidToken
        header_base64, payload_base64, signature = token.split(".")
        payload = self.__convert_base64_to_dict(payload_base64)
        return payload

