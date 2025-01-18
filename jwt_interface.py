from core.jws_core import JWSGenerator, JWSExtractor
from exceptions import InvalidInterfaceName


class JWTInterface:
    JWS_TOKEN = "jws"
    JWE_TOKEN = "jwe"

    def __init__(self, token_type, header=None):
        if token_type == self.JWS_TOKEN:
            self.token_generator = JWSGenerator(header)
            self.token_extractor = JWSExtractor()
        elif token_type == self.JWE_TOKEN:
            raise InvalidInterfaceName
        else:
            raise InvalidInterfaceName

    def generate_token(self, payload, secret):
        return self.token_generator.generate(payload, secret)

    def is_token_valid(self, token, secret):
        return self.token_extractor.is_token_valid(token, secret)

    def extract_token(self, token, secret):
        return self.token_extractor.extract(token, secret)

