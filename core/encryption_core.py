import hashlib
import hmac


class Encryptor:
    def __init__(self, encryption_type):
        self.encryption_function = self.__config_encryption_function(encryption_type)

    @staticmethod
    def __hs256_hash_function(data, secret):
        raw_signature = hmac.new(secret, data, hashlib.sha256)
        return raw_signature.hexdigest()

    @staticmethod
    def __hs512_hash_function(data, secret):
        raw_signature = hmac.new(secret, data, hashlib.sha512)
        return raw_signature.hexdigest()

    def __config_encryption_function(self, encryption_type):
        if encryption_type == "HS256":
            return self.__hs256_hash_function
        elif encryption_type == "HS512":
            return self.__hs512_hash_function
        return self.__hs256_hash_function

    def encrypt(self, data, secret):
        data = data.encode("utf-8")
        secret = secret.encode("utf-8")
        return self.encryption_function(data, secret)


class Decrypter:
    def __init__(self):
        pass

    def decrypt(self, data, secret):
        pass
