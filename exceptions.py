class TokenTypeNotFound(Exception):
    """Raised when there is no typ field in header fields"""
    pass


class TokenSignAlgorithmNotFound(Exception):
    """Raised when there is no alg field in header fields"""
    pass


class InvalidTokenType(Exception):
    """Raised when the token type is not jwt"""
    pass


class InvalidInterfaceName(Exception):
    """Raised when the interface token name is not valid"""
    pass


class InvalidToken(Exception):
    """Raised when the token is not valid"""
    pass
