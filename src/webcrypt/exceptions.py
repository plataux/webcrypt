

class TokenException(Exception):
    pass


class InvalidToken(TokenException):
    pass


class AlgoMismatch(TokenException):
    pass


class InvalidSignature(TokenException):
    pass


class InvalidClaims(TokenException):
    pass
