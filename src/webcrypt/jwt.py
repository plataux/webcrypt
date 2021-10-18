from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List, Tuple, Any, TypeVar, Type
from pydantic import BaseModel, Field

from uuid import uuid4

import webcrypt.convert as conv
import webcrypt.jwk as wj
import webcrypt.keys as wk
from webcrypt.jwk import JWK, JWK_Algorithm

from webcrypt.jwk import SHA256, SHA512, SHA384


T = TypeVar('T')


def dt_offset(days=0, hours=0, minutes=0, seconds=60) -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=days, hours=hours, minutes=minutes,
                                                  seconds=seconds)


def dt_now() -> datetime:
    return datetime.now(timezone.utc)


class Token(BaseModel):
    """
    Acts as a General Purpose JWT
    and OpenID Connect Core 1.0 ID Token
    The ID Token is a security token that contains Claims
    about the Authentication of an End-User
    by an Authorization Server when using a Client

    The following Claims are used within the ID Token for all
    OAuth 2.0 flows used by OpenID Connect
    """

    # Mandatory Fields
    # Expires UTC timestamp
    exp: int = Field(default_factory=lambda: int(dt_offset().timestamp()))

    # Issued At UTC Timestamp
    iat: int = Field(default_factory=lambda: int(dt_now().timestamp()))

    ###############################
    # Generic Fields
    # JWT ID: Unique token Identifier
    jti: str = Field(default_factory=lambda: str(uuid4()))

    #############################
    # Conditionally Binding Fields

    # https scheme that contains scheme and host, and optionally
    # port number and path components and no query or fragment components
    iss: Optional[str]

    # A locally unique and never reassigned identifier within the Issuer for the End-User
    # which is intended to be consumed by the Client
    sub: Optional[str]

    # It MUST contain the OAuth 2.0 client_id of the Relying Party as an audience value
    aud: Optional[str]

    # in case access_token is provided
    at_hash: Optional[str]

    #####################################

    # authentication time UTC Timestamp
    auth_time: Optional[int]

    # String value used to associate a Client session with an ID Token,
    # and to mitigate replay attacks
    nonce: Optional[str]

    # Authentication Context Class Reference
    acr: Optional[str]

    # Authentication Methods References
    amr: Optional[List[str]]

    #  Authorized party - the party to which the ID Token was issued.
    #  If present, it MUST contain the OAuth 2.0 Client ID of this party.
    azp: Optional[str]

    # Extra Claims
    eclaims: Optional[Dict[Any, Any]]


class EncoderOptions(BaseModel):
    verify_signature: bool = True
    verify_aud: bool = True
    verify_iat: bool = True
    verify_exp: bool = True
    verify_nbf: bool = True
    verify_iss: bool = True
    verify_sub: bool = True
    verify_jti: bool = True
    verify_at_hash: bool = True

    require_aud: bool = False
    require_iat: bool = False
    require_exp: bool = False
    require_nbf: bool = False
    require_iss: bool = False
    require_sub: bool = False
    require_jti: bool = False
    require_at_hash: bool = False

    leeway: int = 0


class TokenEncoder:
    __slots__ = ('_jwk', '_options')

    def __init__(self, jwk: Optional[JWK] = None, options: Optional[EncoderOptions] = None):
        if jwk is None:
            # hkey = wk.hmac_genkey(SHA256())
            # self._jwk = JWK((hkey, None))
            self._jwk = JWK.random_jwk_alg()
        else:
            self._jwk = jwk

        if options is None:
            self._options = EncoderOptions()

    def encode(self, token: Token | dict,
               access_token: Optional[str] = None) -> str:
        if isinstance(token, Token):
            token = token.dict(exclude_none=True)

        return self._jwk.sign(payload=token)

    def decode(self, token: str) -> Tuple[bool, Dict[str, Any]]:
        return self._jwk.verify(token)

    def decode_token(self, token: str, TokenClass: Type[T] = Token) -> T:
        valid, payload = self._jwk.verify(token, raise_errors=True)
        return TokenClass(**payload)

    @property
    def jwk(self):
        return self._jwk
