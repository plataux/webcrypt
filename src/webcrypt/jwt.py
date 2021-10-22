from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List, Any, TypeVar, Type
from pydantic import BaseModel, Field

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from uuid import uuid4

import webcrypt.convert as conv

from random import choice

from webcrypt.jws import JWS
from webcrypt.jwe import JWE

from collections import defaultdict

from hashlib import sha256

import webcrypt.exceptions as tex  # Token Exceptions


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


class TokenOptions(BaseModel):
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


T = TypeVar('T', bound=Token)


class JWT:
    """
    Encoder and decoder of JWT Tokens.

    The encoding involves:

    * Encoding the payload into a base64 string
    * Generating a header based on the JWK alg and key-type
    * Encoding the JWT header
    * Signing the Token

    """
    __slots__ = ('_options',
                 '_sign_ks', '_sign_kid_lookup', '_sign_alg_lookup',
                 '_encrypt_ks', '_encrypt_kid_lookup', '_encrypt_alg_lookup')

    def __init__(self,
                 jws: Optional[JWS | List[JWS]] = None,
                 jwe: Optional[JWE | List[JWE]] = None,
                 options: Optional[TokenOptions] = None):
        if jws is None:
            self._sign_ks: List[JWS] = [JWS.random_jws()]
        elif isinstance(jws, JWS):
            self._sign_ks = [jws]
        elif isinstance(jws, list):
            self._sign_ks = list(jws)
        else:
            raise ValueError("Unexected JWS Value")

        self._sign_kid_lookup = {x.kid: x for x in self._sign_ks}
        self._sign_alg_lookup = defaultdict(list)

        for jwk in self._sign_ks:
            self._sign_alg_lookup[jwk.alg].append(jwk)

        if jwe is None:
            # hkey = wk.hmac_genkey(SHA256())
            # self._jwk = JWK((hkey, None))
            self._encrypt_ks = [JWE.random_jwe()]
        elif isinstance(jwe, JWE):
            self._encrypt_ks = [jwe]
        elif isinstance(jwe, list):
            self._encrypt_ks = list(jwe)

        self._encrypt_kid_lookup = {x.kid: x for x in self._encrypt_ks}
        self._encrypt_alg_lookup = defaultdict(list)

        for jwk in self._encrypt_ks:
            self._encrypt_alg_lookup[jwk.alg].append(jwk)

        if options is None:
            self._options = TokenOptions()

    def to_jwks(self, passphrase: Optional[str] = None) -> str:
        ks = []
        jwks = {'keys': ks}

        for item in self._sign_ks:
            ks.append(item.to_jwk())

        for item in self._encrypt_ks:
            ks.append(item.to_jwk())

        jwks_json = json.dumps(jwks, indent=2)

        if passphrase is None:
            return jwks_json
        else:
            key = sha256(passphrase.encode()).digest()[:16]
            iv = os.urandom(12)
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(iv, jwks_json.encode(), b'')
            jwks_enc = iv + ciphertext
            return conv.bytes_to_b64(jwks_enc)

    @classmethod
    def from_jwks(cls, jwks: str, passphrase: Optional[str] = None) -> "JWT":
        if passphrase is None:
            try:
                jwks_dict: Dict[str, Any] = json.loads(jwks)
            except Exception as ex:
                raise ValueError(f"Invalid JWKS string: either corrupted, or encrypted: {ex}")
        else:
            try:
                jwks_enc = conv.bytes_from_b64(jwks)
                key = sha256(passphrase.encode()).digest()[:16]
                aesgcm = AESGCM(key)
                jwks_json: bytes = aesgcm.decrypt(jwks_enc[:12], jwks_enc[12:], b'')
                jwks_dict = json.loads(jwks_json)
            except Exception:
                raise ValueError(f"Could Not Decrypt/Parse JWKS, passphrase maybe invalid")

        jws, jwe = [], []

        for item in jwks_dict['keys']:
            if (_use := item['use']) == 'sig':
                jws.append(JWS.from_jwk(item))
            elif _use == 'enc':
                jwe.append(JWE.from_jwk(item))

        return cls(jws, jwe)

    def sign(self, token: Token,
             access_token: Optional[str] = None,
             extra_header: Optional[Dict[str, Any]] = None,
             kid: Optional[str] = None) -> str:

        if kid is not None:
            jwk: JWS = self._sign_kid_lookup[kid]
        else:
            jwk: JWS = choice(self._sign_ks)

        if access_token is not None:
            token.at_hash = self.at_hash(access_token, jwk)

        return jwk.sign(payload=conv.doc_to_bytes(token.dict(exclude_none=True)),
                        extra_header=extra_header)

    def verify(self, token: str, TokenClass: Type[T] = Token,
               access_token: Optional[str] = None) -> T:
        """

        Verify and decode Token

        :param token: Encoded Token str in the format ``b64head.b64payload.b64sig``
        :param TokenClass:
        :param access_token:
        :return: tuple of token validity and Decoded token if raise_errors is ``False``

        :raises ValueError: if the raw Token is not a Valid JWT
            of type ``str`` and structure ``typrb64head.b64payload.b64sig``

        :raises
        """

        jwk = self._sign_kid_lookup[JWS.decode_header(token)['kid']]

        # validate signature and decode token
        payload: Dict[str, Any] = conv.doc_from_bytes(jwk.verify(token))

        # Structural Token validation
        ptoken = TokenClass(**payload)

        self._verify_at_hash(ptoken, access_token, jwk)

        return ptoken

    def encrypt(self, token: Token,
                extra_header: Optional[Dict[str, Any]] = None,
                kid: Optional[str] = None) -> str:
        if kid is not None:
            jwk: JWE = self._encrypt_kid_lookup[kid]
        else:
            jwk: JWE = choice(self._encrypt_ks)
        return jwk.encrypt(token.json(exclude_none=True).encode(), extra_header=extra_header)

    def decrypt(self, token: str,
                TokenClass: Type[T] = Token) -> T:
        jwk: JWE = self._encrypt_kid_lookup[JWS.decode_header(token)['kid']]
        return TokenClass(**conv.doc_from_bytes(jwk.decrypt(token)))

    def _verify_at_hash(self, token: Token, access_token: str, jwk):
        try:
            if token.at_hash is not None:
                if access_token is None:
                    raise tex.InvalidClaims("at_hash is present but access_token "
                                            "was not provided")
                else:
                    _at_hash = self.at_hash(access_token, jwk)
                    if token.at_hash != _at_hash:
                        raise tex.InvalidClaims("Invalid at_hash against given access_token")
            if token.at_hash is None and access_token is not None:
                raise tex.InvalidClaims("at_hash was missing from the token")
        except tex.TokenException as ex:
            raise ex

    @staticmethod
    def at_hash(access_token, jws: JWS) -> str:
        hash_digest = jws.do_hash(access_token)
        cut_at = int(len(hash_digest) / 2)
        truncated = hash_digest[:cut_at]
        at_hash = conv.bytes_to_b64(truncated)
        return at_hash
