############################################################################
# Copyright 2021 Plataux LLC                                               #
#                                                                          #
# Licensed under the Apache License, Version 2.0 (the "License");          #
# you may not use this file except in compliance with the License.         #
# You may obtain a copy of the License at                                  #
#                                                                          #
#    https://www.apache.org/licenses/LICENSE-2.0                           #
#                                                                          #
# Unless required by applicable law or agreed to in writing, software      #
# distributed under the License is distributed on an "AS IS" BASIS,        #
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. #
# See the License for the specific language governing permissions and      #
# limitations under the License.                                           #
############################################################################

"""
# https://www.iana.org/assignments/jwt/jwt.xhtml#claims
# https://openid.net/specs/openid-connect-core-1_0.html
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List, Any, TypeVar, Type
from pydantic import BaseModel, Field

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# from hashlib import sha256

from uuid import uuid4
import os

import webcrypt.convert as conv

from random import choice

from webcrypt.jws import JWS
from webcrypt.jwe import JWE

from collections import defaultdict

import webcrypt.exceptions as tex  # Token Exceptions


def ts_offset(days=0, hours=0, minutes=0, seconds=0) -> int:
    return int((datetime.now(timezone.utc) + timedelta(days=days,
                                                       hours=hours,
                                                       minutes=minutes,
                                                       seconds=seconds)).timestamp())


def ts_now() -> int:
    return int(datetime.now(timezone.utc).timestamp())


class Token(BaseModel):
    """
    Acts as a General Purpose JWT, and OpenID Connect Core 1.0 ID Token.

    The ID Token is a security token that contains Claims
    about the Authentication of an End-User
    by an Authorization Server when authorizing a software client.

    The General JWT Claims are defined here, most of which are optional to use

    https://datatracker.ietf.org/doc/html/rfc7519#section-4.1

    The following Claims are used within the ID Token for all
    OAuth 2.0 flows used by OpenID Connect
    """

    # Issued At UTC Timestamp
    iat: int = Field(default_factory=lambda: ts_now())

    # Expires UTC timestamp - 60 minutes by default
    exp: int = Field(default_factory=lambda: ts_offset(minutes=60))

    ###############################
    # Generic Fields
    # JWT ID: Unique token Identifier
    jti: str = Field(default_factory=lambda: str(uuid4()))

    # Valid Not Before a given timestamp
    nbf: Optional[int]

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

    # in case access_token is provided. This is an OpenID Claim
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
                 jwe: Optional[JWE | List[JWE]] = None):

        self._sign_ks: List[JWS]

        if jws is None:
            self._sign_ks: List[JWS] = [JWS.random_jws()]
        elif isinstance(jws, JWS):
            self._sign_ks: List[JWS] = [jws]
        elif isinstance(jws, list):
            self._sign_ks: List[JWS] = list(jws)
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

    def to_jwks(self, encryption_key: Optional[bytes] = None) -> str:
        ks = []
        jwks = {'keys': ks}

        for item in self._sign_ks:
            ks.append(item.to_jwk())

        for item in self._encrypt_ks:
            ks.append(item.to_jwk())

        jwks_json = json.dumps(jwks, indent=2)

        if encryption_key is None:
            return jwks_json
        else:
            iv = os.urandom(12)
            aesgcm = AESGCM(encryption_key)
            ciphertext = aesgcm.encrypt(iv, jwks_json.encode(), b'')
            jwks_enc = iv + ciphertext
            return conv.bytes_to_b64(jwks_enc)

    @classmethod
    def from_jwks(cls, jwks: str, encryption_key: Optional[bytes] = None) -> "JWT":
        if encryption_key is None:
            try:
                jwks_dict: Dict[str, Any] = json.loads(jwks)
            except Exception as ex:
                raise ValueError(
                    f"Invalid JWKS string: either corrupted, or encrypted: {ex}")
        else:
            aesgcm = AESGCM(encryption_key)
            try:
                jwks_enc = conv.bytes_from_b64(jwks)
                jwks_json: bytes = aesgcm.decrypt(jwks_enc[:12], jwks_enc[12:], b'')
                jwks_dict = json.loads(jwks_json)
            except Exception:
                raise ValueError(
                    f"Could Not Decrypt/Parse JWKS, AES key maybe incorrect")

        jws, jwe = [], []

        for item in jwks_dict['keys']:
            if (_use := item['use']) == 'sig':
                jws.append(JWS.from_jwk(item))
            elif _use == 'enc':
                jwe.append(JWE.from_jwk(item))

        return cls(jws, jwe)

    def public_jwks(self) -> Dict[str, Any]:

        ks = []
        jwks = {'keys': ks}

        for jwk in self._sign_ks:
            if jwk.kty != 'oct':
                ks.append(jwk.public_jwk())

        return jwks

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

        JWT._verify_at_hash(ptoken, access_token, jwk)
        JWT._verify_time_claims(ptoken)

        return ptoken

    def encrypt(self, token: Token, compress=True,
                extra_header: Optional[Dict[str, Any]] = None,
                kid: Optional[str] = None) -> str:
        if kid is not None:
            jwk: JWE = self._encrypt_kid_lookup[kid]
        else:
            jwk: JWE = choice(self._encrypt_ks)
        return jwk.encrypt(token.json(exclude_none=True).encode(),
                           compress=compress, extra_header=extra_header)

    def decrypt(self, token: str,
                TokenClass: Type[T] = Token) -> T:
        jwk: JWE = self._encrypt_kid_lookup[JWS.decode_header(token)['kid']]
        return TokenClass(**conv.doc_from_bytes(jwk.decrypt(token)))

    @staticmethod
    def _verify_at_hash(token: Token, access_token: str, jwk: JWS):
        try:
            if token.at_hash is not None:
                if access_token is None:
                    raise tex.InvalidClaims("at_hash is present but access_token "
                                            "was not provided")
                else:
                    _at_hash = JWT.at_hash(access_token, jwk)
                    if token.at_hash != _at_hash:
                        raise tex.InvalidClaims("Invalid at_hash against given access_token")
            if token.at_hash is None and access_token is not None:
                raise tex.InvalidClaims("at_hash was missing from the token")
        except tex.TokenException as ex:
            raise ex

    @staticmethod
    def _verify_time_claims(token: Token):
        now_ts = ts_now()

        if now_ts < token.iat:
            raise tex.InvalidClaims("iat claim cannot be in the future")

        if now_ts > token.exp:
            raise tex.InvalidClaims("Token has expired")

        if token.nbf is not None and now_ts < token.nbf:
            raise tex.InvalidClaims("Token isn't valid yet: nbf hasn't been reached")

    @staticmethod
    def at_hash(access_token, jws: JWS) -> str:
        hash_digest = jws.do_hash(access_token)
        cut_at = int(len(hash_digest) / 2)
        truncated = hash_digest[:cut_at]
        at_hash = conv.bytes_to_b64(truncated)
        return at_hash
