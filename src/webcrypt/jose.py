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
from typing import Optional, Dict, List, Any, TypeVar, Type, Union, DefaultDict

import pydantic

if int(pydantic.version.VERSION.split('.')[0]) == 2:
    import pydantic.v1 as pydantic
else:
    pass

from cryptography.hazmat.primitives.constant_time import bytes_eq

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

T = TypeVar('T', bound='Token')


class Token(pydantic.BaseModel):
    @staticmethod
    def ts_offset(days=0, hours=0, minutes=0, seconds=0) -> int:
        """
        Calculate a timestamp offset from current UTC time

        :param days: number of days offset
        :param hours: number of hours offset
        :param minutes: number of minutes offset
        :param seconds: number of seconds offset
        :return: ``int`` timestamp
        """
        return int((datetime.now(timezone.utc) + timedelta(days=days,
                                                           hours=hours,
                                                           minutes=minutes,
                                                           seconds=seconds)).timestamp())

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
    iat: int = pydantic.Field(default_factory=lambda: Token.ts_offset())

    # Expires UTC timestamp - 60 minutes by default
    exp: int = pydantic.Field(default_factory=lambda: Token.ts_offset(minutes=60))

    ###############################
    # Generic Fields
    # JWT ID: Unique token Identifier
    jti: str = pydantic.Field(default_factory=lambda: str(uuid4()))

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


class JOSE:
    """
    Encoder and decoder of JWT Tokens.

    The encoding involves:

    * Encoding the payload into a base64 string
    * Generating a header based on the JWK alg and key-type
    * Encoding the JWT header
    * Signing the Token

    """
    __slots__ = ('_options',
                 '_sig_ks', '_sig_idx_kid', '_sig_idx_kid_priv', '_sig_idx_alg_priv',
                 '_enc_ks', '_enc_idx_kid', '_enc_idx_alg')

    def __init__(self,
                 jws: Optional[JWS | List[JWS]] = None,
                 jwe: Optional[JWE | List[JWE]] = None):

        self._sig_ks: List[JWS]
        self._enc_ks: List[JWE]

        if jws is None:
            self._sig_ks = [JWS(JWS.Algorithm.RS256)]
        elif isinstance(jws, JWS):
            self._sig_ks = [jws]
        elif isinstance(jws, list) and all(isinstance(key, JWS) for key in jws):
            self._sig_ks = list(jws)
        else:
            raise ValueError("Unexpected/Invalid JWS Value")

        self._sig_idx_kid: Dict[str, JWS] = {x.kid: x for x in self._sig_ks}
        self._sig_idx_kid_priv: Dict[str, JWS] = {}
        self._sig_idx_alg_priv: DefaultDict[str, List[JWS]] = defaultdict(list)

        for jwk in self._sig_ks:
            if jwk.can_sign:
                self._sig_idx_kid_priv[jwk.kid] = jwk
                self._sig_idx_alg_priv[jwk.jws_alg.name].append(jwk)

        if jwe is None:
            self._enc_ks = [JWE(JWE.Algorithm.A256KW)]
        elif isinstance(jwe, JWE):
            self._enc_ks = [jwe]
        elif isinstance(jwe, list) and all(isinstance(key, JWE) for key in jwe):
            self._enc_ks = list(jwe)
        else:
            raise ValueError("Unexpected/Invalid JWE Value")

        self._enc_idx_kid: Dict[str, JWE] = {x.kid: x for x in self._enc_ks}
        self._enc_idx_alg: DefaultDict[str, List[JWE]] = defaultdict(list)

        for jwk2 in self._enc_ks:
            self._enc_idx_alg[jwk2.alg_name].append(jwk2)

    @classmethod
    def from_jwks(cls, jwks: str | Dict[str, Any],
                  encryption_key: Optional[bytes] = None) -> "JOSE":
        if isinstance(jwks, str):
            if encryption_key is None:
                try:
                    jwks_dict: Dict[str, Any] = json.loads(jwks)
                except Exception as ex:
                    raise ValueError(
                        f"Invalid JWKS string: either corrupted, or encrypted: {ex}")
            else:
                aes_gcm = AESGCM(encryption_key)
                try:
                    jwks_enc = conv.bytes_from_b64(jwks)
                    jwks_json: bytes = aes_gcm.decrypt(jwks_enc[:12], jwks_enc[12:], b'')
                    jwks_dict = json.loads(jwks_json)
                except Exception:
                    raise ValueError(
                        "Could Not Decrypt/Parse JWKS, AES key maybe incorrect")

        elif isinstance(jwks, dict):
            jwks_dict = jwks

        else:
            raise ValueError("Invalid JWKS data type: Either dict or JSON string accepted")

        jws, jwe = [], []

        for item in jwks_dict['keys']:
            try:
                if (_use := item['use']) == 'sig':
                    jws.append(JWS.from_jwk(item))
                elif _use == 'enc':
                    jwe.append(JWE.from_jwk(item))
            except Exception as ex:
                import logging
                logging.warning(f"Invalid JWK in JWKS: {ex}, will proceed without it")
                continue

        return cls(jws, jwe)

    def to_jwks(self, encryption_key: Optional[bytes] = None) -> str:
        ks: List[Dict[str, Any]] = []
        jwks = {'keys': ks}

        for item in self._sig_ks:
            ks.append(item.to_jwk())

        for item2 in self._enc_ks:
            ks.append(item2.to_jwk())

        jwks_json = json.dumps(jwks, indent=2)

        if encryption_key is None:
            return jwks_json
        else:
            iv = os.urandom(12)
            aes_gcm = AESGCM(encryption_key)
            ciphertext = aes_gcm.encrypt(iv, jwks_json.encode(), b'')
            jwks_enc = iv + ciphertext
            return conv.bytes_to_b64(jwks_enc)

    def public_jwks(self) -> Dict[str, Any]:

        ks: List[Dict[str, Any]] = []
        jwks = {'keys': ks}

        for jwk in self._sig_ks:
            if jwk.kty != 'oct':
                ks.append(jwk.public_jwk())

        return jwks

    def index_jwks(self) -> Dict[str, Dict[str, str]]:
        cat: Dict[str, Any] = {}

        for k1 in self._sig_ks:
            cat[k1.kid] = {
                'use': 'sig',
                'kty': k1.kty,
                'alg': k1.alg_name,
                'can_sign': k1.can_sign
            }

        for k2 in self._enc_ks:
            cat[k2.kid] = {
                'use': 'enc',
                'kty': k2.kty,
                'alg': k2.alg_name,
                'can_decrypt': k2.can_decrypt
            }

        return cat

    @property
    def get_sig_jwks(self) -> List[JWS]:
        return list(self._sig_ks)

    @property
    def get_enc_jwks(self) -> List[JWE]:
        return list(self._enc_ks)

    def raw_sign(self, data: bytes,
                 extra_header: Optional[Dict[str, Any]] = None,
                 kid: Optional[str] = None,
                 alg: Optional[str | JWS.Algorithm] = None) -> str:
        """
        Sign raw byte data, and return an encoded JWT as a unicode ``str``

        :param data: raw byte string
        :param extra_header: dict of additional headers to include in the JWT
        :param kid: Optional kid parameter to sign with a specific key in the JWKS, if it exists
        :param alg: Optional alg parameter to sign with a specific alg in the JWKS, if it exists

        :return: JWT encoded in Base64 unicode string
        """

        if len(self._sig_idx_kid_priv) == 0:
            raise RuntimeError("This JOSE Object isn't capable of signing - No Private keys")

        if kid is not None:
            if kid in self._sig_idx_kid_priv:
                jwk: JWS = self._sig_idx_kid_priv[kid]
            else:
                raise ValueError("No privkey with this signing kid exist in this JWKS")

        elif alg is not None:
            if isinstance(alg, JWS.Algorithm):
                alg = alg.value

            if alg in self._sig_idx_alg_priv:
                jwk = choice(self._sig_idx_alg_priv[alg])
            else:
                raise ValueError("No privkey with this signing alg exist in this JWKS")

        else:
            jwk = choice(list(self._sig_idx_kid_priv.values()))

        return jwk.sign(payload=data,
                        extra_header=extra_header)

    def raw_verify(self, token: str) -> bytes:
        """
        Verify the signature, Decode the payload, and validate and deserialize it with the given,
        or the default ``Token`` Pydantic Model

        :param token: Encoded Token str in the format ``b64head.b64payload.b64sig``

        :return: Valid and Decoded Token of Type ``T`` which is a type of class ``Token``

        :raises InvalidToken: if the JWT header is not a valid JSON serializable object, or the
            ``kid`` could not be found, or couldn't be extracted from the JWT Header

        :raises TokenException: if no JWK with a matching kid could be found to verify the token

        :raises InvalidToken: if the encoded Token is not a Valid JWT
            of type ``str`` and structure ``b64head.b64payload.b64sig``

        :raises AlgoMismatch: If the signature algo in the header doesn't match that of the JWK

        :raises InvalidSignature: If the signature is an invalid Base64 encoded string

        :raises InvalidSignature: If the signature of the JWT header+claims is invalid
        """
        try:
            kid = JWS.decode_header(token)['kid']
        except Exception as ex:
            raise tex.InvalidToken(f"Could not find/extract kid from JWT header: {ex}")

        if kid not in self._sig_idx_kid:
            raise tex.TokenException(f"Could not find the JWK kid matching this token: {kid}")

        jwk: JWS = self._sig_idx_kid[kid]

        payload_raw = jwk.verify(token)

        return payload_raw

    def raw_encrypt(self, data, enc: JWE.Encryption | None = None,
                    compress=True,
                    extra_header: Optional[Dict[str, Any]] = None,
                    kid: Optional[str] = None,
                    alg: Optional[str | JWE.Algorithm] = None) -> str:
        """
        Encrypt raw data, and optionally compress, returning an encoded JWT unicode string

        :param enc:
        :param data: input data in byte string
        :param compress: Option to compress. True by default
        :param extra_header: dict of extra JWT headers
        :param kid: Optional kid of the encryption key to use, if present
        :param alg: Optional alg og the encryption key to use, if present
        :return:
        """

        if len(self._enc_ks) == 0:
            raise RuntimeError("This JOSE object has no JWE keys")

        if kid is not None:
            if kid in self._enc_idx_kid:
                jwk: JWE = self._enc_idx_kid[kid]
            else:
                raise ValueError("No key with this encrypting kid exist in this JWKS")

        elif alg is not None:
            if isinstance(alg, JWE.Algorithm):
                alg = alg.value
            if alg in self._enc_idx_alg:
                jwk = choice(self._enc_idx_alg[alg])
            else:
                raise ValueError("No key with this encrypting alg exist in this JWKS")

        else:
            jwk = choice(self._enc_ks)

        return jwk.encrypt(data,
                           enc,
                           compress=compress, extra_header=extra_header)

    def raw_decrypt(self, token: str) -> bytes:
        """
        :param token:
        :return: decrypted data byte string

        :raises InvalidToken: if the JWT header is not a valid JSON serializable object, or the
            ``kid`` could not be found, or couldn't be extracted from the JWT Header

        :raises TokenException: if no JWK with a matching kid could be found to verify the token

        :raises InvalidToken: if the encoded Token is not a Valid JWE

        :raises AlgoMismatch: If the encryption algo in the header doesn't match that of the JWK
        """
        try:
            kid = JWS.decode_header(token)['kid']
        except Exception as ex:
            raise tex.InvalidToken(f"Could not find/extract kid from JWT header: {ex}")

        if kid not in self._enc_idx_kid:
            raise tex.TokenException(f"Could not find the JWK kid matching this token: {kid}")

        if kid not in self._enc_idx_kid:
            raise RuntimeError(f"no JWE decryption key with this kid was found: {kid}")

        jwk: JWE = self._enc_idx_kid[kid]

        if not jwk.can_decrypt:
            raise ValueError("This JWK is not capable of decrypting: No privkey")

        payload_raw = jwk.decrypt(token)

        return payload_raw

    def sign(self, token: Token,
             access_token: Optional[str] = None,
             extra_header: Optional[Dict[str, Any]] = None,
             kid: Optional[str] = None,
             alg: Optional[str | JWS.Algorithm] = None) -> str:
        """
        Encode and sign a Token object, optionally including the at_hash claim if the access_token
        is provided.

        :param token: a Pydantic Token Model of all standard JWT claims, as well as custom ones
        :param access_token: Optional access token to calculate and include the at_hash JWT claim
        :param extra_header: Optional dict of extra JWT headers
        :param kid: Optional kid of the signing key to use, if present.
        :param alg: Optional algo if the signing kid to use, if present

        :return: encoded JWT in Base64 unicode string
        """

        if len(self._sig_idx_kid_priv) == 0:
            raise RuntimeError("This JOSE Object isn't capable of signing - No Private keys")

        if kid is not None:
            if kid in self._sig_idx_kid_priv:
                jwk: JWS = self._sig_idx_kid_priv[kid]
            else:
                raise ValueError("No privkey with this signing kid exist in this JWKS")

        elif alg is not None:
            if isinstance(alg, JWS.Algorithm):
                alg = alg.value

            if alg in self._sig_idx_alg_priv:
                jwk = choice(self._sig_idx_alg_priv[alg])
            else:
                raise ValueError("No privkey with this signing alg exist in this JWKS")

        else:
            jwk = choice(list(self._sig_idx_kid_priv.values()))

        if access_token is not None:
            token.at_hash = self.at_hash(access_token, jwk)

        return jwk.sign(payload=conv.doc_to_bytes(token.dict(exclude_none=True)),
                        extra_header=extra_header)

    def verify(self, token: str, TokenClass: Type[T] | Type[Token] = Token,
               access_token: Optional[str] = None, verify_access_token: bool = True) -> T | Token:
        """
        Verify the signature, Decode the payload, and validate and deserialize it with the given,
        or the default ``Token`` Pydantic Model

        :param verify_access_token: if True, will verify the at_hash claim against the access_token
        :param token: Encoded Token str in the format ``b64head.b64payload.b64sig``
        :param TokenClass: Pydantic Model to Deserialize and Validate the token Payload
        :param access_token: must be provided to calculate and validate at_hash claim, if present

        :return: Valid and Decoded Token of Type ``T`` which is a type of class ``Token``

        :raises InvalidToken: if the JWT header is not a valid JSON serializable object, or the
            ``kid`` could not be found, or couldn't be extracted from the JWT Header

        :raises TokenException: if no JWK with a matching kid could be found to verify the token

        :raises InvalidToken: if the encoded Token is not a Valid JWT
            of type ``str`` and structure ``b64head.b64payload.b64sig``

        :raises AlgoMismatch: If the signature algo in the header doesn't match that of the JWK

        :raises InvalidSignature: If the signature is an invalid Base64 encoded string

        :raises InvalidSignature: If the signature of the JWT header+claims is invalid

        :raises InvalidClaims: if calculated at_hash doesn't fit with the access token, or if
            either of the at_hash or access_token is absent

        :raises ExpiredSignature: if token has expired

        :raises NotYetValid: if token is not valid yet with respect to the specific nbf timestamp
        """

        if not issubclass(TokenClass, Token):
            raise ValueError("TokenClass must be a Pydantic Model")

        try:
            kid = JWS.decode_header(token)['kid']
        except Exception as ex:
            raise tex.InvalidToken(f"Could not find/extract kid from JWT header: {ex}")

        if kid not in self._sig_idx_kid:
            raise tex.TokenException(f"Could not find the JWK kid matching this token: {kid}")

        jwk: JWS = self._sig_idx_kid[kid]

        payload_raw = jwk.verify(token)

        # Structural Token validation
        try:
            # validate signature and decode token
            payload: Dict[str, Any] = conv.doc_from_bytes(payload_raw)
            p_token = TokenClass(**payload)
        except Exception as ex:
            raise tex.InvalidClaims(f"invalid or missing claims from the defined schema: {ex}")

        if verify_access_token:
            JOSE._verify_at_hash(p_token, access_token, jwk)

        JOSE._verify_time_claims(p_token)

        return p_token

    def encrypt(self, token: Token, enc: JWE.Encryption | None = None, compress=True,
                extra_header: Optional[Dict[str, Any]] = None,
                kid: Optional[str] = None,
                alg: Optional[str | JWE.Algorithm] = None) -> str:

        if len(self._enc_ks) == 0:
            raise RuntimeError("This JOSE object has no JWE keys")

        if kid is not None:
            if kid in self._enc_idx_kid:
                jwk: JWE = self._enc_idx_kid[kid]
            else:
                raise ValueError("No key with this encrypting kid exist in this JWKS")

        elif alg is not None:
            if isinstance(alg, JWE.Algorithm):
                alg = alg.value
            if alg in self._enc_idx_alg:
                jwk = choice(self._enc_idx_alg[alg])
            else:
                raise ValueError("No key with this encrypting alg exist in this JWKS")

        else:
            jwk = choice(self._enc_ks)

        return jwk.encrypt(token.json(exclude_none=True).encode(),
                           enc=enc,
                           compress=compress, extra_header=extra_header)

    def decrypt(self, token: str,
                TokenClass: Union[Type[T], Type[Token]] = Token) -> Union[T, Token]:
        """

        :param token:
        :param TokenClass:
        :return: Valid and Decoded Token of Type ``T`` which is a type of class ``Token``

        :raises InvalidToken: if the JWT header is not a valid JSON serializable object, or the
            ``kid`` could not be found, or couldn't be extracted from the JWT Header

        :raises TokenException: if no JWK with a matching kid could be found to verify the token

        :raises InvalidToken: if the encoded Token is not a Valid JWT
            of type ``str`` and structure ``b64head.b64payload.b64sig``

        :raises AlgoMismatch: If the signature algo in the header doesn't match that of the JWK

        :raises InvalidToken: If the token could not be decrypted due to
            being corrupted or tampered with

        :raises ExpiredSignature: if token has expired

        :raises NotYetValid: if token is not valid yet with respect to the specific nbf timestamp
        """

        try:
            kid = JWS.decode_header(token)['kid']
        except Exception as ex:
            raise tex.InvalidToken(f"Could not find/extract kid from JWT header: {ex}")

        if kid not in self._enc_idx_kid:
            raise tex.TokenException(f"Could not find the JWK kid matching this token: {kid}")

        jwk: JWE = self._enc_idx_kid[kid]

        if not jwk.can_decrypt:
            raise ValueError("This JWK is not capable of decrypting: No privkey")

        payload_raw = jwk.decrypt(token)

        # Structural Token validation
        try:
            # validate signature and decode token
            payload: Dict[str, Any] = conv.doc_from_bytes(payload_raw)
            p_token = TokenClass(**payload)
        except Exception as ex:
            raise tex.InvalidClaims(f"invalid or missing claims from the defined schema: {ex}")

        JOSE._verify_time_claims(p_token)

        return p_token

    @staticmethod
    def _verify_at_hash(token: Token, access_token: Union[str, None], jwk: JWS):
        try:
            if token.at_hash is not None:
                if access_token is None:
                    raise tex.InvalidClaims("at_hash is present but access_token "
                                            "was not provided")
                else:
                    _at_hash = JOSE.at_hash(access_token, jwk)
                    if not bytes_eq(token.at_hash.encode(), _at_hash.encode()):
                        raise tex.InvalidClaims("Invalid at_hash against given access_token")
            if token.at_hash is None and access_token is not None:
                raise tex.InvalidClaims("at_hash was missing from the token")
        except tex.TokenException as ex:
            raise ex

    @staticmethod
    def _verify_time_claims(token: Token):
        now_ts = Token.ts_offset()

        if now_ts < token.iat:
            raise tex.InvalidClaims("iat claim cannot be in the future")

        if now_ts > token.exp:
            raise tex.ExpiredSignature("Token has expired")

        if token.nbf is not None and now_ts < token.nbf:
            raise tex.NotYetValid("Token isn't valid yet: nbf hasn't been reached")

    @staticmethod
    def at_hash(access_token, jws: JWS) -> str:
        hash_digest = jws.do_hash(access_token)
        cut_at = int(len(hash_digest) / 2)
        truncated = hash_digest[:cut_at]
        at_hash = conv.bytes_to_b64(truncated)
        return at_hash
