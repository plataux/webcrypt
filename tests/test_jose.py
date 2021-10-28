

import pytest

from webcrypt.jwe import JWE
from webcrypt.jws import JWS
from webcrypt.jose import JOSE, Token

from typing import Tuple, List

from secrets import token_urlsafe

from random import choice

import json

import os

jwe_excludes = [
    JWE.Algorithm.ECDH_ES,
    JWE.Algorithm.ECDH_ES_A256KW,
    JWE.Algorithm.ECDH_ES_A192KW,
    JWE.Algorithm.ECDH_ES_A128KW
]

sig_alg = list(JWS.Algorithm)
enc_alg = [alg for alg in list(JWE.Algorithm) if alg not in jwe_excludes]


@pytest.fixture(scope="session")
def keyset() -> Tuple[List[JWS], List[JWE]]:
    sig_ks = [JWS(algorithm=algo) for algo in sig_alg]
    enc_ks = [JWE(algorithm=algo) for algo in enc_alg]
    return sig_ks, enc_ks


def test_jwt_export_import(keyset):
    sig_ks, enc_ks = keyset
    jwks = JOSE(sig_ks, enc_ks)

    # export and import of jwks objects, and construction of JWT objects
    jwks2 = JOSE.from_jwks(jwks.to_jwks())
    assert jwks2.to_jwks() == jwks.to_jwks()

    # export and import JWS and JWE objects, and construction of JWT objects
    jwks2 = JOSE(jws=jwks.get_sig_jwks, jwe=jwks.get_enc_jwks)
    assert jwks2.to_jwks() == jwks.to_jwks()

    # the public JWKS from a private JWKS should match with a reconstructed public JWKS
    pub_jwks = JOSE.from_jwks(jwks.public_jwks())
    assert json.dumps(pub_jwks.public_jwks()) == json.dumps(jwks.public_jwks())


def test_jwt_sign_verify(keyset):
    sig_ks, enc_ks = keyset
    jwks = JOSE(sig_ks, enc_ks)

    # sign and verify raw data
    for alg in sig_alg:
        raw_data = token_urlsafe(32).encode()
        token = jwks.raw_sign(raw_data, alg=alg)
        assert raw_data == jwks.raw_verify(token)

    # Sign and verify Token Models, with and without access tokens
    for alg in sig_alg:
        tk = Token(
            sub='Some Random Sub',
            exp=Token.ts_offset(seconds=20)
        )
        access_token = token_urlsafe(16)

        token1 = jwks.sign(tk.copy(), access_token=access_token, alg=alg)
        token2 = jwks.sign(tk.copy(), access_token=None, alg=alg)

        assert jwks.verify(token1, access_token=access_token)
        assert jwks.verify(token2)

    # sign with private jwks and verify with public jwks
    pub_jwks = JOSE.from_jwks(jwks.public_jwks())
    for alg in [alg for alg in sig_alg if alg.name not in ('HS256', 'HS384', 'HS512')]:
        tk = Token(
            sub='Some Random Sub',
            exp=Token.ts_offset(seconds=20)
        )
        access_token = token_urlsafe(16)

        token1 = jwks.sign(tk.copy(), access_token=access_token, alg=alg)
        token2 = jwks.sign(tk.copy(), access_token=None, alg=alg)

        assert pub_jwks.verify(token1, access_token=access_token)
        assert pub_jwks.verify(token2)


def test_jwt_encrypt_decrypt(keyset):
    sig_ks, enc_ks = keyset
    jwks = JOSE(sig_ks, enc_ks)

    # encrypt and decrypt raw data
    for alg in enc_alg:
        raw_data = token_urlsafe(32).encode()
        token = jwks.raw_encrypt(raw_data, compress=choice([True, False]), alg=alg)
        assert raw_data == jwks.raw_decrypt(token)

    # encrypt and decrypt tokens
    for alg in enc_alg:
        tk = Token(
            sub='Some Random Sub',
            exp=Token.ts_offset(seconds=20)
        )

        token = jwks.encrypt(tk, compress=choice([True, False]), alg=alg)

        assert jwks.decrypt(token)

    # sign with private jwks and verify with public jwks (RSA keys in this case)
    pub_jwks = JOSE.from_jwks(jwks.public_jwks())
    for enc_jwk in pub_jwks.get_enc_jwks:
        assert enc_jwk.kty == 'RSA'

        tk = Token(
            sub='Some Random Sub',
            exp=Token.ts_offset(seconds=20)
        )
        token = pub_jwks.encrypt(tk, compress=choice([True, False]), kid=enc_jwk.kid)
        assert jwks.decrypt(token)


def test_jwks_encryption():
    key = os.urandom(16)

    jwks = JOSE()

    jwks2 = JOSE.from_jwks(jwks.to_jwks(key), key)

    assert jwks.to_jwks() == jwks2.to_jwks()
