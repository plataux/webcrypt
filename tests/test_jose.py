

import pytest

from webcrypt.jose import JOSE, Token
from webcrypt.jws import JWS
from webcrypt.jwe import JWE
import webcrypt.exceptions as tex
import time

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


def test_jwt_priv_sign_pub_verify(keyset):
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


def test_sign_verify_scenarios():
    jwks = """{
      "keys": [
        {
          "use": "sig",
          "kid": "522cb858-7675-4c60-bcf4-35265187f7fd",
          "kty": "EC",
          "alg": "ES384",
          "key_ops": [
            "sign",
            "verify"
          ],
          "crv": "P-384",
          "x": "UzncNix6j_zYx0WH8eMXXmzBNnInW6wNydXcvus3K2zGhVuEWqW49MJV3GKPTC6b",
          "y": "wndqTfB9rXthfw7dAAcNAUwS3DCBOGFlBWk-v45FoA2VkP0lywofvhQvM_8hTuwD",
          "d": "7DTYK-xWeeHr0FIDzGdxoHO-km_KzDuNbKP0QnsoZYyBkghmhGv8Po5iHSCGc9mW"
        },
        {
          "use": "sig",
          "kid": "c43bec88-c777-4330-9268-e5f4f076db2c",
          "kty": "EC",
          "alg": "ES384",
          "key_ops": [
            "sign",
            "verify"
          ],
          "crv": "P-384",
          "x": "vzWMSJKwwQII8USIhEaIJmK2Sc_BvBcBQB6p9IGY7W2SGmTaShCAlQZd3YoY9o55",
          "y": "9JLmmPoDrpYwyNRHG6jLg_eCjZoX6zYkw6vnp0iSe4yAFJrjiKsqUZF6vHtRSto2",
          "d": "Ww4uKCa9b7m-w_adqD1SxoNiJDVree03huIBpQ1Sw3qD6KrmJZjA1o1po5ZUFZC3"
        },
        {
          "use": "sig",
          "kid": "62d69497-e2c2-4785-bf34-df8f77036c68",
          "kty": "RSA",
          "alg": "PS256",
          "key_ops": [
            "sign",
            "verify"
          ],
          "e": "AQAB",
          "n": "xzNY0UlMskxBufGID2g-ePvEa0bARjIpCoBVGuEadcuQcoa2QKyLtlYOVudyUhQUBBwOEeD7VQFp2XxbwGSZ__bUI0PCcUutOe9JUhN9SCgdogVUiiNWT-OVoSgJmExm6-Wc9O9gOBAvxjzHOltSBGtWM5oygnrPvCpvFHsABrSv4y2lYOBYN80xOZoUuJ6poSltdXchZWfDEBJB8YB69ZCSQEtuSmxDITtodVzFYi5KyTlzU_6kRCpTGWDn_iAGugyuWeIbiQsyrdyKqpEosMDpKcg4HrhGDgtcIrSWOSP4hrG7ZmR_anb7flMXQKLcGRWUZff9UJPFPWyc6kTwYQ",
          "d": "bu4ZN_Mp0uDEeVgX_PyATb9m0pbD3FNyp3Zv7lgM9Cw4dI6wT7PG2fNyaNLaxvqHawJ0k2BGlkADQioOrkVXvUMnP7wsPAt4nBq1Kg_QZK5yUhfFzGeBWVvTp7s0HKvvZM6paX0kiBP7htmx2L2iHvPnPTVRi3f410CKO02D5jcb-ChcFsGeExojgIsFmvcWz-3W9dcjok7iXRAkzFG1gibWSz0mRlhHA7wv1_yGaMkkVBL8vyZbZMRIStk6S5ZAbl9bHhRMch9aanK3L2jfxMsNcEO_f1Y8om2hZHQHfpP3baeWXZ9Z821tj-E9zBJrt1F3Y1XWryVZ6AZj9c5LAQ",
          "p": "--E5BFXO2i_0GFBoDSUWWDpMQsratyf88NkFadpScS1P0Xmu3qeCvKVQasAUfJqqg4oQC5Vs1-R3o6g6vAn9H8wuVJqDbqeQ30BtrTJzMWGwKwYVFSXXRycL6ucnzQrWgHkyCrFDZ8GZKt5MxxGAjJ8uq6umr0TiE5owXD55pD0",
          "q": "ynWGDSDbeZ7an0oPwYB58JvqsscE1gcxGfWaBKvXRTzjF72b4Iff5FZpAHwR3P_4aDTI_h6eLpxOJYP-Sx7HzExBuJnje8pjOwEmWiS6iOOyOmmclGqkMctt2e4Se2Lb2Tvbd6hLdnnKKuDKZd0XXo8iLSfDQwMUgZ737otX6vU",
          "dp": "5Y3NuPW7H360p7QgIFq8kowPFJBr5KC9FYO0O1SN7jetluufQ6zGqcbAE4obIbST0m3xUZ1NJTVDFBQt81HnLyOW1eQ8BI0Sq2S8kCx6b3boZ02TyUJDgMVFR0CENYq7EzthL_19wQHf5gHTV1nMHly03CAEOZg9sj_D80287sE",
          "dq": "L_EaeDtinW8nd_bSulCRD4_sSL9l_sSfNPV6rkZ-6G9dmz6UDdw_AVQQ80Nt-3ZFvW9adQqNDJ6Ixst1yRYV2-Pm4C7YtnSbgNpp2Yi-_zFj__8ITADgtsXkUmnUyJEFXHCXLMOWcwyt-e9XHj33jbW5MxYqX9D35yXcsgkfHY0",
          "qi": "FBHg8R_yBqI8zKa9f_GMs6rTCovKWVeajl0iztRjTRPtFbGZ2bpIFdXBseKJa45naB9jf2FKmGLFo_5ALrYybulyslf7ImhBa-JY_121wMPpsGeNEOD3LjlIWl1sGqLX5p67fG5upU94N4ePDbXj1P0Y-kBRSat7nnMCK_uI78M"
        },
        {
          "use": "sig",
          "kid": "d43b539d-51d2-4499-b5e7-92b7d7ad20f4",
          "kty": "RSA",
          "alg": "RS512",
          "key_ops": [
            "sign",
            "verify"
          ],
          "e": "AQAB",
          "n": "zXg4bt4AonQU4APtTEJcpSM6OI-uxhW9Bt2otOQSZxROd4zMo04vEPCjvEqeeUz6PAWncltnOCKQ_r-moY23LxFegYyOnYDjo0ZkmobE2u-zwiq9l98DCIDNVG_BJnwU21NcN2vXEUgNOh4lOM7sa1j7IrViuhVkixuIUCQZy0WEXn3KG1T1Pg41Fb_-HZHuHeuabnmGKuHL9bs4hPBx1yz6x-58MiziFbf4JWnR23oSlvs_zJr8EHqu7Vf6C7j942j4kwoAeTxdtCLkWiMbpltbX8R274PcCYiI5az3WiZV9UqvxRCMYoWROaf86E8pjxofo92VetqBy-6mcUvpMQ",
          "d": "BR0L0n6F54UaC-UtH6u7IIT66vNwdw-Nb8FOdIoEhzozJbiEU0Ab3cEPYh09SmmHBL1jSG5L6FK75wsf-39KYsp83p5_4h2WDLcww8O83HIAuEFWDJSJP8ns0kAhv3JxFnBBqENvy8dORPcBGCPWMGm7fkajWVw0711VDCGJ3swlr1TqGKU595WJCxAO10uGb3QRpAD96FIieIqgiY5Gul4ozRNbgqPZuimcuTokiqdb_Xvpi8ay1LRi_BtUQhLN-ly94gS0lI0syWTX3DKXC9YpqwMck0nSR0xXSytESRhvRQ0qiJ9jIyLAhnclMoZQ2Mjsrxb8biPwK-ogCUzOAQ",
          "p": "6X8ojx2rU4EYM_tW0CL8RRyEpyZteeKDphJS5M5zaP6_Z6C7QKWZIvm0bZ0GHvIdQte2BA3PwjC6EzWyYIXyIRjAYAthndnlU0HPoQCNyqh6PfGt2rTPDPBdVcvBVvf3eeXZ7VgLAkjdfIlCSz2YwfsQ-LUKkyFkPsUbSc6Y3yE",
          "q": "4UWTedfxG-HEdrp-OiqOe32ibEkL56mEyucovwtGhnfqfNP8rQfj5Rdoo_w_AbylEYmbFc9kovklRIcY6EC0fX3K7myRiECTQoxwQrc3ktj2EXlEWZ2vYiZpu7uACc2WPPwQ7DXI1YPvZLQ3SX934Gu7sp_EzR7bw-m93b76GBE",
          "dp": "P2AgJhgrdFLJuvIxMfUM-8UtzCCF_lsY2G6IyUmv0YOzd_EMYhOQaQnVixrfmm6kuovJ_3ewOEj5eFVOwRwaCBmrvWXZbPrDX8GxFUYNNkBcTYvXYFFLEXv8GVlgdLaBGTjl2aHX-xrD4xVuRPXHDH-Ur6yT3jNl_hOJwJKus4E",
          "dq": "A-M6f1DNtWh5Bn-DbCeN2-24HtxH21CenQ3OMzXTmsB5CHx0ENxg_3Qe9y2EPNhvlNTmG0M__lwEW6FlOaTcOIoyNVkkTdCnee-IhG47BErAPF72YgGJpEz7aCT9Oa4VmKnU9O6cr6qeOAOwLJGJlRLm41dEgzG0IzZmc2w3TrE",
          "qi": "XLxZXtx7_IfL9DCW6agXc7CU5jvhMx3Rka1wfdtv-zFm6_IKLIvz_3l5WtK2BoJmC3q5UDgFfbpLQnWd6Sq3UiC2VnHuoNvVxTJHKENtJ6PuXHe3U5bVygUMoC0av22iaOpir1jLW8xnnSEnHUUEheLoT9WDVe24nZgoc3f2CDQ"
        },
        {
          "use": "sig",
          "kid": "1246fbae-3b08-4fe2-b8e1-d22d4dd97549",
          "kty": "oct",
          "alg": "HS256",
          "key_ops": [
            "sign",
            "verify"
          ],
          "k": "aD9DFoEmVcsLj3Unfp1QewV9qfLp88UPHJeSFAeMHNA"
        }
      ]
    }

    """
    # signers = [
    #     JWS(algorithm=JWS.Algorithm.ES384),
    #     JWS(algorithm=JWS.Algorithm.ES384),
    #     JWS(algorithm=JWS.Algorithm.PS256),
    #     JWS(algorithm=JWS.Algorithm.RS512),
    #     JWS(algorithm=JWS.Algorithm.HS256),
    # ]

    # jose = JOSE(jws=signers, jwe=[])

    jose = JOSE.from_jwks(jwks)

    pub_jose = JOSE.from_jwks(jose.public_jwks())

    assert len(jose.index_jwks()) == 5
    assert len(pub_jose.index_jwks()) == 4

    data = b'data to be signed and verified'

    # Test sign and verify with a specific kid
    tok = jose.raw_sign(data, kid="522cb858-7675-4c60-bcf4-35265187f7fd")
    assert data == pub_jose.raw_verify(tok)

    # Test FAIL signing with Not Found kid
    with pytest.raises(ValueError, match="No privkey with this signing kid exist in this JWKS"):
        jose.raw_sign(data, kid="522cb858-7675-4c60-bcf4-35265187f7f")

    # Test sign and verify with a specific alg
    tok = jose.raw_sign(data, alg=JWS.Algorithm.ES384)
    assert data == pub_jose.raw_verify(tok)

    # Test FAIL signing with a not found alg
    with pytest.raises(ValueError, match="No privkey with this signing alg exist in this JWKS"):
        jose.raw_sign(data, alg=JWS.Algorithm.ES512)

    # Test FAIL verifying with a not found kid
    with pytest.raises(tex.TokenException):
        tok = jose.raw_sign(data, alg=JWS.Algorithm.HS256)
        assert data == pub_jose.raw_verify(tok)

    # Test FAIL sign with no private keys
    with pytest.raises(RuntimeError,
                       match="This JOSE Object isn't capable of signing - No Private keys"):
        pub_jose.raw_sign(data)


def test_sign_verify_tokens():
    jose = JOSE()

    pub_jose = JOSE.from_jwks(jose.public_jwks())

    tk = Token(
        exp=Token.ts_offset(seconds=1)
    )

    access_token = token_urlsafe(32)

    jwt1 = jose.sign(tk.copy())
    jwt2 = jose.sign(tk.copy(), access_token=access_token)

    assert pub_jose.verify(jwt1)
    assert pub_jose.verify(jwt2, access_token=access_token)

    with pytest.raises(tex.InvalidClaims):
        assert pub_jose.verify(jwt1, access_token='invalid token')

    with pytest.raises(tex.InvalidClaims):
        assert pub_jose.verify(jwt2, access_token='invalid token')

    time.sleep(2)

    with pytest.raises(tex.ExpiredSignature):
        assert pub_jose.verify(jwt1)

    with pytest.raises(tex.ExpiredSignature):
        assert pub_jose.verify(jwt2, access_token=access_token)

    tk = Token(
        iat=Token.ts_offset(seconds=2),
        exp=Token.ts_offset(seconds=5)
    )

    jwt3 = jose.sign(tk)

    with pytest.raises(tex.InvalidClaims):
        assert pub_jose.verify(jwt3)
