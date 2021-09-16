

import pytest

from webcrypt.jws import JWS
import json

from typing import Dict


# @pytest.fixture(scope="session")
# def rsa_keys() -> Dict[int, wk.RSA]:
#     rsa_keys = {}
#     for keysize in [2048, 3072, 4096]:
#         rsa_keys[keysize] = wk.RSA(keysize)
#     return rsa_keys

@pytest.mark.parametrize(
    "algo",
    list(JWS.Algorithm)
)
def test_all_algo_ops(algo: JWS.Algorithm):
    sk1 = JWS(algorithm=algo)

    # privkey to and from jwk
    sk2 = JWS.from_jwk(sk1.to_jwk())
    assert sk1 == sk2
    assert json.dumps(sk1.to_jwk()) == json.dumps(sk2.to_jwk())

    # privkey to and from pem
    sk2 = JWS.from_pem(sk1.to_pem(), algorithm=algo)
    assert sk1 == sk2

    # privkey to and from key object
    sk2 = JWS(algo, key_obj=sk1.key)
    assert sk2 == sk1

    # public jwk as the main key
    if algo.name not in ('HS256', 'HS384', 'HS512'):
        pub1 = JWS.from_jwk(sk1.public_jwk())

        pub2 = JWS.from_jwk(pub1.to_jwk())
        assert pub1 == pub2
        assert json.dumps(pub1.to_jwk()) == json.dumps(pub2.to_jwk())
        assert json.dumps(pub1.public_jwk()) == json.dumps(pub2.public_jwk())

        pub2 = JWS.from_jwk(pub1.public_jwk())
        assert pub1 == pub2
        assert json.dumps(pub1.to_jwk()) == json.dumps(pub2.to_jwk())
        assert json.dumps(pub1.public_jwk()) == json.dumps(pub2.public_jwk())

        pub2 = JWS.from_pem(pub1.to_pem(), pub1.jws_alg)
        assert pub1 == pub2

    # to and from key objects
    sk2 = JWS(algo, sk1.privkey)
    assert sk1.to_pem() == sk2.to_pem()

    data = b'Some Random data to be signed and verified'

    # sign and verify

    token = sk1.sign(data)
    sk1.verify(token)

    # sign, and a separate public key object to verify

    if algo.name not in ('HS256', 'HS384', 'HS512'):
        sk2 = JWS(algorithm=algo, key_obj=sk1.pubkey)
    else:
        sk2 = JWS(algorithm=algo, key_obj=sk1.privkey)
    token = sk1.sign(data)
    sk2.verify(token)


def test_random_alg():
    for _ in range(32):
        sk1 = JWS.random_jws()
        data = b'Some Random data to be signed and verified'

        # sign and verify

        token = sk1.sign(data)
        sk1.verify(token)
