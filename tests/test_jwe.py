import random

import pytest

from webcrypt.jwe import JWE
import webcrypt as wk
import json

from typing import Dict

import webcrypt.convert as conv
import os


@pytest.fixture(scope="session")
def rsa_keys() -> Dict[int, wk.RSA]:
    rsa_keys = {}
    for keysize in [2048, 3072, 4096]:
        rsa_keys[keysize] = wk.RSA(keysize)
    return rsa_keys


@pytest.mark.parametrize(
    "algo",
    list(JWE.Algorithm)
)
def test_jwe_conversions(algo: JWE.Algorithm):
    ek1 = JWE(algorithm=algo)

    # to and from jwk
    ek2 = JWE.from_jwk(ek1.to_jwk())
    assert json.dumps(ek1.to_jwk()) == json.dumps(ek2.to_jwk())

    if algo.value != 'dir':
        # to and from pem
        ek2 = JWE.from_pem(ek1.to_pem(), algorithm=algo, kid=ek1.kid)
        assert ek1.to_pem() == ek2.to_pem() and ek1.to_jwk() == ek2.to_jwk()

        #
        # to and from key objects
        ek2 = JWE(algo, key=ek1.privkey)
        assert ek1.to_pem() == ek2.to_pem()


def test_jwe_defaults():
    # test JWE defaults
    ek = JWE()
    assert ek.kty == 'oct'

    # test default Encryption algorithm, A128GCM by default
    ek = JWE(JWE.Algorithm.DIR)
    assert ek.alg_name == 'dir'
    assert ek.kty == 'oct'


@pytest.mark.parametrize(
    "enc",
    [*list(JWE.Encryption), None]
)
@pytest.mark.parametrize(
    "none_key",
    (True, False)
)
def test_dir_ops(enc, none_key):
    # test randomly generated keys with given encryption algos

    if none_key:
        ek = JWE(JWE.Algorithm.DIR)
    else:
        k = os.urandom(JWE._alg_size[enc.value]) if enc else None
        ek = JWE(JWE.Algorithm.DIR, key=k)

    assert ek.alg_name == 'dir'

    if not enc or JWE._alg_size[enc.value] == len(ek.key):
        data = b'some data to be encrypted and decrypted'
        data_enc = ek.encrypt(data, enc, compress=False)
        data_enc_comp = ek.encrypt(data, enc, compress=True)

        assert data_enc != data_enc_comp
        assert data == ek.decrypt(data_enc)
        assert data == ek.decrypt(data_enc_comp)
    else:
        with pytest.raises(ValueError):
            ek.encrypt(b'some data to be encrypted and decrypted', enc)


@pytest.mark.parametrize(
    "alg",
    [JWE.Algorithm.PBES2_HS384_A192KW,
     JWE.Algorithm.PBES2_HS256_A128KW, JWE.Algorithm.PBES2_HS512_A256KW],
)
@pytest.mark.parametrize(
    "enc",
    [*list(JWE.Encryption), None]
)
def test_pbe(alg, enc):
    passphrase = conv.bytes_to_b64(os.urandom(random.randint(30, 100)))

    jwe = JWE(algorithm=alg, key=passphrase)

    jwe2 = JWE.from_jwk(jwe.to_jwk())

    assert json.dumps(jwe.to_jwk()) == json.dumps(jwe2.to_jwk())

    data = conv.bytes_to_b64(os.urandom(random.randint(100, 500))).encode()

    token = jwe.encrypt(data, enc)

    head = JWE.decode_header(token)

    assert head['enc']
    assert head['alg'] == alg.value

    if 'CBC' in head['enc']:
        assert 'p2s' in head
        assert 'p2c' in head

    assert data == jwe2.decrypt(token)


@pytest.mark.parametrize(
    "alg",
    [a for a in list(JWE.Algorithm) if 'RSA' not in a.value and 'dir' not in a.value]
)
@pytest.mark.parametrize(
    "enc",
    [*list(JWE.Encryption), None]
)
def test_key_wrappers(alg, enc):
    key = os.urandom(JWE._alg_size[alg.value])

    jwe = JWE(algorithm=alg, key=key)

    jwk = jwe.to_jwk()

    assert key == conv.bytes_from_b64(jwk['k'])
    assert alg.value == jwk['alg']

    data = conv.bytes_to_b64(os.urandom(random.randint(100, 500))).encode()

    token = jwe.encrypt(data, enc=enc)

    head = JWE.decode_header(token)

    assert head['alg'] == alg.value
    assert head['enc']

    assert data == jwe.decrypt(token)


@pytest.mark.parametrize(
    "alg",
    [a for a in list(JWE.Algorithm) if 'RSA' in a.value]
)
@pytest.mark.parametrize(
    "enc",
    [*list(JWE.Encryption), None]
)
def test_rsa_keys(alg, enc):
    k1_priv = JWE(algorithm=alg)
    k2_priv = JWE(alg, key=k1_priv.privkey, kid=k1_priv.kid)
    k1_pub = JWE(alg, key=k1_priv.pubkey, kid=k1_priv.kid)
    k2_pub = JWE.from_jwk(k1_priv.public_jwk())

    assert k1_priv.to_pem() == k2_priv.to_pem() and k1_priv.to_jwk() == k2_priv.to_jwk()

    assert k1_priv.to_pem() != k1_pub.to_pem() and k1_priv.to_jwk() != k1_pub.to_jwk()

    assert k1_pub.to_pem() == k2_pub.to_pem() and k1_pub.to_jwk() == k2_pub.to_jwk()

    assert alg.value == k1_priv.alg_name

    data = conv.bytes_to_b64(os.urandom(random.randint(100, 500))).encode()

    token_1 = k1_priv.encrypt(data, enc=enc)
    token_2 = k1_pub.encrypt(data, enc=enc)
    token_3 = k2_pub.encrypt(data, enc=enc)

    head = JWE.decode_header(token_1)

    assert head['alg'] == alg.value
    assert head['enc']

    assert data == k1_priv.decrypt(token_1) == k2_priv.decrypt(token_1)
    assert data == k1_priv.decrypt(token_2) == k2_priv.decrypt(token_2)
    assert data == k1_priv.decrypt(token_3) == k2_priv.decrypt(token_3)
