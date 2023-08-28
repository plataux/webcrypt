import random

import pytest

from webcrypt.jwe import JWE
import json

# from typing import Dict

import webcrypt.convert as conv
import os


# @pytest.fixture(scope="session")
# def rsa_keys() -> Dict[int, wk.RSA]:
#     rsa_keys = {}
#     for keysize in [2048, 3072, 4096]:
#         rsa_keys[keysize] = wk.RSA(keysize)
#     return rsa_keys

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
        ek2 = JWE.from_pem(ek1.to_pem(), algorithm=algo)
        assert ek1.to_pem() == ek2.to_pem()

        #
        # to and from key objects
        ek2 = JWE(algo, key=ek1.privkey)
        assert ek1.to_pem() == ek2.to_pem()
    #
    # data = b'Some Random data to be encrypted and decrypted


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
    list(JWE.Encryption)
)
def test_dir_ops(enc):
    # test randomly generated keys with given encryption algos

    ek = JWE(JWE.Algorithm.DIR, key=os.urandom(JWE._alg_size[enc.value]))
    assert ek.alg_name == 'dir'

    # test invalid AES keys
    k = os.urandom(JWE._alg_size[enc.value]) + b'x'
    with pytest.raises(ValueError):
        JWE(JWE.Algorithm.DIR, key=k)

    k = os.urandom(JWE._alg_size[enc.value])[:-1]
    with pytest.raises(ValueError):
        JWE(JWE.Algorithm.DIR, key=k)

    #
    # test encrypt and decrypt with and without compression
    ek2 = JWE(JWE.Algorithm.DIR, key=os.urandom(JWE._alg_size[enc.value]))

    data = b'some data to be encrypted and decrypted'
    data_enc = ek2.encrypt(data, enc, compress=False)
    data_enc_comp = ek2.encrypt(data, enc, compress=True)

    assert data_enc != data_enc_comp
    assert data == ek2.decrypt(data_enc)
    assert data == ek2.decrypt(data_enc_comp)


@pytest.mark.parametrize(
    "enc",
    [JWE.Encryption.A128GCM, JWE.Encryption.A192GCM, JWE.Encryption.A256GCM]
)
def test_kw_ops(enc):
    ek = JWE()
    assert ek


def test_pbe():
    for alg in [JWE.Algorithm.PBES2_HS384_A192KW,
                JWE.Algorithm.PBES2_HS256_A128KW, JWE.Algorithm.PBES2_HS512_A256KW]:

        for enc in list(JWE.Encryption):
            passphrase = conv.bytes_to_b64(os.urandom(random.randint(30, 100)))
            passphrase = None if random.choice((True, False)) else passphrase

            jwe = JWE(algorithm=alg, key=passphrase)

            jwe2 = JWE.from_jwk(jwe.to_jwk())

            assert json.dumps(jwe.to_jwk()) == json.dumps(jwe2.to_jwk())

            data = conv.bytes_to_b64(os.urandom(random.randint(100, 500))).encode()

            token = jwe.encrypt(data, enc)

            head = JWE.decode_header(token)

            assert head['enc'] == enc.value
            assert head['alg'] == alg.value

            if 'CBC' in head['enc']:
                assert 'p2s' in head
                assert 'p2c' in head

            assert data == jwe2.decrypt(token)


@pytest.mark.parametrize(
    "alg",
    [a for a in list(JWE.Algorithm) if 'RSA' not in a.value and 'dir' not in a.value]
)
def test_key_wrappers(alg):
    for enc in list(JWE.Encryption):
        key = os.urandom(JWE._alg_size[alg.value])

        jwe = JWE(algorithm=alg, key=key)

        jwk = jwe.to_jwk()

        assert key == conv.bytes_from_b64(jwk['k'])
        assert alg.value == jwk['alg']

        data = conv.bytes_to_b64(os.urandom(random.randint(100, 500))).encode()

        token = jwe.encrypt(data, enc=enc)

        head = JWE.decode_header(token)

        assert head['alg'] == alg.value
        assert head['enc'] == enc.value

        assert data == jwe.decrypt(token)


@pytest.mark.parametrize(
    "alg",
    [a for a in list(JWE.Algorithm) if 'RSA' in a.value]
)
def test_rsa_keys(alg):
    k1 = JWE(algorithm=alg)

    k2 = JWE(alg, key=k1.privkey)

    assert k1.to_pem() == k2.to_pem()

    assert alg.value == k1.alg_name

    data = conv.bytes_to_b64(os.urandom(random.randint(100, 500))).encode()

    for enc in list(JWE.Encryption):
        token = k1.encrypt(data, enc=enc)
        head = JWE.decode_header(token)

        assert head['alg'] == alg.value
        assert head['enc'] == enc.value

        assert data == k1.decrypt(token)
