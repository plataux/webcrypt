import pytest

from webcrypt.jwe import JWE
import json

# from typing import Dict
import os


_aes_alg_size = {
    'A128GCMKW': 16,
    'A192GCMKW': 24,
    'A256GCMKW': 32,
    'A128KW': 16,
    'A192KW': 24,
    'A256KW': 32,
    'A128GCM': 16,
    'A192GCM': 24,
    'A256GCM': 32
}


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

    # # to and from pem
    ek2 = JWE.from_pem(ek1.to_pem(), algorithm=algo)
    assert ek1.to_pem() == ek2.to_pem()
    #
    # to and from key objects
    ek2 = JWE(algo, encryption=None, key=ek1.privkey)
    assert ek1.to_pem() == ek2.to_pem()
    #
    # data = b'Some Random data to be encrypted and decrypted'

    # sign and verify

    # token = ek1.encrypt(data)
    # ek1.decrypt(token)
    #
    # sign, and a separate public key object to verify

    # if algo.name not in ('HS256', 'HS384', 'HS512'):
    #     ek2 = JWE(algorithm=algo, key_obj=ek1.pubkey)
    # else:
    #     ek2 = JWE(algorithm=algo, key_obj=ek1.privkey)
    #
    # token = ek1.encrypt(data)
    # ek1.decrypt(token)


def test_jwe_defaults():
    # test JWE defaults
    ek = JWE()
    assert len(ek.key) == 16 and ek.alg_name == 'A128KW' and ek.enc_name == 'A128GCM'
    assert ek.kty == 'oct'

    # test default Encryption algorithm, A128GCM by default
    ek = JWE(JWE.Algorithm.DIR)
    assert len(ek.key) == 16 and ek.alg_name == 'dir' and ek.enc_name == 'A128GCM'
    assert ek.kty == 'oct'


@pytest.mark.parametrize(
    "enc",
    [JWE.Encryption.A128GCM, JWE.Encryption.A192GCM, JWE.Encryption.A256GCM]
)
def test_dir_ops(enc):

    # test randomly generated keys with given encryption algos
    ek = JWE(JWE.Algorithm.DIR, encryption=enc)
    assert len(ek.key) == _aes_alg_size[enc.name]
    assert ek.alg_name == 'dir' and ek.enc_name == enc.name

    # test existing keys without specifying encryption algos
    k = os.urandom(_aes_alg_size[enc.name])
    ek = JWE(JWE.Algorithm.DIR, key=k)
    assert ek.key == k
    assert ek.alg_name == 'dir' and ek.enc_name == enc.name

    # test invalid AES keys
    k = os.urandom(_aes_alg_size[enc.name]) + b'x'
    with pytest.raises(ValueError):
        JWE(JWE.Algorithm.DIR, key=k)

    k = os.urandom(_aes_alg_size[enc.name])[:-1]
    with pytest.raises(ValueError):
        JWE(JWE.Algorithm.DIR, key=k)

    # test valid keys that contradict specified encryption algorithm
    valid_sizes = [16, 24, 32]
    enc_size = _aes_alg_size[enc.name]
    valid_sizes.remove(enc_size)
    for v in valid_sizes:
        k = os.urandom(v)
        with pytest.raises(ValueError):
            JWE(JWE.Algorithm.DIR, encryption=enc, key=k)

    # test encrypt and decrypt with and without compression
    ek = JWE(JWE.Algorithm.DIR, encryption=enc)

    data = b'some data to be encrypted and decrypted'
    data_enc = ek.encrypt(data, compress=False)
    data_enc_comp = ek.encrypt(data, compress=True)

    assert data_enc != data_enc_comp
    assert data == ek.decrypt(data_enc)
    assert data == ek.decrypt(data_enc_comp)


@pytest.mark.parametrize(
    "enc",
    [JWE.Encryption.A128GCM, JWE.Encryption.A192GCM, JWE.Encryption.A256GCM]
)
def test_kw_ops(enc):
    ek = JWE()


@pytest.mark.parametrize(
    "alg",
    [JWE.Algorithm.ECDH_ES, JWE.Algorithm.ECDH_ES_A128KW,
     JWE.Algorithm.ECDH_ES_A192KW, JWE.Algorithm.ECDH_ES_A256KW]
)
def test_ecdh_1(alg):

    k1 = JWE(algorithm=alg)

    k2 = JWE(algorithm=alg)

    data = b'some data to be encrpyted and decrypted'

    with pytest.raises(RuntimeError):
        k1.encrypt(data)

    u_params = k1.party_u_generate('Alice')

    with pytest.raises(RuntimeError):
        k1.encrypt(data)

    v_params = k2.party_v_import(u_params, 'Bob')

    data_enc = k2.encrypt(data)

    assert k1.decrypt(data_enc) == data


@pytest.mark.parametrize(
    "alg",
    [JWE.Algorithm.ECDH_ES, JWE.Algorithm.ECDH_ES_A128KW,
     JWE.Algorithm.ECDH_ES_A192KW, JWE.Algorithm.ECDH_ES_A256KW]
)
def test_ecdh_2(alg):

    k1 = JWE(algorithm=alg)

    k2 = JWE(algorithm=alg)

    data = b'some data to be encrpyted and decrypted'

    with pytest.raises(RuntimeError):
        k1.encrypt(data)

    u_params = k1.party_u_generate('Alice')

    with pytest.raises(RuntimeError):
        k1.encrypt(data)

    uv_params = k2.party_v_import(u_params, 'Bob')

    k1.party_u_import(uv_params)

    data_enc = k1.encrypt(data, compress=True, extra_header={'cty': 'binary'})

    assert k2.decrypt(data_enc) == data