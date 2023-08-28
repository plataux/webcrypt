import webcrypt.keys as wk

import pytest
import os
from math import nan


@pytest.mark.parametrize(
    "key",
    [None, 1025, "128", 1024.0, 3j + 4, b'256', nan, 0, int(), int, float]
)
def test_aes_genkey(key):
    with pytest.raises(Exception):
        wk.AES(key)


@pytest.mark.parametrize(
    "keysize",
    [128, 192, 256]
)
def test_aes_export_import(keysize):
    for _ in range(100):
        k = wk.AES(keysize)

        # load a another key obj from a bytes string, and the __eq__ with 2 obj
        assert k == wk.AES(k.key)

        # restore a key from an int array
        assert k.key == wk.AES.restore_key_bytes(k.array)

        # even if the hexadecimal string chars are lowered, the parsing function handles it
        assert k.key == wk.AES.restore_key_bytes(k.base16.lower())
        assert k.key == wk.AES.restore_key_bytes(k.base16)

        # B64 strings are case sensitive, so we can't mess with the char case
        assert k.key == wk.AES.restore_key_bytes(k.base64)

        # B85
        assert k.key == wk.AES.restore_key_bytes(k.base85)

        # Lower case English-AES is automatically handled
        assert k.key == wk.AES.restore_key_bytes(k.words.lower())
        assert k.key == wk.AES.restore_key_bytes(k.words)


@pytest.mark.parametrize(
    "auth_data",
    [None, b'', b'Some Random Auth data string']
)
def test_encrypt_decrypt(auth_data):
    data = b"""
    Python's convenience has made it the most popular language for machine learning
    and artificial intelligence. Python's flexibility has allowed Anyscale to make
    ML/AI scalable from laptops to clusters.
    """

    k = wk.AES()

    enc = k.encrypt(data, auth_data=auth_data)

    dec = k.decrypt(enc, auth_data=auth_data)

    assert data == dec

    with pytest.raises(Exception):
        k.decrypt(enc, auth_data=b'incorrect auth data')


@pytest.mark.parametrize(
    "auth_data",
    [None, b'', b'Some Random Auth data string']
)
@pytest.mark.parametrize(
    "keysize",
    [16, 24, 32],
)
def test_gcm_encrypt_decrypt(auth_data, keysize):
    data = b"""
    Python's convenience has made it the most popular language for machine learning
    and artificial intelligence. Python's flexibility has allowed Anyscale to make
    ML/AI scalable from laptops to clusters.
    """

    key_correct = os.urandom(keysize)

    key_wrong = os.urandom(keysize)

    enc = wk.encrypt_gcm(key_correct, data, auth_data=auth_data)

    dec = wk.decrypt_gcm(key_correct, enc, auth_data=auth_data)

    assert data == dec

    with pytest.raises(Exception):
        wk.decrypt_gcm(key_wrong, enc, auth_data=auth_data)

    with pytest.raises(Exception):
        wk.decrypt_gcm(key_correct, enc, auth_data=b'incorrect auth data')


@pytest.mark.parametrize(
    "auth_data",
    [None, b'', b'Some Random Auth data string']
)
@pytest.mark.parametrize(
    "keysize",
    [32, 48, 64],
)
def test_cbc_encrypt_decrypt(auth_data, keysize):
    data = b"""
    Python's convenience has made it the most popular language for machine learning
    and artificial intelligence. Python's flexibility has allowed Anyscale to make
    ML/AI scalable from laptops to clusters.
    """

    key_correct = os.urandom(keysize)

    key_wrong = os.urandom(keysize)

    enc = wk.encrypt_cbc(key_correct, data, auth_data=auth_data)

    dec = wk.decrypt_cbc(key_correct, enc, auth_data=auth_data)

    assert data == dec

    with pytest.raises(Exception):
        wk.decrypt_cbc(key_wrong, enc, auth_data=auth_data)

    with pytest.raises(Exception):
        wk.decrypt_cbc(key_correct, enc, auth_data=b'incorrect auth data')
