import webcrypt.keys as wk

import pytest
from math import nan


@pytest.mark.parametrize(
    "key",
    [None, 1025, "128", 1024.0, 3j + 4, b'256', nan, 0, int(), int]
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


def test_derive_key():
    k1 = wk.derive_key('python')
    k2 = wk.derive_key('python')

    assert k1 != k2

    k1 = wk.derive_key('python', salt=b'abcdefg')
    k2 = wk.derive_key('python', salt=b'abcdefg')

    assert k1 == k2
