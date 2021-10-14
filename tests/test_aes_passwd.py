
import webcrypt.keys as wk

import pytest
from math import nan


@pytest.mark.parametrize(
    "keysize",
    [None, 1025, "2048", 1024.0, 3j + 4, b'1024', nan, 0, int(), int]
)
def test_aes_genkey(keysize):
    with pytest.raises(Exception):
        wk.aes_genkey(keysize)


@pytest.mark.parametrize(
    "keysize",
    [128, 192, 256]
)
def test_aes_export_import(keysize):
    for _ in range(1000):
        k = wk.AESKey(keysize)
        assert k.key == wk.aes_parse_to_bytes(k.aes_integers)

        # even if the hexadecimal string chars are lowered, the parsing function handles it
        assert k.key == wk.aes_parse_to_bytes(k.aes_base16.lower())
        assert k.key == wk.aes_parse_to_bytes(k.aes_base16)

        # B64 strings are case sensitive, so we can't mess with the char case
        assert k.key == wk.aes_parse_to_bytes(k.aes_base64)

        # Lower case English-AES is automatically handled
        assert k.key == wk.aes_parse_to_bytes(k.aes_english.lower())
        assert k.key == wk.aes_parse_to_bytes(k.aes_english)


@pytest.mark.parametrize(
    "keysize",
    [128, 192, 256]
)
def test_aes_doc_encrypt_decrypt(keysize):
    doc = {'color': '#977cea', 'ascii_company_email': 'jacobsonwilliam@smith.com',
           'tld': 'com', 'uri_extension': '.php',
           'credit_card_expire': '01/24', 'ean8': '80978701', 'locale': 'lzh_TW', 'user_name': 'marisa42',
           'currency_symbol': '₩', 'time_object': '10:13:17',
           'text': 'Where along good choice. No too cut three political down follow option. Red their able necessary.',
           'fixed_width': 'Amy Thomas          0  \nLindsey Ross        15 \nLori Walton         14 \nMichael Nguyen'
                          '8  \nJennifer Fisher     11 \nDavid Tran          3  \nJay Robertson       '
                          '5  \nCarmen Evans        6  \nPhilip Wagner       16 \nTabitha Ferrell     19 ',
           'month_name': 'June', 'time': '05:31:48', 'year': '2018'}

    k = wk.AESKey(keysize)

    doc_enc = wk.doc_aes_encrypt_to_b64(k.key, doc)

    doc_dec = wk.doc_aes_decrypt_from_b64(k.key, doc_enc)

    assert doc_dec == doc


@pytest.mark.parametrize(
    "password_size",
    [x for x in range(10, 24)]
)
def test_password_functions(password_size):
    px = wk.password_generate(password_size)
    ph = wk.password_hash(px)
    assert wk.password_verify(px, ph)