import webcrypt.keys

from webcrypt.keys import RSAKeyPair, AESKey, aes_parse_to_bytes, \
    doc_aes_encrypt_to_b64, doc_aes_decrypt_from_b64, doc_hybrid_encrypt_to_b64, \
    doc_hybrid_decrypt_from_b64, rsa_gen_pubkey

from webcrypt.keys import password_hash, password_verify, password_generate

import pytest
from math import nan

from typing import Dict, Any


@pytest.mark.parametrize(
    "keysize",
    [None, 1025, "2048", 1024.0, 3j + 4, b'1024', nan, 0, int(), int]
)
def test_rsa_genkeypair(keysize):
    with pytest.raises(ValueError):
        webcrypt.keys.rsa_genkeypair(keysize)


@pytest.mark.parametrize(
    "keysize",
    [1024, 2048, 3072, 4096]
)
def test_RSAKeyPair_export_import(keysize, tmpdir):
    kp = webcrypt.keys.rsa_genkeypair(keysize)

    # ensure that private key is PKCS#8 PEM format, which is the more current version
    assert '-----BEGIN PRIVATE KEY-----\n' in kp.privkey

    # ensure that public key is in the PEM Format
    assert '-----BEGIN PUBLIC KEY-----\n' in kp.pubkey

    jx = kp.export_jwk()

    assert isinstance(jx, dict)

    kp2 = RSAKeyPair.import_jwk(jx)

    assert kp.privkey == kp2.privkey
    assert kp.pubkey == kp2.pubkey

    rx = kp.export_rsa_objects()

    kp3 = RSAKeyPair.import_rsa_objects(rx)

    assert kp.privkey == kp3.privkey
    assert kp.pubkey == kp3.pubkey

    # test exporting and importing of PEM files

    kp.export_pem_files(tmpdir)

    kp4 = RSAKeyPair.import_pem_files(tmpdir)

    assert kp.privkey == kp4.privkey
    assert kp.pubkey == kp4.pubkey


@pytest.fixture(scope="session")
def rsa_keys():
    rsa_keys = {}
    for keysize in [1024, 2048, 3072, 4096]:
        rsa_keys[keysize] = webcrypt.keys.rsa_genkeypair(keysize)
    return rsa_keys


@pytest.mark.parametrize(
    "message",
    [None, 1025, 1024.0, nan, 4 + 2j, int(), int, object(), set(), dict()]
)
def test_sign_bad_messages(message):
    message: Any
    key = webcrypt.keys.rsa_genkeypair()
    with pytest.raises(ValueError):
        webcrypt.keys.rsa_sign(key.privkey, message)


@pytest.mark.parametrize(
    "message",
    [r"_/\/\/\`''$%^&%#+" * 20, b"_`''$%^&%#+" * 30]
)
def test_rsa_sign_verify(message, rsa_keys: Dict[int, RSAKeyPair]):
    for key in rsa_keys.values():
        sig = webcrypt.keys.rsa_sign(key.privkey, message)
        assert webcrypt.keys.rsa_verify(key.pubkey, message, sig)


@pytest.mark.parametrize(
    "message_size,ksize",
    [(86, 1024),
     (214, 2048),
     (342, 3072),
     (470, 4096)]
)
def test_rsa_encrypt_decrypt_limits(message_size, ksize, rsa_keys):
    key = rsa_keys[ksize]
    m1 = message_size * b'x'
    m_enc = webcrypt.keys.rsa_encrypt(key.pubkey, m1)
    assert m1 == webcrypt.keys.rsa_decrypt(key.privkey, message_encrypted=m_enc)


@pytest.mark.parametrize(
    "message_size,ksize",
    [(87, 1024),
     (215, 2048),
     (343, 3072),
     (471, 4096)]
)
def test_rsa_encrypt_decrypt_limits_to_fail(message_size, ksize, rsa_keys):
    key = rsa_keys[ksize]
    m1 = message_size * b'x'
    with pytest.raises(ValueError):
        m_enc = webcrypt.keys.rsa_encrypt(key.pubkey, m1)
        assert m1 == webcrypt.keys.rsa_decrypt(key.privkey, message_encrypted=m_enc)


@pytest.mark.parametrize(
    "email",
    [b"someone@host.domain", '', 85, b"", "someone@domain", "@host.com", "some@.", ".@g.x"]
)
def test_rsa_gen_ssh_authorized_key_fail(email, rsa_keys):
    with pytest.raises(ValueError):
        webcrypt.keys.rsa_gen_ssh_authorized_key(rsa_keys[1024].privkey, email)


def test_rsa_gen_pubkey_from_privkey(rsa_keys):
    for rsa_k in rsa_keys.values():
        assert rsa_k.pubkey == rsa_gen_pubkey(rsa_k.privkey).decode()


@pytest.mark.parametrize(
    "keysize",
    [None, 1025, "2048", 1024.0, 3j + 4, b'1024', nan, 0, int(), int]
)
def test_aes_genkey(keysize):
    with pytest.raises(ValueError):
        webcrypt.keys.aes_genkey(keysize)


@pytest.mark.parametrize(
    "keysize",
    [128, 192, 256]
)
def test_aes_export_import(keysize):
    for _ in range(1000):
        k = AESKey(keysize)
        assert k.key == aes_parse_to_bytes(k.aes_integers)

        # even if the hexadecimal string chars are lowered, the parsing function handles it
        assert k.key == aes_parse_to_bytes(k.aes_base16.lower())
        assert k.key == aes_parse_to_bytes(k.aes_base16)

        # B64 strings are case sensitive, so we can't mess with the char case
        assert k.key == aes_parse_to_bytes(k.aes_base64)

        # Lower case English-AES is automatically handled
        assert k.key == aes_parse_to_bytes(k.aes_english.lower())
        assert k.key == aes_parse_to_bytes(k.aes_english)


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

    k = AESKey(keysize)

    doc_enc = doc_aes_encrypt_to_b64(k.key, doc)

    doc_dec = doc_aes_decrypt_from_b64(k.key, doc_enc)

    assert doc_dec == doc


@pytest.mark.parametrize(
    "keysize",
    [128, 192, 256]
)
def test_hybrid_doc_encrypt_decrypt(keysize, rsa_keys):
    doc = {'color': '#977cea', 'ascii_company_email': 'jacobsonwilliam@smith.com',
           'tld': 'com', 'uri_extension': '.php',
           'credit_card_expire': '01/24', 'ean8': '80978701', 'locale': 'lzh_TW', 'user_name': 'marisa42',
           'currency_symbol': '₩', 'time_object': '10:13:17',
           'text': 'Where along good choice. No too cut three political down follow option. Red their able necessary.',
           'fixed_width': 'Amy Thomas          0  \nLindsey Ross        15 \nLori Walton         14 \nMichael Nguyen'
                          '8  \nJennifer Fisher     11 \nDavid Tran          3  \nJay Robertson       '
                          '5  \nCarmen Evans        6  \nPhilip Wagner       16 \nTabitha Ferrell     19 ',
           'month_name': 'June', 'time': '05:31:48', 'year': '2018'}

    for rsa_k in rsa_keys.values():
        doc_enc = doc_hybrid_encrypt_to_b64(rsa_k.pubkey, doc, keysize=keysize)
        doc_dec = doc_hybrid_decrypt_from_b64(rsa_k.privkey, doc_enc)
        assert doc_dec == doc


@pytest.mark.parametrize(
    "password_size",
    [x for x in range(10, 24)]
)
def test_password_functions(password_size):
    px = password_generate(password_size)
    ph = password_hash(px)
    assert password_verify(px, ph)
