
import webcrypt.keys as wk

import pytest
from math import nan

from typing import Dict, Any


@pytest.mark.parametrize(
    "keysize",
    [None, 1025, "2048", 1024.0, 3j + 4, b'1024', nan, 0, int(), int]
)
def test_rsa_genkeypair(keysize):
    with pytest.raises(ValueError):
        wk.rsa_genkeypair(keysize)


@pytest.mark.parametrize(
    "keysize",
    [1024, 2048, 3072, 4096]
)
def test_RSAKeyPair_export_import(keysize, tmpdir):
    kp = wk.rsa_genkeypair(keysize)

    pem = kp.export_pem_data()

    # ensure that private key is PKCS#8 PEM format, which is the more current version
    assert b'-----BEGIN PRIVATE KEY-----\n' in pem['privkey']

    # ensure that public key is in the PEM Format
    assert b'-----BEGIN PUBLIC KEY-----\n' in pem['pubkey']

    # Export and Import of PEM Data
    kp2 = wk.RSAKeyPair.import_pem_data(kp.export_pem_data())
    assert repr(kp) == repr(kp2)

    # Export and Import of PEM Files
    kp.export_pem_files(tmpdir)
    kp2 = wk.RSAKeyPair.import_pem_files(tmpdir)
    assert repr(kp) == repr(kp2)

    # Export and Import of RSA components dict
    kp2 = wk.RSAKeyPair.import_from_components(kp.export_to_components())
    assert repr(kp) == repr(kp2)


@pytest.fixture(scope="session")
def rsa_keys() -> Dict[int, wk.RSAKeyPair]:
    rsa_keys = {}
    for keysize in [1024, 2048, 3072, 4096]:
        rsa_keys[keysize] = wk.rsa_genkeypair(keysize)
    return rsa_keys


@pytest.mark.parametrize(
    "message",
    [None, 1025, 1024.0, nan, 4 + 2j, int(), int, object(), set(), dict()]
)
def test_sign_bad_messages(message):
    message: Any
    key = wk.rsa_genkeypair()
    with pytest.raises(ValueError):
        wk.rsa_sign(key.privkey, message)


@pytest.mark.parametrize(
    "message",
    [r"_/\/\/\`''$%^&%#+" * 20, b"_`''$%^&%#+" * 30]
)
def test_rsa_sign_verify(message, rsa_keys: Dict[int, wk.RSAKeyPair]):
    for key in rsa_keys.values():
        sig = wk.rsa_sign(key.privkey, message)
        assert wk.rsa_verify(key.pubkey, message, sig)


@pytest.mark.parametrize(
    "message_size,ksize",
    [(62, 1024),
     (190, 2048),
     (318, 3072),
     (446, 4096)]
)
def test_rsa_encrypt_decrypt_limits(message_size, ksize,
                                    rsa_keys: Dict[int, wk.RSAKeyPair]):
    key = rsa_keys[ksize]
    m1 = message_size * b'x'
    m_enc = wk.rsa_encrypt(key.pubkey, m1)
    assert m1 == wk.rsa_decrypt(key.privkey, message_encrypted=m_enc)


@pytest.mark.parametrize(
    "message_size,ksize",
    [(63, 1024),
     (191, 2048),
     (319, 3072),
     (447, 4096)]
)
def test_rsa_encrypt_decrypt_limits_to_fail(message_size, ksize, rsa_keys):
    key = rsa_keys[ksize]
    m1 = message_size * b'x'
    with pytest.raises(ValueError):
        m_enc = wk.rsa_encrypt(key.pubkey, m1)
        assert m1 == wk.rsa_decrypt(key.privkey, message_encrypted=m_enc)


@pytest.mark.parametrize(
    "email",
    [b"someone@host.domain", '', 85, b"", "someone@domain", "@host.com", "some@.", ".@g.x"]
)
def test_rsa_gen_ssh_authorized_key_fail(email, rsa_keys):
    with pytest.raises(ValueError):
        wk.rsa_gen_ssh_authorized_key(rsa_keys[1024].pubkey, email)


@pytest.mark.parametrize(
    "email",
    ["someone@host.domain"]
)
def test_rsa_gen_ssh_authorized_key(email, rsa_keys):
    for key in rsa_keys.values():
        key_str = wk.rsa_gen_ssh_authorized_key(key.pubkey, email)
        assert email in key_str
        assert key_str.split()[2] == email


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
        doc_enc = wk.doc_hybrid_encrypt_to_b64(rsa_k.pubkey, doc, keysize=keysize)
        doc_dec = wk.doc_hybrid_decrypt_from_b64(rsa_k.privkey, doc_enc)
        assert doc_dec == doc
