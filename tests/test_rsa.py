import webcrypt.keys as wk

import pytest
from math import nan

from typing import Dict


@pytest.mark.parametrize(
    "key",
    [None, 1025, "2048", 1024.0, 3j + 4, b'1024', nan, 0, int(), int]
)
def test_rsa_genkeypair(key):
    with pytest.raises(ValueError):
        wk.RSA(key)


@pytest.mark.parametrize(
    "keysize",
    [2048, 3072, 4096]
)
def test_RSAKeyPair_export_import(keysize, tmpdir):
    kp = wk.RSA(keysize)

    pub_pem = kp.pubkey_pem()
    priv_pem = kp.privkey_pem()

    # ensure that private key is PKCS#8 PEM format, which is the more current version
    assert '-----BEGIN PRIVATE KEY-----\n' in priv_pem

    # ensure that public key is in the PEM Format
    assert '-----BEGIN PUBLIC KEY-----\n' in pub_pem

    # Export and Import of PEM Data
    kp2 = wk.RSA(kp.privkey_pem())
    assert kp == kp2

    # Export and Import of RSA components dict
    kp2 = wk.RSA(kp.privkey_dict())
    assert kp == kp2


@pytest.fixture(scope="session")
def rsa_keys() -> Dict[int, wk.RSA]:
    rsa_keys = {}
    for keysize in [2048, 3072, 4096]:
        rsa_keys[keysize] = wk.RSA(keysize)
    return rsa_keys


@pytest.mark.parametrize(
    "message",
    [r"_/\/\/\`''$%^&%#+" * 20, b"_`''$%^&%#+" * 30]
)
def test_rsa_sign_verify(message, rsa_keys: Dict[int, wk.RSA]):
    for key in rsa_keys.values():
        sig = key.sign(message)
        assert key.verify(message, sig)


@pytest.mark.parametrize(
    "message_size,ksize",
    [
        (190, 2048),
        (318, 3072),
        (446, 4096)]
)
def test_rsa_wrap_unwrap_limits(message_size, ksize,
                                rsa_keys: Dict[int, wk.RSA]):
    key = rsa_keys[ksize]
    m1 = message_size * b'x'
    m_enc = key.wrap(m1)
    assert m1 == key.unwrap(m_enc)


@pytest.mark.parametrize(
    "message_size,ksize",
    [
        (240, 2048),
        (350, 3072),
        (480, 4096)]
)
def test_rsa_encrypt_decrypt_limits_to_fail(message_size, ksize, rsa_keys):
    key = rsa_keys[ksize]
    m1 = message_size * b'x'
    with pytest.raises(ValueError):
        m_enc = key.wrap(m1)
        assert m1 == key.unwrap(message_encrypted=m_enc)


@pytest.mark.parametrize(
    "email",
    [b"someone@host.domain", '', 85, b"", "someone@domain", "@host.com", "some@.", ".@g.x"]
)
def test_rsa_gen_ssh_authorized_key_fail(email, rsa_keys):
    with pytest.raises(ValueError):
        rsa_keys[2048].pubkey_ssh(email)


@pytest.mark.parametrize(
    "email",
    ["someone@host.domain"]
)
def test_rsa_gen_ssh_authorized_key(email, rsa_keys):
    for key in rsa_keys.values():
        key_str = key.pubkey_ssh(email)
        assert email in key_str
        assert key_str.split()[2] == email


@pytest.mark.parametrize(
    "keysize",
    [128, 192, 256]
)
def test_rsa_encrypt_decrypt(keysize, rsa_keys):
    doc = b"""
    Python's convenience has made it the most popular language for machine learning and 
    artificial intelligence. Python's flexibility has allowed Anyscale to make ML/AI 
    scalable from laptops to clusters.
    """

    for rsa_k in rsa_keys.values():
        doc_enc = rsa_k.encrypt(doc, keysize)
        doc_dec = rsa_k.decrypt(doc_enc)
        assert doc_dec == doc
