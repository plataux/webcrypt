import webcrypt.keys as wk
import pytest

import cryptography.hazmat.primitives.asymmetric.ec as ec

_supported_curves = {
    "secp256k1": ec.SECP256K1(),
    "secp256r1": ec.SECP256R1(),
    "secp384r1": ec.SECP384R1(),
    "secp521r1": ec.SECP521R1(),
}


@pytest.mark.parametrize(
    "ec_curve",
    list(_supported_curves.values())
)
def test_ec_export_import(ec_curve):
    privkey = wk.ECKey(ec_curve)

    # test serialization and de-serialization of an ec privkey across all supported curves
    h1 = privkey.privkey_hex()
    privkey2 = wk.ECKey.privkey_from_hex(h1, ec_curve)
    h2 = privkey2.privkey_hex()
    assert h1 == h2

    # test ser and de-ser of ec-pubkey across all curves, and pubkey formats
    for fmt in list(wk.ECKey.PubHexFormat):
        h1 = privkey.pubkey_hex(fmt)
        pubkey2 = wk.ECKey.pubkey_from_hex(h1, ec_curve, fmt)
        h2 = pubkey2.pubkey_hex(fmt)
        assert h1 == h2


@pytest.mark.parametrize(
    "ec_curve",
    list(_supported_curves.values())
)
def test_ec_sign_verify(ec_curve):
    priv1 = wk.ECKey(ec_curve)
    priv2 = wk.ECKey(ec_curve)

    priv3 = wk.ECKey.privkey_from_hex(priv1.privkey_hex(), curve=ec_curve)
    priv4 = wk.ECKey(priv1.privkey_pem())
    priv5 = wk.ECKey(priv1.privkey)

    pub1 = wk.ECKey.pubkey_from_hex(priv1.pubkey_hex(), curve=ec_curve)
    pub2 = wk.ECKey(priv1.pubkey_pem())
    pub3 = wk.ECKey(priv1.pubkey)

    assert priv1.privkey_pem() == priv3.privkey_pem()
    assert priv1.privkey_pem() == priv4.privkey_pem()
    assert priv1.privkey_pem() == priv5.privkey_pem()

    assert priv1.pubkey_pem() == pub1.pubkey_pem()
    assert priv1.pubkey_pem() == pub2.pubkey_pem()
    assert priv1.pubkey_pem() == pub3.pubkey_pem()

    data = b'some data that needs to be signed and verified'

    assert priv1.verify(data, priv1.sign(data))
    assert not priv1.verify(data, priv2.sign(data))
    assert not priv1.verify(data[:-1], priv1.sign(data))
    assert not priv1.verify(data, priv1.sign(data)[:-1])

    assert pub1.verify(data, priv1.sign(data))
    assert not pub1.verify(data, priv2.sign(data))

    assert pub2.verify(data, priv1.sign(data))


@pytest.mark.parametrize(
    "ec_curve",
    list(_supported_curves.values())
)
def test_ecdh(ec_curve):
    privkey1 = wk.ECKey(ec_curve)
    privkey2 = wk.ECKey(ec_curve)

    dk1 = wk.ECKey.ecdh_derive_key(privkey1.privkey, privkey2.pubkey)
    dk2 = wk.ECKey.ecdh_derive_key(privkey2.privkey, privkey1.pubkey)

    assert dk1 == dk2


def test_ed_export_import():
    privkey = wk.EDKey()

    h1 = privkey.privkey_hex()
    privkey2 = wk.EDKey.privkey_from_hex(h1)
    h2 = privkey2.privkey_hex()
    assert h1 == h2

    p1 = privkey.pubkey_hex()
    pubkey2 = wk.EDKey.pubkey_from_hex(p1)
    p2 = pubkey2.pubkey_hex()

    assert p1 == p2


def test_ed_sign_verify():
    priv1 = wk.EDKey()
    priv2 = wk.EDKey()

    priv3 = wk.EDKey.privkey_from_hex(priv1.privkey_hex())
    priv4 = wk.EDKey(priv1.privkey_pem())
    priv5 = wk.EDKey(priv1.privkey)

    pub1 = wk.EDKey.pubkey_from_hex(priv1.pubkey_hex())
    pub2 = wk.EDKey(priv1.pubkey_pem())
    pub3 = wk.EDKey(priv1.pubkey)

    assert priv1.privkey_pem() == priv3.privkey_pem()
    assert priv1.privkey_pem() == priv4.privkey_pem()
    assert priv1.privkey_pem() == priv5.privkey_pem()

    assert priv1.pubkey_pem() == pub1.pubkey_pem()
    assert priv1.pubkey_pem() == pub2.pubkey_pem()
    assert priv1.pubkey_pem() == pub3.pubkey_pem()

    data = b'some data that needs to be signed and verified'

    assert priv1.verify(data, priv1.sign(data))
    assert not priv1.verify(data, priv2.sign(data))
    assert not priv1.verify(data[:-1], priv1.sign(data))
    assert not priv1.verify(data, priv1.sign(data)[:-1])

    assert pub1.verify(data, priv1.sign(data))
    assert not pub1.verify(data, priv2.sign(data))

    assert pub2.verify(data, priv1.sign(data))

