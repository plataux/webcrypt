

import webcrypt.keys as wk
import pytest


@pytest.mark.parametrize(
    "ec_curve",
    list(wk._supported_curves.values())
)
def test_ec_export_import(ec_curve):
    privkey = wk.ec_privkey_generate(ec_curve)

    # test serialization and de-serialization of an ec privkey across all supported curves
    h1 = wk.ec_privkey_to_hex(privkey)
    privkey2 = wk.ec_privkey_from_hex(h1, ec_curve)
    h2 = wk.ec_privkey_to_hex(privkey2)
    assert h1 == h2

    # test ser and de-ser of ec-pubkey across all curves, and pubkey formats
    pubkey = privkey.public_key()
    for fmt in list(wk.EllipticPubkeyFormat):
        h1 = wk.ec_pubkey_to_hex(pubkey, fmt)
        pubkey2 = wk.ec_pubkey_from_hex(h1, ec_curve, fmt)
        h2 = wk.ec_pubkey_to_hex(pubkey2, fmt)
        assert h1 == h2


@pytest.mark.parametrize(
    "ec_curve",
    list(wk._supported_curves.values())
)
def test_ec_sign_verify(ec_curve):
    privkey1 = wk.ec_privkey_generate(ec_curve)

    privkey2 = wk.ec_privkey_generate(ec_curve)

    data = b"some data to be signed"

    sig = wk.ec_sign(privkey1, data)

    assert wk.ec_verify(privkey1.public_key(), data, sig)

    assert not wk.ec_verify(privkey2.public_key(), data, sig)
    assert not wk.ec_verify(privkey1.public_key(), data[:-1], sig)
    assert not wk.ec_verify(privkey1.public_key(), data, sig[:-1])


@pytest.mark.parametrize(
    "ec_curve",
    list(wk._supported_curves.values())
)
def test_ecdh(ec_curve):
    privkey1 = wk.ec_privkey_generate(ec_curve)
    privkey2 = wk.ec_privkey_generate(ec_curve)

    dk1 = wk.ec_dh_derive_key(privkey1, privkey2.public_key())
    dk2 = wk.ec_dh_derive_key(privkey2, privkey1.public_key())

    assert dk1 == dk2


@pytest.mark.parametrize(
    "privkey",
    [*[wk.ec_privkey_generate(c) for c in wk._supported_curves.values()],
     wk.ed_privkey_generate()]
)
def test_curve_sign_verify_doc(privkey):
    msg = 'a message to be signed and verified'
    doc = wk.curve_sign_doc(privkey, msg)
    assert wk.curve_verify_doc(doc)


def test_ed_export_import():
    privkey = wk.ed_privkey_generate()

    h1 = wk.ed_privkey_to_hex(privkey)
    privkey2 = wk.ed_privkey_from_hex(h1)
    h2 = wk.ed_privkey_to_hex(privkey2)
    assert h1 == h2

    pubkey = privkey.public_key()
    p1 = wk.ed_pubkey_to_hex(pubkey)
    pubkey2 = wk.ed_pubkey_from_hex(p1)
    p2 = wk.ed_pubkey_to_hex(pubkey2)

    assert p1 == p2


def test_ed_sign_verify():
    priv1 = wk.ed_privkey_generate()
    priv2 = wk.ed_privkey_generate()

    data = b'some data that needs to be signed and verified'

    assert wk.ed_verify(priv1.public_key(), data, wk.ed_sign(priv1, data))
    assert not wk.ed_verify(priv2.public_key(), data, wk.ed_sign(priv1, data))
    assert not wk.ed_verify(priv1.public_key(), data[:-1], wk.ed_sign(priv1, data))
    assert not wk.ed_verify(priv1.public_key(), data, wk.ed_sign(priv1, data)[:-1])
