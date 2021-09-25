
import pytest

from webcrypt.jwx import *
from webcrypt.keys import RSAKeyPair, rsa_genkeypair
from time import sleep

from jose.exceptions import ExpiredSignatureError, JWSError, JWTClaimsError, JWTError
import json


def test_token_workflow():
    kp = rsa_genkeypair()

    tk = jwt_create(expires=exp_create(seconds=1))

    tk_encoded = jwt_encode(tk, privkey=kp.privkey)

    tk_decoded = jwt_decode(tk_encoded, pubkey=kp.pubkey)

    assert tk.dict() == Token.parse_obj(tk_decoded).dict()

    sleep(2)
    with pytest.raises(ExpiredSignatureError):
        jwt_decode(tk_encoded, pubkey=kp.pubkey)


def test_token_jwe():
    kp = rsa_genkeypair()
    kp2 = rsa_genkeypair()

    access_token = jwt_create(expires=exp_create(seconds=1))
    access_encoded = jwt_encode(access_token, privkey=kp.privkey)

    assert jwt_verify_signature(access_encoded, kp.pubkey)[0]
    assert not jwt_verify_signature(access_encoded, kp2.pubkey)[0]

    access_encrypted = jwe_encrypt(access_encoded, kp.pubkey)

    id_token = jwt_create(expires=exp_create(seconds=1))

    id_encoded = jwt_encode(id_token, privkey=kp.privkey, access_token=access_encrypted)

    id_decoded = jwt_decode(id_encoded, pubkey=kp.pubkey, access_token=access_encrypted)

    id_dict = id_decoded

    assert "at_hash" in id_dict

    del id_dict["at_hash"]

    assert json.dumps(id_dict) == id_token.json(exclude_unset=True)

    access_decrypted = jwe_decrypt(access_encrypted, kp.privkey)

    assert access_decrypted == access_encoded

    assert jwt_decode(access_decrypted, kp.pubkey)

    sleep(2)

    with pytest.raises(ExpiredSignatureError):
        jwt_decode(id_encoded, pubkey=kp.pubkey, access_token=access_encrypted)

    with pytest.raises(ExpiredSignatureError):
        jwt_decode(access_decrypted, kp.pubkey)
