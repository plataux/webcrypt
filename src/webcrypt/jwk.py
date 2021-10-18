# https://datatracker.ietf.org/doc/html/rfc7518#section-3.1

from __future__ import annotations

import enum
import json
from typing import Dict, Tuple, Callable, Any, Union, Optional
from math import ceil
from random import choice
import os

from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, SECP384R1, SECP521R1
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization as ser

import webcrypt.convert as conv
import binascii

from webcrypt.exceptions import JWKAlgorithmMismatch, InvalidSignature
from uuid import uuid4

_jwk_curves = {
    'secp256r1': {'kty': 'EC', 'alg': 'ES256', 'crv': 'P-256'},
    'secp384r1': {'kty': 'EC', 'alg': 'ES384', 'crv': 'P-384'},
    'secp521r1': {'kty': 'EC', 'alg': 'ES512', 'crv': 'P-521'},
}

crypto_keys_types = Union[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey,
                          rsa.RSAPrivateKey, rsa.RSAPublicKey, bytes]


class _RSAPadding(enum.Enum):
    PSS = 1
    PKCS1v15 = 2


class JWK_Algorithm(enum.Enum):
    HS256 = {'hash_alg': SHA256()}
    HS384 = {'hash_alg': SHA384()}
    HS512 = {'hash_alg': SHA512()}
    RS256 = {'hash_alg': SHA256(), "rsa_padding": _RSAPadding.PKCS1v15}
    RS384 = {'hash_alg': SHA384(), "rsa_padding": _RSAPadding.PKCS1v15}
    RS512 = {'hash_alg': SHA512(), "rsa_padding": _RSAPadding.PKCS1v15}
    PS256 = {'hash_alg': SHA256(), "rsa_padding": _RSAPadding.PSS}
    PS384 = {'hash_alg': SHA384(), "rsa_padding": _RSAPadding.PSS}
    PS512 = {'hash_alg': SHA512(), "rsa_padding": _RSAPadding.PSS}
    ES256 = {'hash_alg': SHA256(), 'crv': SECP256R1}
    ES384 = {'hash_alg': SHA384(), 'crv': SECP384R1}
    ES512 = {'hash_alg': SHA512(), 'crv': SECP521R1}


class JWK:
    __slots__ = ('_key', '_jwk', '_signer', '_verifier', '_hash_alg')

    def __init__(self,
                 key: Optional[Dict[str, Any] |
                               Tuple[crypto_keys_types,
                                     Optional[JWK_Algorithm]]] = None,
                 kid=None):

        if isinstance(key, dict):
            self._key = jwk_to_key(key)
            self._jwk = key
            del key

        elif isinstance(key, tuple):
            self._jwk = jwk_from_key(*key)
            self._key = key[0]
            del key

        elif key is None:
            self._key = os.urandom(32)
            self._jwk = jwk_from_key(self._key, None)

        else:
            raise ValueError(f"Unexpected cryptographic key format: {type(key)}")

        if kid is not None:
            self._jwk = {'kid': kid, **self._jwk}

        elif 'kid' not in self._jwk:
            self._jwk = {'kid': str(uuid4()), **self._jwk}

        self._hash_alg = _parse_hash_alg(f'sha{self._jwk["alg"][2:]}')

        def _signer(_):
            raise ValueError(f"This JWK Does not support signing and encoding JWTs "
                             f" {self._jwk['kid']}:{self._jwk['key_opts']}")

        self._signer = _signer

        if self._jwk['kty'] == 'RSA':
            self._verifier = _rsa_jwt_verifier(self._jwk)
            if 'sign' in self._jwk['key_ops']:
                self._signer = _rsa_jwt_signer(self._jwk)

        elif self._jwk['kty'] == 'EC':
            self._verifier = _ec_jwt_verifier(self._jwk)
            if 'sign' in self._jwk['key_ops']:
                self._signer = _ec_jwt_signer(self._jwk)

        elif self._jwk['kty'] == 'oct':
            self._signer = _hmac_jwt_signer(self._jwk)
            self._verifier = _hmac_jwt_verifier(self._jwk)

    @classmethod
    def from_pem(cls, key_pem: str | bytes,
                 jwk_alg: JWK_Algorithm = None, kid=None) -> "JWK":
        if isinstance(key_pem, str):
            key_pem = key_pem.encode()

        if b'PRIVATE' in key_pem:
            return cls((ser.load_pem_private_key(key_pem, password=None), jwk_alg), kid)
        elif b'PUBLIC' in key_pem:
            return cls((ser.load_pem_public_key(key_pem), jwk_alg), kid)
        else:
            raise ValueError("Invalid PEM file")

    @classmethod
    def random_jwk_alg(cls) -> "JWK":
        J = JWK_Algorithm

        def _hmac_key():
            hx = [(SHA256, J.HS256), (SHA384, J.HS384), (SHA512, J.HS512)]
            h = choice(hx)
            return cls((os.urandom(h[0].digest_size), h[1]))

        def _rsa_key():
            hx = [J.PS256, J.PS384, J.PS512, J.RS256, J.RS384, J.RS512]
            ks = [k * 1024 for k in (2, 3, 4)]
            return cls((rsa.generate_private_key(65537, choice(ks)), choice(hx)))

        def _ec_key():
            _c = [SECP256R1(), SECP384R1(), SECP521R1()]
            return cls((ec.generate_private_key(choice(_c)), None))

        _tx = [
            _hmac_key,
            _rsa_key,
            _ec_key
        ]

        return choice(_tx)()

    def sign(self, payload):
        return self._signer(payload)

    def verify(self, token, raise_errors=False):
        return self._verifier(token, raise_errors)

    def hash_data(self, data: str | bytes) -> bytes:
        if isinstance(data, str):
            data = data.encode()
        hasher = hashes.Hash(self._hash_alg)
        hasher.update(data)
        return hasher.finalize()

    @property
    def key(self):
        return self._key

    @property
    def jwk(self):
        return self._jwk

    @property
    def hash_alg(self):
        return self._hash_alg

    def __repr__(self) -> str:
        return json.dumps(self.jwk, indent=1)

    def __str__(self) -> str:
        return repr(self)


def jwk_from_key(key: crypto_keys_types,
                 jwk_alg: JWK_Algorithm = None) -> Dict[str, str]:
    J = JWK_Algorithm

    if isinstance(key, ec.EllipticCurvePrivateKey):
        if jwk_alg is not None and jwk_alg not in (J.ES256, J.ES384, J.ES512):
            raise ValueError(f"Chosen Alg {jwk_alg} incompatible with given EC key")

        jwk_dict = _ec_privkey_to_jwk(key)

        if jwk_alg is None or jwk_alg.name == jwk_dict['alg']:
            return jwk_dict
        else:
            raise ValueError(f"Chosen Alg: {jwk_alg.name} incompatible "
                             f"with EC Curve type of the "
                             f"given key: {jwk_alg['crv']}")

    if isinstance(key, ec.EllipticCurvePublicKey):
        if jwk_alg is not None and jwk_alg not in (J.ES256, J.ES384, J.ES512):
            raise ValueError(f"Chosen Alg {jwk_alg} incompatible with given EC key")

        jwk_dict = _ec_pubkey_to_jwk(key)

        if jwk_alg is None or jwk_alg.name == jwk_dict['alg']:
            return jwk_dict
        else:
            raise ValueError(f"Chosen Alg: {jwk_alg.name} incompatible "
                             f"with EC Curve type of the "
                             f"given key: {jwk_alg['crv']}")

    rsa_alg = (J.RS256, J.RS384, J.RS512, J.PS256, J.PS384, J.PS512)

    if isinstance(key, rsa.RSAPrivateKey):
        jwk_alg = jwk_alg if jwk_alg is not None else J.PS256

        if jwk_alg not in rsa_alg:
            raise ValueError(f"Chosen Alg: {jwk_alg} incompatible with given RSA Key")
        jwk_dict = _rsa_privkey_to_jwk(key, **jwk_alg.value)
        return jwk_dict

    if isinstance(key, rsa.RSAPublicKey):
        jwk_alg = jwk_alg if jwk_alg is not None else J.PS256

        if jwk_alg not in rsa_alg:
            raise ValueError(f"Chosen Alg: {jwk_alg} incompatible with given RSA Key")
        jwk_dict = _rsa_pubkey_to_jwk(key, **jwk_alg.value)
        return jwk_dict

    if isinstance(key, bytes):
        jwk_alg = jwk_alg if jwk_alg is not None else J.HS256

        if jwk_alg not in (J.HS256, J.HS384, J.HS512):
            raise ValueError(f"Chosen Alg: {jwk_alg} incompatible with given HMAC Key")

        jwk_dict = _hmac_to_jwk(key, **jwk_alg.value)
        return jwk_dict

    raise ValueError(f"unsupported key type: {type(key)}")


def jwk_to_key(jwk: Dict[str, Any]) -> crypto_keys_types:
    if not all(item in jwk for item in ('kty', 'alg')):
        raise ValueError("Invalid JWK format")

    if jwk['alg'] not in [_ja.name for _ja in list(JWK_Algorithm)]:
        raise ValueError(f"Invalid JWK alg: {jwk['alg']}")

    kty = jwk['kty']

    if kty not in ('RSA', 'EC', 'oct'):
        raise ValueError(f"Invalid JWK kty {jwk['alg']}")

    if kty == 'RSA':
        if all(comp in jwk for comp in ('e', 'n', 'p', 'q', 'd', 'dp', 'dq', 'qi')):
            jwk['key_ops'] = ['sign', 'verify']
            return _rsa_privkey_from_jwk(jwk)
        elif all(comp in jwk for comp in ('e', 'n')):
            jwk['key_ops'] = ['verify']
            return _rsa_pubkey_from_jwk(jwk)

    elif kty == 'EC':
        if all(comp in jwk for comp in ('crv', 'x', 'y', 'd')):
            jwk['key_ops'] = ['sign', 'verify']
            return _ec_privkey_from_jwk(jwk)
        elif all(comp in jwk for comp in ('crv', 'x', 'y')):
            jwk['key_ops'] = ['verify']
            return _ec_pubkey_from_jwk(jwk)
        else:
            raise ValueError("Invalid EC JWK")

    elif kty == 'oct':
        if 'k' in jwk:
            return conv.bytes_from_b64(jwk['k'])
        else:
            raise ValueError("Invalid HMAC JWK")


def jwt_signer(jwk: Dict[str, Any]):
    if jwk['kty'] == 'RSA':
        return _rsa_jwt_signer(jwk)

    elif jwk['kty'] == 'EC':
        return _ec_jwt_signer(jwk)

    elif jwk['kty'] == 'oct':
        return _hmac_jwt_signer(jwk)


def jwt_verifier(jwk: Dict[str, Any]):
    if jwk['kty'] == 'RSA':
        return _rsa_jwt_verifier(jwk)

    elif jwk['kty'] == 'EC':
        return _ec_jwt_verifier(jwk)

    elif jwk['kty'] == 'oct':
        return _hmac_jwt_verifier(jwk)


def _parse_hash_alg(alg: str) -> hashes.HashAlgorithm:
    _jwk_hashes = {
        'sha256': SHA256(),
        'sha384': SHA384(),
        'sha512': SHA512()
    }
    alg = alg.lower()
    if alg not in _jwk_hashes:
        raise ValueError(f"unsupported hash algorithm: {alg}")
    return _jwk_hashes[alg]


def _ec_privkey_to_jwk(key: ec.EllipticCurvePrivateKey) -> Dict[str, str]:
    if key.curve.name not in _jwk_curves:
        raise RuntimeError(f"only the following curves "
                           f"supported for jwk: {list(_jwk_curves.keys())}")

    pub_nums = key.public_key().public_numbers()
    priv_nums = key.private_numbers()

    jwk_dict = {}

    jwk_dict.update(_jwk_curves[key.curve.name])

    jwk_dict['key_ops'] = ['sign', 'verify']

    ks = int(ceil(key.curve.key_size / 8))

    jwk_dict['x'] = conv.bytes_to_b64(conv.int_to_bytes(pub_nums.x, byte_size=ks))
    jwk_dict['y'] = conv.bytes_to_b64(conv.int_to_bytes(pub_nums.y, byte_size=ks))
    jwk_dict['d'] = conv.bytes_to_b64(conv.int_to_bytes(priv_nums.private_value,
                                                        byte_size=ks))

    return jwk_dict


def _ec_pubkey_to_jwk(key: ec.EllipticCurvePublicKey) -> Dict[str, str]:
    if key.curve.name not in _jwk_curves:
        raise RuntimeError(f"only the following curves supported"
                           f" for jwk: {list(_jwk_curves.keys())}")

    pub_nums = key.public_numbers()

    jwk_dict = {}

    jwk_dict.update(_jwk_curves[key.curve.name])

    jwk_dict['key_ops'] = ['verify']

    ks = int(ceil(key.curve.key_size / 8))

    jwk_dict['x'] = conv.bytes_to_b64(conv.int_to_bytes(pub_nums.x, byte_size=ks))
    jwk_dict['y'] = conv.bytes_to_b64(conv.int_to_bytes(pub_nums.y, byte_size=ks))

    return jwk_dict


def _ec_privkey_from_jwk(jwk_dict: Dict[str, str]) -> ec.EllipticCurvePrivateKey:
    _jwk_crv_to_curve = {
        'P-256': SECP256R1(),
        'P-384': SECP384R1(),
        'P-521': SECP521R1()
    }

    key_curve: ec.EllipticCurve = _jwk_crv_to_curve[jwk_dict['crv']]

    if _jwk_curves[key_curve.name]['alg'] != jwk_dict['alg']:
        raise ValueError(f"EC Key Curve: {key_curve.name} "
                         f"and JWK Hash Algorithm {jwk_dict['alg']} mismatch: ")

    return ec.derive_private_key(conv.int_from_bytes(conv.bytes_from_b64(jwk_dict['d'])),
                                 key_curve)


def _ec_pubkey_from_jwk(jwk_dict: Dict[str, str]) -> ec.EllipticCurvePublicKey:
    _jwk_crv_to_curve = {
        'P-256': SECP256R1(),
        'P-384': SECP384R1(),
        'P-521': SECP521R1()
    }

    key_curve = _jwk_crv_to_curve[jwk_dict['crv']]

    if _jwk_curves[key_curve.name]['alg'] != jwk_dict['alg']:
        raise ValueError(f"EC Key Curve: {key_curve.name} "
                         f"and JWK Hash Algorithm {jwk_dict['alg']} mismatch: ")

    x = conv.int_from_bytes(conv.bytes_from_b64(jwk_dict['x']))
    y = conv.int_from_bytes(conv.bytes_from_b64(jwk_dict['y']))
    pub_nums = ec.EllipticCurvePublicNumbers(x, y, key_curve)
    return pub_nums.public_key()


def _rsa_privkey_to_jwk(key: rsa.RSAPrivateKey, rsa_padding=_RSAPadding.PSS,
                        hash_alg=SHA256()) -> Dict[str, str]:
    if key.key_size < 2048:
        raise ValueError(f"RSA Key too short {key.key_size}")

    if rsa_padding == _RSAPadding.PSS:
        alg = 'PS'
    else:
        alg = 'RS'

    alg += hash_alg.name[3:]

    pub_num = key.public_key().public_numbers()
    priv_num = key.private_numbers()

    jwk_dict = {
        'kty': 'RSA',
        'alg': alg,
        "key_ops": ["sign", "verify"],
        'e': conv.int_to_b64(pub_num.e),
        'n': conv.int_to_b64(pub_num.n),
        'd': conv.int_to_b64(priv_num.d),
        'p': conv.int_to_b64(priv_num.p),
        'q': conv.int_to_b64(priv_num.q),
        'dp': conv.int_to_b64(priv_num.dmp1),
        'dq': conv.int_to_b64(priv_num.dmq1),
        'qi': conv.int_to_b64(priv_num.iqmp)
    }
    return jwk_dict


def _rsa_pubkey_to_jwk(key: rsa.RSAPublicKey, rsa_padding=_RSAPadding.PSS,
                       hash_alg=SHA256()) -> Dict[str, str]:
    if key.key_size < 2048:
        raise ValueError(f"RSA Key too short {key.key_size}")

    if rsa_padding == _RSAPadding.PSS:
        alg = 'PS'
    else:
        alg = 'RS'

    alg += hash_alg.name[3:]

    pub_num = key.public_numbers()
    jwk_dict = {
        'kty': 'RSA',
        'alg': alg,
        "key_ops": ["verify"],
        'e': conv.int_to_b64(pub_num.e),
        'n': conv.int_to_b64(pub_num.n),
    }
    return jwk_dict


def _rsa_privkey_from_jwk(jwk_dict: Dict[str, Any]) -> rsa.RSAPrivateKey:
    pub_num = rsa.RSAPublicNumbers(conv.int_from_b64(jwk_dict['e']),
                                   conv.int_from_b64(jwk_dict['n']))
    priv_num = rsa.RSAPrivateNumbers(
        conv.int_from_b64(jwk_dict['p']),
        conv.int_from_b64(jwk_dict['q']),
        conv.int_from_b64(jwk_dict['d']),
        conv.int_from_b64(jwk_dict['dp']),
        conv.int_from_b64(jwk_dict['dq']),
        conv.int_from_b64(jwk_dict['qi']),
        pub_num
    )
    return priv_num.private_key()


def _rsa_pubkey_from_jwk(jwk_dict: Dict[str, Any]) -> rsa.RSAPublicKey:
    pub_num = rsa.RSAPublicNumbers(conv.int_from_b64(jwk_dict['e']),
                                   conv.int_from_b64(jwk_dict['n']))
    return pub_num.public_key()


def _hmac_to_jwk(key: bytes, hash_alg=SHA256()) -> Dict[str, str]:
    if len(key) < hash_alg.digest_size:
        raise ValueError("Not a Valid HMAC key and alg: "
                         "keysize too small for the given hash")

    jwk_dict = {
        'kty': 'oct',
        'alg': 'HS' + hash_alg.name[3:],
        'key_ops': ["sign", "verify"],
        'k': conv.bytes_to_b64(key)
    }
    return jwk_dict


def _rsa_jwt_signer(jwk: Dict[str, str]) -> Callable[[Dict[str, str]], str]:
    if not all(item in jwk for item in ('alg', 'kty')) and jwk['kty'] != 'RSA':
        raise ValueError("Invalid RSA JWK")

    privkey = _rsa_privkey_from_jwk(jwk)

    hash_alg = _parse_hash_alg('sha' + jwk['alg'][2:])

    if jwk['alg'][:2] == 'PS':
        rsa_padding = _RSAPadding.PSS
    elif jwk['alg'][:2] == 'RS':
        rsa_padding = _RSAPadding.PKCS1v15
    else:
        raise ValueError("Unrecognized RSA Padding Algorithm")

    if rsa_padding == _RSAPadding.PSS:
        rsa_pad = padding.PSS(mgf=padding.MGF1(hash_alg),
                              salt_length=hash_alg.digest_size)
    else:
        rsa_pad = padding.PKCS1v15()

    header = {
        'typ': 'JWT',
        'alg': jwk['alg'],
        'kid': jwk['kid']
    }

    header_enc = conv.doc_to_b64(header)

    def _signer(payload: Dict[str: str]) -> str:
        payload_enc = conv.doc_to_b64(payload)
        head_payload = f'{header_enc}.{payload_enc}'
        sig = privkey.sign(head_payload.encode(), rsa_pad, hash_alg)
        return f'{head_payload}.{conv.bytes_to_b64(sig)}'

    return _signer


def _rsa_jwt_verifier(
        rsa_jwk: Dict[str, str],
) -> Callable[[str, bool], Tuple[bool, Dict[str, str]]]:
    if not all(item in rsa_jwk for item in ('alg', 'kty')) and rsa_jwk['kty'] != 'RSA':
        raise ValueError("Invalid RSA JWK")

    pubkey = _rsa_pubkey_from_jwk(rsa_jwk)

    hash_alg = _parse_hash_alg('sha' + rsa_jwk['alg'][2:])

    if rsa_jwk['alg'][:2] == 'PS':
        rsa_padding = _RSAPadding.PSS
    elif rsa_jwk['alg'][:2] == 'RS':
        rsa_padding = _RSAPadding.PKCS1v15
    else:
        raise ValueError("Unrecognized RSA Padding Algorithm")

    if rsa_padding == _RSAPadding.PSS:
        rsa_pad = padding.PSS(mgf=padding.MGF1(hash_alg),
                              salt_length=hash_alg.digest_size)
    else:
        rsa_pad = padding.PKCS1v15()

    def _verifier(token: str, raise_errors=False) -> Tuple[bool, Dict[str, str]]:
        header_enc, payload_enc, sig_enc = token.split('.')
        payload = conv.doc_from_b64(payload_enc)

        header = conv.doc_from_b64(header_enc)
        if header['alg'] != rsa_jwk['alg']:
            if raise_errors:
                raise JWKAlgorithmMismatch(
                    f"Mismatch token and key and token alg: "
                    f"{header['alg']} != {rsa_jwk['alg']}")
            else:
                return False, payload
        try:
            sig = conv.bytes_from_b64(sig_enc)
            pubkey.verify(sig, f'{header_enc}.{payload_enc}'.encode(),
                          rsa_pad, hash_alg)
            return True, payload
        except (InvalidSignature, binascii.Error):
            if raise_errors:
                raise InvalidSignature(f"Invalid signature string "
                                       f"for payload {json.dumps(payload)}")
            else:
                return False, payload

    return _verifier


def _ec_jwt_signer(jwk: Dict[str, str]) -> Callable[[Dict[str, str]], str]:
    if not all(item in jwk for item in ('alg', 'kty')) and jwk['kty'] != 'EC':
        raise ValueError("Invalid EC JWK")

    if jwk['alg'] not in ('ES256', 'ES384', 'ES512'):
        raise ValueError("Invalid EC Hashing Alg")

    privkey = _ec_privkey_from_jwk(jwk)

    hash_alg = _parse_hash_alg('sha' + jwk['alg'][2:])

    header = {
        'typ': 'JWT',
        'alg': jwk['alg']
    }

    ks = int(ceil(privkey.key_size / 8))

    header_enc = conv.doc_to_b64(header)

    def _signer(payload: Dict[str: str]) -> str:
        payload_enc = conv.doc_to_b64(payload)
        head_payload = f'{header_enc}.{payload_enc}'
        sig = privkey.sign(head_payload.encode(), ec.ECDSA(hash_alg))
        return f'{head_payload}.{conv.ec_sig_der_to_raw_b64(sig, byte_size=ks)}'

    return _signer


def _ec_jwt_verifier(
        ec_jwk: Dict[str, str]) -> Callable[[str, bool], Tuple[bool, Dict[str, str]]]:
    if not all(item in ec_jwk for item in ('alg', 'kty')) and ec_jwk['kty'] != 'EC':
        raise ValueError("Invalid EC JWK")

    if ec_jwk['alg'] not in ('ES256', 'ES384', 'ES512'):
        raise ValueError("Invalid EC Hashing Alg")

    pubkey = _ec_pubkey_from_jwk(ec_jwk)

    hash_alg = _parse_hash_alg('sha' + ec_jwk['alg'][2:])

    def _verifier(token: str, raise_errors=False) -> Tuple[bool, Dict[str, str]]:
        header_enc, payload_enc, sig_enc = token.split('.')
        payload = conv.doc_from_b64(payload_enc)
        header = conv.doc_from_b64(header_enc)

        if header['alg'] != ec_jwk['alg']:
            if raise_errors:
                raise JWKAlgorithmMismatch(
                    f"Mismatch token and key and token alg: "
                    f"{header['alg']} != {ec_jwk['alg']}")
            else:
                return False, payload

        try:
            sig = conv.ec_sig_der_from_raw_b64(sig_enc)
            pubkey.verify(sig, f'{header_enc}.{payload_enc}'.encode(), ec.ECDSA(hash_alg))
            return True, payload
        except (InvalidSignature, binascii.Error):
            if raise_errors:
                raise InvalidSignature(f"Invalid signature string "
                                       f"for payload {json.dumps(payload)}")
            else:
                return False, payload

    return _verifier


def _hmac_jwt_signer(jwk) -> Callable[[Dict[str, str]], str]:
    if not all(item in jwk for item in ('kty', 'alg', 'k')) or \
            jwk['kty'] != 'oct':
        raise RuntimeError("Invalid HMAC JWK")

    h_alg = _parse_hash_alg('sha' + jwk['alg'][2:])
    key = conv.bytes_from_b64(jwk['k'])

    if len(key) < h_alg.digest_size:
        raise ValueError("Not a Valid HMAC key and alg: "
                         "keysize too small for the given hash")

    header = {
        'typ': 'JWT',
        'alg': jwk['alg'],
        'kid': jwk['kid']
    }

    header_enc = conv.doc_to_b64(header)

    def _signer(payload: Dict[str, str]) -> str:
        h = hmac.HMAC(key, h_alg)
        payload_enc = conv.doc_to_b64(payload)
        head_payload = f'{header_enc}.{payload_enc}'
        h.update(head_payload.encode())
        return f'{head_payload}.{conv.bytes_to_b64(h.finalize())}'

    return _signer


def _hmac_jwt_verifier(
        hmac_jwk: Dict[str, str]) -> Callable[[str, bool], Tuple[bool, Dict[str, str]]]:
    if not all(item in hmac_jwk for item in ('kty', 'alg', 'k')) or \
            hmac_jwk['kty'] != 'oct':
        raise RuntimeError("Invalid HMAC JWK")

    h_alg = _parse_hash_alg('sha' + hmac_jwk['alg'][2:])
    key = conv.bytes_from_b64(hmac_jwk['k'])

    if len(key) < h_alg.digest_size:
        raise ValueError("Not a Valid HMAC key and alg: "
                         "keysize too small for the given hash")

    def _verifier(token: str, raise_errors=False) -> Tuple[bool, Dict[str, str]]:
        h = hmac.HMAC(key, h_alg)
        header_enc, payload_enc, sig_enc = token.split('.')

        payload = conv.doc_from_b64(payload_enc)
        header = conv.doc_from_b64(header_enc)
        if header['alg'] != hmac_jwk['alg']:
            if raise_errors:
                raise JWKAlgorithmMismatch(
                    f"Mismatch token and key and token alg: "
                    f"{header['alg']} != {hmac_jwk['alg']}")
            else:
                return False, payload

        h.update(f'{header_enc}.{payload_enc}'.encode())

        try:
            signature = conv.bytes_from_b64(sig_enc)
            h.verify(signature)
            return True, payload
        except (InvalidSignature, binascii.Error):
            if raise_errors:
                raise InvalidSignature(f"Invalid signature string "
                                       f"for payload {json.dumps(payload)}")
            else:
                return False, payload

    return _verifier
