# https://datatracker.ietf.org/doc/html/rfc7518#section-3.1

from __future__ import annotations

import enum

from typing import Dict, Any, Union, Optional
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
import webcrypt.exceptions as tex

from cryptography.exceptions import InvalidSignature

from uuid import uuid4

jws_kty = Union[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey,
                rsa.RSAPrivateKey, rsa.RSAPublicKey, bytes]


class JWS:
    class Algorithm(enum.Enum):
        HS256 = SHA256()
        HS384 = SHA384()
        HS512 = SHA512()
        RS256 = {'hash_alg': SHA256(), "rsa_padding": "PKCS1v15"}
        RS384 = {'hash_alg': SHA384(), "rsa_padding": "PKCS1v15"}
        RS512 = {'hash_alg': SHA512(), "rsa_padding": "PKCS1v15"}
        PS256 = {'hash_alg': SHA256(), "rsa_padding": "PSS"}
        PS384 = {'hash_alg': SHA384(), "rsa_padding": "PSS"}
        PS512 = {'hash_alg': SHA512(), "rsa_padding": "PSS"}
        ES256 = {'hash_alg': SHA256(), 'curve': SECP256R1()}
        ES384 = {'hash_alg': SHA384(), 'curve': SECP384R1()}
        ES512 = {'hash_alg': SHA512(), 'curve': SECP521R1()}

    _jwk_curves = {
        'secp256r1': {'alg': 'ES256', 'crv': 'P-256'},
        'secp384r1': {'alg': 'ES384', 'crv': 'P-384'},
        'secp521r1': {'alg': 'ES512', 'crv': 'P-521'},
    }

    _HMAC = ('HS256', 'HS384', 'HS512')
    _EC = ('ES256', 'ES384', 'ES512')
    _RSA = ('RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512')

    _ec_types = (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)
    _rsa_types = (rsa.RSAPrivateKey, rsa.RSAPublicKey)

    @staticmethod
    def decode_header(token: str) -> Dict[str, Any]:
        return conv.doc_from_b64(token.split('.')[0])

    def _init_hmac(self):
        self._hash_alg = self._alg.value

        if self._key is None:
            self._hmac_key = os.urandom(self._hash_alg.digest_size)
        elif isinstance(self._key, bytes):
            if len(self._key) < self._hash_alg.digest_size:
                raise ValueError("HMAC key needs to be larger than Hash Digest")
            else:
                self._hmac_key = self._key
        else:
            raise ValueError("Invalid HMAC key: expected bytes object")

        self._kty = 'oct'
        self._can_sign = True
        self._hmac = hmac.HMAC(self._hmac_key, self._alg.value)

        del self._key

    def _init_rsa(self):
        if self._key is None:
            self._key = rsa.generate_private_key(65537, 2048)

        if not isinstance(self._key, JWS._rsa_types):
            raise ValueError("Invalid RSA Key")

        if self._key.key_size < 2048:
            raise ValueError("RSA key size too small - breakable")

        self._hash_alg = self._alg.value['hash_alg']

        if self._alg.value['rsa_padding'] == "PSS":
            self._rsa_pad = padding.PSS(mgf=padding.MGF1(self._hash_alg),
                                        salt_length=self._hash_alg.digest_size)
        else:
            self._rsa_pad = padding.PKCS1v15()

        self._kty = 'RSA'

        if isinstance(self._key, rsa.RSAPrivateKey):
            self._rsa_privkey = self._key
            self._rsa_pubkey = self._key.public_key()
            self._can_sign = True
        else:
            self._rsa_privkey = None
            self._rsa_pubkey = self._key
            self._can_sign = False

        del self._key

    def _init_ec(self):
        if self._key is None:
            self._key = ec.generate_private_key(self._alg.value['curve'])

        if not isinstance(self._key, JWS._ec_types):
            raise ValueError("Invalid EC Key")

        if self._key.curve.name not in JWS._jwk_curves:
            raise ValueError("This EC curve is not valid for the JOSE spec")

        if JWS._jwk_curves[self._key.curve.name]['alg'] != self._alg.name:
            raise ValueError("This JWS Hash algo is not compatible with this key curve: "
                             f"{self._key.curve.name} with {self._alg.name}")

        self._kty = 'EC'
        self._crv = JWS._jwk_curves[self._key.curve.name]['crv']
        self._hash_alg = self._alg.value['hash_alg']
        self._ec_size = int(ceil(self._key.key_size / 8))

        if isinstance(self._key, ec.EllipticCurvePrivateKey):
            self._ec_privkey = self._key
            self._ec_pubkey = self._key.public_key()
            self._can_sign = True
        else:
            self._ec_privkey = None
            self._ec_pubkey = self._key
            self._can_sign = False

        del self._key

    __slots__ = ('_key', '_header', '_hmac_key', '_hmac',
                 '_alg', '_kid', '_kty', '_hash_alg',
                 '_ec_pubkey', '_ec_privkey', '_ec_size', '_crv', '_can_sign',
                 '_rsa_pubkey', '_rsa_privkey', '_rsa_pad')

    def __init__(self, algorithm: Optional[JWS.Algorithm] = None,
                 key_obj: Optional[jws_kty] = None,
                 kid: Optional[str] = None):

        if algorithm is None and key_obj is None:
            algorithm = JWS.Algorithm.ES256

        self._alg = algorithm
        self._key = key_obj

        if self._alg.name in JWS._HMAC:
            self._init_hmac()
        elif self._alg.name in JWS._RSA:
            self._init_rsa()
        elif self._alg.name in JWS._EC:
            self._init_ec()
        else:
            raise ValueError("Unrecognized JWS Algo")

        self._kid = kid or str(uuid4())

        self._header = {
            'alg': self._alg.name,
            'kty': self._kty,
            'kid': self._kid,
        }

    def to_jwk(self) -> Dict[str, str]:
        jwk_dict = {
            "use": 'sig',
            'kid': self._kid,
            'kty': self._kty,
            'alg': self._alg.name,
        }

        if self._kty == 'oct':
            jwk_dict['key_ops'] = ['sign', 'verify']
            jwk_dict['k'] = conv.bytes_to_b64(self._hmac_key)

        elif self._kty == 'RSA':
            pub_num = self._rsa_pubkey.public_numbers()
            jwk_dict = {
                **jwk_dict,
                "key_ops": ["verify"],
                'e': conv.int_to_b64(pub_num.e),
                'n': conv.int_to_b64(pub_num.n),
            }

            if self._can_sign:
                priv_num = self._rsa_privkey.private_numbers()
                jwk_dict = {
                    **jwk_dict,
                    'd': conv.int_to_b64(priv_num.d),
                    'p': conv.int_to_b64(priv_num.p),
                    'q': conv.int_to_b64(priv_num.q),
                    'dp': conv.int_to_b64(priv_num.dmp1),
                    'dq': conv.int_to_b64(priv_num.dmq1),
                    'qi': conv.int_to_b64(priv_num.iqmp)
                }

                jwk_dict['key_ops'] = ['sign', 'verify']

        elif self._kty == 'EC':
            pub_num = self._ec_pubkey.public_numbers()
            jwk_dict = {
                **jwk_dict,
                'crv': self._crv,
                "key_ops": ["verify"],
                'x': conv.bytes_to_b64(conv.int_to_bytes(
                    pub_num.x, byte_size=self._ec_size)),
                'y': conv.bytes_to_b64(conv.int_to_bytes(
                    pub_num.y, byte_size=self._ec_size)),
            }

            if self._can_sign:
                pv = self._ec_privkey.private_numbers().private_value

                jwk_dict['d'] = conv.bytes_to_b64(conv.int_to_bytes(
                    pv, byte_size=self._ec_size))

                jwk_dict['key_ops'] = ['sign', 'verify']

        return jwk_dict

    @classmethod
    def from_jwk(cls, jwk: Dict[str, Any]):

        if 'use' in jwk and (_use := jwk['use']) != 'sig':
            raise ValueError(
                f"not declare to be use for encryption/decryption purposes: {_use}")

        if not all(item in jwk for item in ('kty', 'alg')):
            raise ValueError("Invalid JWK format")

        algo_map = {_ja.name: _ja for _ja in list(JWS.Algorithm)}

        alg_name = jwk['alg']

        if alg_name not in algo_map:
            raise ValueError(f"Invalid JWK alg: {alg_name}")

        alg = algo_map[alg_name]
        kty = jwk['kty']

        if kty not in ('RSA', 'EC', 'oct'):
            raise ValueError(f"Invalid JWK kty {jwk['alg']}")

        if 'kid' in jwk:
            kid = jwk['kid']
        else:
            kid = None

        if kty == 'RSA':
            if alg_name not in JWS._RSA:
                raise ValueError(
                    f"kty not compatible with algorithm: {kty} with {alg_name}")

            if all(comp in jwk for comp in ('e', 'n')):
                pub_num = rsa.RSAPublicNumbers(conv.int_from_b64(jwk['e']),
                                               conv.int_from_b64(jwk['n']))
            else:
                raise ValueError("invalid RSA key")

            if all(comp in jwk for comp in ('p', 'q', 'd', 'dp', 'dq', 'qi')):
                priv_num = rsa.RSAPrivateNumbers(
                    conv.int_from_b64(jwk['p']),
                    conv.int_from_b64(jwk['q']),
                    conv.int_from_b64(jwk['d']),
                    conv.int_from_b64(jwk['dp']),
                    conv.int_from_b64(jwk['dq']),
                    conv.int_from_b64(jwk['qi']),
                    pub_num
                )
                return cls(alg, priv_num.private_key(), kid)
            else:
                return cls(alg, pub_num.public_key(), kid)

        elif kty == 'EC':
            if alg_name not in JWS._EC:
                raise ValueError("JWS Algorithm not compatible with this key")

            _crv_to_alg = {
                'P-256': 'ES256',
                'P-384': 'ES384',
                'P-521': 'ES512',
            }

            if 'crv' in jwk:
                if (_crv := jwk['crv']) not in _crv_to_alg:
                    raise ValueError(f"Unrecognized/Unsupported EC Curve {_crv}")

                elif _crv_to_alg[_crv] != alg_name:
                    raise ValueError(
                        f"EC crv and JWS alg incompatible: {_crv} with {alg_name}")

            key_curve = alg.value['curve']

            if all(comp in jwk for comp in ('x', 'y', 'd')):
                ec_key = ec.derive_private_key(
                    conv.int_from_bytes(conv.bytes_from_b64(jwk['d'])),
                    key_curve)
                return cls(alg, ec_key, kid)
            elif all(comp in jwk for comp in ('x', 'y')):
                x = conv.int_from_bytes(conv.bytes_from_b64(jwk['x']))
                y = conv.int_from_bytes(conv.bytes_from_b64(jwk['y']))
                pub_nums = ec.EllipticCurvePublicNumbers(x, y, key_curve)
                return cls(alg, pub_nums.public_key(), kid)
            else:
                raise ValueError("Invalid EC Key")

        elif kty == 'oct':
            if 'k' in jwk:
                return cls(alg, conv.bytes_from_b64(jwk['k']), kid)
            else:
                raise ValueError("Invalid HMAC JWK")

    def to_pem(self) -> str:
        if self._kty == 'oct':
            return conv.bytes_to_b64(self._hmac_key)
        elif self._kty == 'RSA':
            if self._can_sign:
                return self._rsa_privkey.private_bytes(ser.Encoding.PEM,
                                                       ser.PrivateFormat.PKCS8,
                                                       ser.NoEncryption()).decode()
            else:
                return self._rsa_pubkey.public_bytes(
                    ser.Encoding.PEM,
                    ser.PublicFormat.SubjectPublicKeyInfo).decode()
        elif self._kty == 'EC':
            if self._can_sign:
                return self._ec_privkey.private_bytes(
                    ser.Encoding.PEM,
                    ser.PrivateFormat.PKCS8,
                    ser.NoEncryption()).decode()
            else:
                return self._ec_pubkey.public_bytes(
                    ser.Encoding.PEM,
                    ser.PublicFormat.SubjectPublicKeyInfo).decode()

    @classmethod
    def from_pem(cls, key_pem: str | bytes,
                 algorithm: Algorithm = None, kid=None) -> "JWS":
        if isinstance(key_pem, str):
            key_pem = key_pem.encode()

        if b'PRIVATE' in key_pem:
            return cls(algorithm, ser.load_pem_private_key(key_pem, password=None), kid)
        elif b'PUBLIC' in key_pem:
            return cls(algorithm, ser.load_pem_public_key(key_pem), kid)
        elif algorithm in JWS._HMAC or algorithm is None:
            return cls(algorithm, conv.bytes_from_b64(key_pem.decode()), kid)
        else:
            raise ValueError("Invalid PEM file")

    def sign(self, payload: bytes,
             extra_header: Optional[Dict[str, Any]] = None) -> str:

        if not self._can_sign:
            raise RuntimeError("This key cannot sign tokens")

        if isinstance(extra_header, dict):
            head = {**extra_header, **self._header}
            header_b64: str = conv.doc_to_b64(head)
        else:
            header_b64 = conv.doc_to_b64(self._header)

        head_payload_b64 = f'{header_b64}.{conv.bytes_to_b64(payload)}'
        if self._alg.name in JWS._HMAC:
            return self._hmac_sign(head_payload_b64)
        elif self._alg.name in JWS._EC:
            return self._ec_sign(head_payload_b64)
        elif self._alg.name in JWS._RSA:
            return self._rsa_sign(head_payload_b64)
        else:
            raise NotImplementedError("Should be unreachable")

    def verify(self, token: str) -> bytes:
        sp = token.split('.')

        lx = len(sp)
        if lx != 3:
            raise tex.InvalidToken(f"Invalid Token Structure: {lx} segments")

        try:
            header = conv.doc_from_b64(sp[0])
            alg = header['alg']
        except Exception as ex:
            raise tex.InvalidToken(f"Invalid Token Header: {ex}")

        if alg != self._alg.name:
            raise tex.AlgoMismatch(
                f"Algorithm Mismatch | Invalid : {alg} != {self._alg.name}")

        try:
            sig: bytes = conv.bytes_from_b64(sp[2])
        except Exception as ex:
            raise tex.InvalidSignature(f"could not parse signature: {ex}")

        if alg in JWS._HMAC:
            return self._hmac_verify(sp[0], sp[1], sig)
        if alg in JWS._EC:
            return self._ec_verify(sp[0], sp[1], sig)
        if alg in JWS._RSA:
            return self._rsa_verify(sp[0], sp[1], sig)
        else:
            raise NotImplementedError("This should be unreachable")

    @classmethod
    def random_jws(cls) -> "JWS":
        J = JWS.Algorithm

        def _hmac_key():
            hx = [(SHA256, J.HS256), (SHA384, J.HS384), (SHA512, J.HS512)]
            h = choice(hx)
            return cls(h[1], os.urandom(h[0].digest_size))

        def _rsa_key():
            hx = [J.PS256, J.PS384, J.PS512, J.RS256, J.RS384, J.RS512]
            ks = [k * 1024 for k in (2, 3, 4)]
            return cls(choice(hx), rsa.generate_private_key(65537, choice(ks)))

        def _ec_key():
            _c = [J.ES256, J.ES384, J.ES512]
            return cls(choice(_c))

        _tx = [
            _hmac_key,
            _rsa_key,
            _ec_key
        ]

        return choice(_tx)()

    def do_hash(self, data: str | bytes) -> bytes:
        if isinstance(data, str):
            data = data.encode()
        hasher = hashes.Hash(self._hash_alg)
        hasher.update(data)
        return hasher.finalize()

    @property
    def key(self) -> jws_kty:
        if self._kty == 'oct':
            return self._hmac_key
        elif self._kty == 'RSA':
            return self._rsa_privkey or self._rsa_pubkey
        elif self._kty == 'EC':
            return self._ec_privkey or self._ec_pubkey

    @property
    def hash_alg(self):
        return self._hash_alg

    @property
    def alg(self):
        return self._alg.name

    @property
    def kid(self):
        return self._kid

    def _hmac_sign(self, head_payload) -> str:
        h = self._hmac.copy()
        h.update(head_payload.encode())
        return f'{head_payload}.{conv.bytes_to_b64(h.finalize())}'

    def _hmac_verify(self, header_enc, payload_enc, sig: bytes) -> bytes:
        h = self._hmac.copy()
        h.update(f'{header_enc}.{payload_enc}'.encode())
        try:
            h.verify(sig)
        except InvalidSignature as ex:
            raise tex.InvalidSignature(ex)
        return conv.bytes_from_b64(payload_enc)

    def _ec_sign(self, head_payload) -> str:
        sig = self._ec_privkey.sign(head_payload.encode(), ec.ECDSA(self._hash_alg))
        return f'{head_payload}.{conv.ec_sig_der_to_raw_b64(sig, byte_size=self._ec_size)}'

    def _ec_verify(self, header_enc, payload_enc, sig: bytes) -> bytes:
        try:
            sig_der = conv.ec_sig_der_from_raw(sig)
            self._ec_pubkey.verify(sig_der,
                                   f'{header_enc}.{payload_enc}'.encode(),
                                   ec.ECDSA(self._hash_alg))
        except InvalidSignature as ex:
            raise tex.InvalidSignature(ex)
        return conv.bytes_from_b64(payload_enc)

    def _rsa_sign(self, head_payload) -> str:
        sig = self._rsa_privkey.sign(head_payload.encode(), self._rsa_pad, self._hash_alg)
        return f'{head_payload}.{conv.bytes_to_b64(sig)}'

    def _rsa_verify(self, header_enc, payload_enc, sig) -> bytes:
        try:
            self._rsa_pubkey.verify(sig, f'{header_enc}.{payload_enc}'.encode(),
                                    self._rsa_pad, self._hash_alg)
        except InvalidSignature as ex:
            raise tex.InvalidSignature(ex)
        return conv.bytes_from_b64(payload_enc)
