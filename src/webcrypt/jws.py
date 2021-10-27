############################################################################
# Copyright 2021 Plataux LLC                                               #
#                                                                          #
# Licensed under the Apache License, Version 2.0 (the "License");          #
# you may not use this file except in compliance with the License.         #
# You may obtain a copy of the License at                                  #
#                                                                          #
#    https://www.apache.org/licenses/LICENSE-2.0                           #
#                                                                          #
# Unless required by applicable law or agreed to in writing, software      #
# distributed under the License is distributed on an "AS IS" BASIS,        #
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. #
# See the License for the specific language governing permissions and      #
# limitations under the License.                                           #
############################################################################

"""
Implementation of the JOSE spec at https://datatracker.ietf.org/doc/html/rfc7518#section-3.1

"""

from __future__ import annotations

import enum

from typing import Dict, Any, Union, Optional, Tuple, List
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
        HS256 = "HS256"
        HS384 = "HS384"
        HS512 = "HS512"
        RS256 = "RS256"
        RS384 = "RS384"
        RS512 = "RS512"
        PS256 = "PS256"
        PS384 = "PS384"
        PS512 = "PS512"
        ES256 = "ES256"
        ES384 = "ES384"
        ES512 = "ES512"

    alg_to_curve: Dict[str, Any] = {
        'ES256': {'curve': SECP256R1()},
        'ES384': {'curve': SECP384R1()},
        'ES512': {'curve': SECP521R1()},
    }

    curve_to_alg: Dict[str, Any] = {
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
    def get_hash_alg(jws_alg: str | Algorithm) -> hashes.HashAlgorithm:
        if isinstance(jws_alg, JWS.Algorithm):
            jws_alg = jws_alg.value

        if (_alg := jws_alg[2:]) == '256':
            return SHA256()
        elif _alg == '384':
            return SHA384()
        elif _alg == '512':
            return SHA512()
        else:
            raise ValueError("unexpected JWS Algo")

    @staticmethod
    def decode_header(token: str) -> Dict[str, Any]:
        return conv.doc_from_b64(token.split('.')[0])

    def _init_hmac(self):
        self._hash_alg: hashes.HashAlgorithm = JWS.get_hash_alg(self._alg)

        self._key: Optional[jws_kty]

        if self._key is None:
            self._hmac_key: bytes = os.urandom(self._hash_alg.digest_size)
        elif isinstance(self._key, bytes):
            if len(self._key) < self._hash_alg.digest_size:
                raise ValueError("HMAC key needs to be larger than Hash Digest")
            else:
                self._hmac_key = self._key
        else:
            raise ValueError("Invalid HMAC key: expected bytes object")

        self._kty = 'oct'
        self._can_sign = True
        self._hmac = hmac.HMAC(self._hmac_key, self._hash_alg)

        del self._key

    def _init_rsa(self):
        if self._key is None:
            self._key = rsa.generate_private_key(65537, 2048)

        if not isinstance(self._key, JWS._rsa_types):
            raise ValueError("Invalid RSA Key")

        if self._key.key_size < 2048:
            raise ValueError("RSA key size too small - breakable")

        self._hash_alg = JWS.get_hash_alg(self._alg)

        if self._alg.value[:2] == "PS":
            self._rsa_pad: Any = padding.PSS(mgf=padding.MGF1(self._hash_alg),
                                             salt_length=self._hash_alg.digest_size)
        else:
            self._rsa_pad = padding.PKCS1v15()

        self._kty = 'RSA'

        if isinstance(self._key, rsa.RSAPrivateKey):
            self._rsa_privkey: Union[rsa.RSAPrivateKey, None] = self._key
            self._rsa_pubkey: rsa.RSAPublicKey = self._key.public_key()
            self._can_sign = True
        else:
            self._rsa_privkey = None
            self._rsa_pubkey = self._key
            self._can_sign = False

        del self._key

    def _init_ec(self):
        if self._key is None:
            self._key = ec.generate_private_key(JWS.alg_to_curve[self._alg.value]['curve'])

        if not isinstance(self._key, JWS._ec_types):
            raise ValueError("Invalid EC Key")

        if self._key.curve.name not in JWS.curve_to_alg:
            raise ValueError("This EC curve is not valid for the JOSE spec")

        if JWS.curve_to_alg[self._key.curve.name]['alg'] != self._alg.name:
            raise ValueError("This JWS Hash algo is not compatible with this key curve: "
                             f"{self._key.curve.name} with {self._alg.name}")

        self._kty = 'EC'
        self._crv = JWS.curve_to_alg[self._key.curve.name]['crv']
        self._hash_alg = JWS.get_hash_alg(self._alg)
        self._ec_size = int(ceil(self._key.key_size / 8))

        if isinstance(self._key, ec.EllipticCurvePrivateKey):
            self._ec_privkey: Union[ec.EllipticCurvePrivateKey, None] = self._key
            self._ec_pubkey: ec.EllipticCurvePublicKey = self._key.public_key()
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

    def __init__(self, algorithm: Union[JWS.Algorithm, None],
                 key_obj: Optional[jws_kty] = None,
                 kid: Optional[str] = None):

        if algorithm is None:
            algorithm = JWS.Algorithm.ES256

        self._alg: JWS.Algorithm = algorithm
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

    def public_jwk(self) -> Dict[str, Any]:

        if self._kty == 'oct':
            raise ValueError("JWK with kty oct cannot be a public jwk")

        jwk_dict: Dict[str, Any] = {
            "use": 'sig',
            'kid': self._kid,
            'kty': self._kty,
            'alg': self._alg.name,
        }

        if self._kty == 'RSA':
            pub_num = self._rsa_pubkey.public_numbers()
            jwk_dict = {
                **jwk_dict,
                "key_ops": ["verify"],
                'e': conv.int_to_b64(pub_num.e),
                'n': conv.int_to_b64(pub_num.n),
            }

        if self._kty == 'EC':
            ec_pub_num = self._ec_pubkey.public_numbers()
            jwk_dict = {
                **jwk_dict,
                "key_ops": ["verify"],
                'crv': self._crv,
                'x': conv.bytes_to_b64(conv.int_to_bytes(
                    ec_pub_num.x, byte_size=self._ec_size)),
                'y': conv.bytes_to_b64(conv.int_to_bytes(
                    ec_pub_num.y, byte_size=self._ec_size)),
            }

        return jwk_dict

    def to_jwk(self) -> Dict[str, str]:
        jwk_dict: Dict[str, Any] = {
            "use": 'sig',
            'kid': self._kid,
            'kty': self._kty,
            'alg': self._alg.name,
        }

        if self._kty == 'oct':
            jwk_dict['key_ops'] = ['sign', 'verify']
            jwk_dict['k'] = conv.bytes_to_b64(self._hmac_key)

        elif self._kty == 'RSA':

            kops = ["verify"]

            pub_num = self._rsa_pubkey.public_numbers()
            jwk_dict = {
                **jwk_dict,
                "key_ops": kops,
                'e': conv.int_to_b64(pub_num.e),
                'n': conv.int_to_b64(pub_num.n),
            }

            if self._rsa_privkey is not None:
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

                kops.insert(0, "sign")

        elif self._kty == 'EC':
            kops = ["verify"]
            ec_pub_num = self._ec_pubkey.public_numbers()
            jwk_dict = {
                **jwk_dict,
                "key_ops": kops,
                'crv': self._crv,
                'x': conv.bytes_to_b64(conv.int_to_bytes(
                    ec_pub_num.x, byte_size=self._ec_size)),
                'y': conv.bytes_to_b64(conv.int_to_bytes(
                    ec_pub_num.y, byte_size=self._ec_size)),
            }

            if self._ec_privkey is not None:
                pv = self._ec_privkey.private_numbers().private_value

                jwk_dict['d'] = conv.bytes_to_b64(conv.int_to_bytes(
                    pv, byte_size=self._ec_size))

                kops.insert(0, "sign")

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

            key_curve = JWS.alg_to_curve[alg.value]['curve']

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
            if self._rsa_privkey is not None:
                return self._rsa_privkey.private_bytes(ser.Encoding.PEM,
                                                       ser.PrivateFormat.PKCS8,
                                                       ser.NoEncryption()).decode()
            else:
                return self._rsa_pubkey.public_bytes(
                    ser.Encoding.PEM,
                    ser.PublicFormat.SubjectPublicKeyInfo).decode()
        elif self._kty == 'EC':
            if self._ec_privkey is not None:
                return self._ec_privkey.private_bytes(
                    ser.Encoding.PEM,
                    ser.PrivateFormat.PKCS8,
                    ser.NoEncryption()).decode()
            else:
                return self._ec_pubkey.public_bytes(
                    ser.Encoding.PEM,
                    ser.PublicFormat.SubjectPublicKeyInfo).decode()
        else:
            raise RuntimeError("should be an unreachable statement")

    @classmethod
    def from_pem(cls, key_pem: str | bytes,
                 algorithm: Union[Algorithm, None] = None, kid=None) -> "JWS":
        if isinstance(key_pem, str):
            key_pem = key_pem.encode()

        if b'PRIVATE' in key_pem:
            priv_key = ser.load_pem_private_key(key_pem, password=None)
            if not isinstance(priv_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
                raise ValueError("Invalid Private Key")
            return cls(algorithm, priv_key, kid)

        elif b'PUBLIC' in key_pem:
            pub_key = ser.load_pem_public_key(key_pem)
            if not isinstance(pub_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
                raise ValueError("Invalid Public Key")
            return cls(algorithm, pub_key, kid)

        elif algorithm is None or algorithm.name in JWS._HMAC:
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
            hx: List[Tuple[hashes.HashAlgorithm, JWS.Algorithm]] = [
                (SHA256(), J.HS256), (SHA384(), J.HS384), (SHA512(), J.HS512)
            ]
            h = choice(hx)
            ks: int = h[0].digest_size
            return cls(h[1], os.urandom(ks))

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

        jwk = choice(_tx)()

        if not isinstance(jwk, JWS):
            raise RuntimeError("unexpected randomly generated JWS")

        return jwk

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
        else:
            raise RuntimeError("unexpected kty")

    @property
    def privkey(self) -> Union[bytes, rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]:
        if self._kty == 'oct':
            return self._hmac_key
        elif self._kty == 'RSA':
            if self._rsa_privkey is not None:
                return self._rsa_privkey
        elif self._kty == 'EC':
            if self._ec_privkey is not None:
                return self._ec_privkey

        raise RuntimeError("This key is not capable of signing")

    @property
    def pubkey(self) -> Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]:
        if self._kty == 'RSA':
            return self._rsa_pubkey
        elif self._kty == 'EC':
            return self._ec_pubkey
        else:
            raise ValueError("This HMAC JWS object doesn't have a public component")

    @property
    def hash_alg(self) -> hashes.HashAlgorithm:
        return self._hash_alg

    @property
    def alg_name(self) -> str:
        return self._alg.name

    @property
    def kid(self) -> str:
        return self._kid

    @property
    def kty(self) -> str:
        return self._kty

    def __str__(self) -> str:
        privpub = "private" if self._can_sign else "public"
        return f"{self.kty} | {self.alg_name} | {self.kid} | {privpub}"

    def __repr__(self) -> str:
        return str(self)

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
        if self._ec_privkey is not None:
            sig = self._ec_privkey.sign(head_payload.encode(), ec.ECDSA(self._hash_alg))
            return f'{head_payload}.{conv.ec_sig_der_to_raw_b64(sig, byte_size=self._ec_size)}'
        else:
            raise RuntimeError("This EC JWS is not capable of signing - no privkey")

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
        if self._rsa_privkey is not None:
            sig = self._rsa_privkey.sign(head_payload.encode(), self._rsa_pad, self._hash_alg)
            return f'{head_payload}.{conv.bytes_to_b64(sig)}'
        else:
            raise RuntimeError("This RSA JWS is not capable of signing - no privkey")

    def _rsa_verify(self, header_enc, payload_enc, sig) -> bytes:
        try:
            self._rsa_pubkey.verify(sig, f'{header_enc}.{payload_enc}'.encode(),
                                    self._rsa_pad, self._hash_alg)
        except InvalidSignature as ex:
            raise tex.InvalidSignature(ex)
        return conv.bytes_from_b64(payload_enc)
