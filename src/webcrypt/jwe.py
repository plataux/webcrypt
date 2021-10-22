# https://datatracker.ietf.org/doc/html/rfc7518#section-3.1

from __future__ import annotations

import enum

from typing import Dict, Any, Union, Optional, Tuple
from math import ceil

import os
import logging

import secrets
from random import choice

from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, SECP384R1, SECP521R1
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap

from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import GCM
from cryptography.hazmat.primitives.ciphers.base import Cipher

import webcrypt.convert as conv
import webcrypt.exceptions as tex

from uuid import uuid4

from pydantic import BaseModel, validator

import zlib

jwe_kty = Union[ec.EllipticCurvePrivateKey,
                rsa.RSAPrivateKey, rsa.RSAPublicKey, bytes]


class JWE_Header(BaseModel):
    """
    Pydantic Model to store, validate and serialize JWE during encryption and decryption
    operations
    """

    class EPK(BaseModel):
        """
        Pydantic Model to Validate and Serialize epk data (Ephemeral Public Key) during
        ECDH-ES Key agreement process

        :cvar kty: is the key type, and is always set to "EC" in this case

        """
        kty: str = "EC"
        crv: str
        x: str
        y: str

        @validator('crv')
        def _val_crv(cls, crv):
            if crv not in ('P-256', 'P-384', 'P-521'):
                raise ValueError("Invalid EC curve for the JOSE spec")
            return crv

        @validator('kty')
        def _val_kty(cls, kty):
            if kty != 'EC':
                raise ValueError(f"Invalid kty for ECDH: {kty}")
            return kty

    alg: Optional[str]
    enc: Optional[str]
    kid: Optional[str]

    zip: Optional[str]

    iv: Optional[str]
    tag: Optional[str]

    apu: Optional[str]
    apv: Optional[str]

    epk: Optional["JWE_Header.EPK"]

    @validator('alg')
    def _val_alg(cls, alg):
        if alg not in ['RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256', 'dir',
                       'A128KW', 'A192KW', 'A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
                       'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW']:
            raise ValueError("Invalid Algorithm")
        return alg

    @validator('enc')
    def _val_enc(cls, enc):
        if enc not in ('A128GCM', 'A192GCM', 'A256GCM'):
            raise ValueError("Invalid JWE Encryption Algorithm")
        return enc


JWE_Header.update_forward_refs()


class JWE:
    class Algorithm(enum.Enum):

        # RSA Key Wrapping of cek
        RSA1_5 = 'RSA1_5'
        RSA_OAEP = 'RSA-OAEP'
        RSA_OAEP_256 = 'RSA-OAEP-256'

        # Direct Encryption
        DIR = "dir"

        # wrapping a cek with a 128, 192, 256 bit key. No additional Headers
        A128KW = "A128KW"
        A192KW = "A192KW"
        A256KW = "A256KW"

        # wrapping the cek with 128, 192, 256 bit key, adding the "iv" and "tag" JWT Headers
        A128GCMKW = "A128GCMKW"
        A192GCMKW = "A192GCMKW"
        A256GCMKW = "A256GCMKW"

        # ECDH Ephemeral Static Key Key Derivation between two parties
        ECDH_ES = "ECDH-ES"

        # ECDH-ES with key wrapping
        ECDH_ES_A128KW = "ECDH-ES+A128KW"
        ECDH_ES_A192KW = "ECDH-ES+A192KW"
        ECDH_ES_A256KW = "ECDH-ES+A256KW"

    class Encryption(enum.Enum):
        A128GCM = 'A128GCM'
        A192GCM = 'A192GCM'
        A256GCM = 'A256GCM'

    @staticmethod
    def gcm_encrypt(key: bytes, auth_data: bytes, data: bytes) -> Tuple[bytes, bytes, bytes]:
        iv = os.urandom(12)

        # Construct an AES-GCM Cipher object with the given key and a
        # randomly generated IV.
        encryptor = Cipher(
            AES(key),
            GCM(iv),
        ).encryptor()

        # associated_data will be authenticated but not encrypted,
        # it must also be passed in on decryption.
        encryptor.authenticate_additional_data(auth_data)

        # Encrypt the plaintext and get the associated ciphertext.
        # GCM does not require padding.
        ciphertext = encryptor.update(data) + encryptor.finalize()

        return iv, ciphertext, encryptor.tag

    @staticmethod
    def gcm_decrypt(key: bytes, auth_data: bytes,
                    iv: bytes, ciphertext: bytes, tag: bytes) -> bytes:
        # Construct a Cipher object, with the key, iv, and additionally the
        # GCM tag used for authenticating the message.
        decryptor = Cipher(
            AES(key),
            GCM(iv, tag),
        ).decryptor()

        # We put associated_data back in or the tag will fail to verify
        # when we finalize the decryptor.
        decryptor.authenticate_additional_data(auth_data)

        # Decryption gets us the authenticated plaintext.
        # If the tag does not match an InvalidTag exception will be raised.
        return decryptor.update(ciphertext) + decryptor.finalize()

    @staticmethod
    def concat_kdf(
            shared_key: bytes,
            jwe_alg: str = 'A128GCM',
            apu: str = 'Alice',
            apv: str = 'Bob',
            hash_rounds: int = 1) -> bytes:
        """
        https://datatracker.ietf.org/doc/html/rfc7518#appendix-C

        :param shared_key:
        :param jwe_alg:
        :param apu:
        :param apv:
        :param hash_rounds:
        :return:
        """

        if hash_rounds < 1:
            raise ValueError("key derivation requires at lease one hash round")

        keylen = int(JWE._aes_alg_size[jwe_alg] * 8)

        hash_alg = hashes.SHA256()

        conc = []

        conc += list(hash_rounds.to_bytes(4, "big"))  # round
        conc += list(shared_key)  # shared key, also known as "Z"
        conc += list(len(jwe_alg).to_bytes(4, "big")) + list(jwe_alg.encode())
        conc += list(len(apu).to_bytes(4, "big")) + list(apu.encode())  # PartyUInfo
        conc += list(len(apv).to_bytes(4, "big")) + list(apv.encode())  # PartyVInfo
        conc += list(keylen.to_bytes(4, "big"))

        current_hash = conc

        for r in range(hash_rounds):
            hasher = hashes.Hash(hash_alg)
            hasher.update(bytes(conc))
            current_hash = hasher.finalize()

        return current_hash[:(keylen // 8)]

    @staticmethod
    def decode_header(token: str):
        return conv.doc_from_b64(token.split('.')[0])

    _AESKW = ("A128KW", "A192KW", "A256KW")
    _AESGSMKW = ("A128GCMKW", "A192GCMKW", "A256GCMKW")
    _RSA = ('RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256')
    _ECDH = ("ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW")

    _RSA_Padding = {
        "RSA1_5": padding.PKCS1v15(),
        "RSA-OAEP": padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        ),
        "RSA-OAEP-256": padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    }

    _aes_alg_size = {
        'A128GCMKW': 16,
        'A192GCMKW': 24,
        'A256GCMKW': 32,
        'A128KW': 16,
        'A192KW': 24,
        'A256KW': 32,
        'A128GCM': 16,
        'A192GCM': 24,
        'A256GCM': 32
    }

    _jose_curves = {
        'secp256r1': 'P-256',
        'secp384r1': 'P-384',
        'secp521r1': 'P-521',
    }

    def _init_dir_alg(self, key: bytes, jwe_alg, jwe_enc):
        size_to_enc = {
            16: JWE.Encryption.A128GCM,
            24: JWE.Encryption.A192GCM,
            32: JWE.Encryption.A256GCM
        }

        if key is None and jwe_enc is None:
            key = os.urandom(16)
            jwe_enc = JWE.Encryption.A128GCM

        if key is None and jwe_enc is not None:
            key = os.urandom(JWE._aes_alg_size[jwe_enc.value])

        if key is not None:
            key_len = len(key)

            if key_len not in size_to_enc:
                raise ValueError("Invalid AES key size")

            if jwe_enc is not None and jwe_enc != size_to_enc[key_len]:
                raise ValueError("Invalid JWE Encryption with the given key size")

        self._key = key
        self._alg = jwe_alg.value
        self._enc = jwe_enc.name
        self._kty = 'oct'

    def _init_aeskw_alg(self, key: bytes,
                        jwe_alg: Algorithm, jwe_enc: Encryption):

        if key is None:
            key = os.urandom(JWE._aes_alg_size[jwe_alg.value])

        key_len = len(key)

        if JWE._aes_alg_size[jwe_alg.value] != key_len:
            raise ValueError("AESKW Algorithm not valid with given key")

        if jwe_enc is None:
            jwe_enc = JWE.Encryption.A128GCM

        self._key = key
        self._alg = jwe_alg.value
        self._enc = jwe_enc.value
        self._cek_size = JWE._aes_alg_size[jwe_enc.value]
        self._kty = 'oct'

    def _init_rsa_alg(self, key: Optional[rsa.RSAPrivateKey | rsa.RSAPublicKey],
                      jwe_alg: Algorithm, jwe_enc: Encryption):

        if key is None:
            key = rsa.generate_private_key(65537, 2048)

        if key.key_size < 2048:
            raise ValueError("RSA key must be 2048 bits or larger")

        if isinstance(key, rsa.RSAPrivateKey):
            self._rsa_privkey = key
            self._rsa_pubkey = key.public_key()
        elif isinstance(key, rsa.RSAPublicKey):
            self._rsa_privkey = None
            self._rsa_pubkey = key
        else:
            raise ValueError(f"Invalid RSA Key: {type(key)}")

        if not isinstance(jwe_alg, JWE.Algorithm):
            raise ValueError("Invalid RSA Encryption Padding Algorithm")

        if jwe_enc is None:
            jwe_enc = JWE.Encryption.A128GCM

        if not isinstance(jwe_enc, JWE.Encryption):
            raise ValueError("Invalid cek Encryption spec")

        self._alg = jwe_alg.value
        self._enc = jwe_enc.value
        self._cek_size = JWE._aes_alg_size[jwe_enc.value]
        self._kty = 'RSA'

    def _init_ecdh_alg(self, key: Optional[ec.EllipticCurvePrivateKey],
                       jwe_alg: Algorithm, jwe_enc: Encryption):
        if key is None:
            key = ec.generate_private_key(ec.SECP256R1())

        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise ValueError("Invalid EC Key object")

        if key.curve.name not in JWE._jose_curves:
            raise ValueError(f"JOSE Standard doesn't include this curve: {key.curve.name}")

        if jwe_enc is None:
            jwe_enc = JWE.Encryption.A128GCM

        ks = int(ceil(key.curve.key_size / 8))

        self._ec_privkey = key
        self._ec_pubkey = key.public_key()
        pub_nums = self._ec_pubkey.public_numbers()

        self._ec_x = conv.bytes_to_b64(conv.int_to_bytes(pub_nums.x, byte_size=ks))
        self._ec_y = conv.bytes_to_b64(conv.int_to_bytes(pub_nums.y, byte_size=ks))
        self._ec_d = conv.bytes_to_b64(conv.int_to_bytes(key.private_numbers().private_value,
                                                         byte_size=ks))

        self._alg = jwe_alg.value
        self._enc = jwe_enc.value
        self._kty = 'EC'
        self._crv = JWE._jose_curves[key.curve.name]

        self._jwe_header.epk = {
            'kty': self._kty,
            'crv': self._crv,
            'x': self._ec_x,
            'y': self._ec_y
        }

    __slots__ = ('_key', '_alg', '_enc', '_kty', '_kid',
                 '_cek_size', '_jwe_header',
                 '_rsa_privkey', '_rsa_pubkey',
                 '_crv', '_ec_privkey', '_ec_pubkey',
                 '_apu', '_apv', '_ec_x', '_ec_y', '_ec_d', '_party_u')

    def __init__(self,
                 algorithm: Optional[Algorithm] = None,
                 encryption: Optional[Encryption] = None,
                 key: Optional[jwe_kty] = None,
                 kid: Optional[str] = None):

        if algorithm is None:
            algorithm = JWE.Algorithm.A128KW

        self._alg = None
        self._enc = None
        self._key = None

        self._apu = None
        self._apv = None
        self._party_u: Optional[bool] = None

        self._jwe_header: JWE_Header = JWE_Header()

        if algorithm == JWE.Algorithm.DIR:
            self._init_dir_alg(key, algorithm, encryption)

        elif algorithm.value in JWE._AESKW + JWE._AESGSMKW:
            self._init_aeskw_alg(key, algorithm, encryption)

        elif algorithm.value in JWE._RSA:
            self._init_rsa_alg(key, algorithm, encryption)

        elif algorithm.value in JWE._ECDH:
            self._init_ecdh_alg(key, algorithm, encryption)

        else:
            raise ValueError("Unknown JWE Algorithm")

        self._kid = kid if kid is not None else str(uuid4())

        self._jwe_header.alg = self._alg
        self._jwe_header.enc = self._enc
        self._jwe_header.kid = self._kid

    @classmethod
    def from_jwk(cls, jwk: Dict[str, Any]):

        if 'use' in jwk and (_use := jwk['use']) != 'enc':
            raise ValueError(
                f"not declare to be use for encryption/decryption purposes: {_use}")

        if not all(item in jwk for item in ('kty', 'alg', 'enc')):
            raise ValueError("Invalid JWK format")

        algo_map = {_ja.value: _ja for _ja in list(JWE.Algorithm)}
        enc_map = {_ja.value: _ja for _ja in list(JWE.Encryption)}

        alg_name = jwk['alg']
        enc_name = jwk['enc']

        if alg_name not in algo_map:
            raise ValueError(f"Invalid JWK alg: {alg_name}")

        if enc_name not in enc_map:
            raise ValueError(f"Invalid JWK enc: {enc_name}")

        alg = algo_map[alg_name]
        enc = enc_map[enc_name]

        kty = jwk['kty']

        if kty not in ('RSA', 'EC', 'oct'):
            raise ValueError(f"Invalid JWK kty {jwk['alg']}")

        if 'kid' in jwk:
            kid = jwk['kid']
        else:
            kid = None

        if kty == 'RSA':
            if alg_name not in JWE._RSA:
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
                return cls(algorithm=alg, encryption=enc, key=priv_num.private_key(), kid=kid)
            else:
                return cls(algorithm=alg, encryption=enc, key=pub_num.public_key(), kid=kid)

        elif kty == 'EC':
            if alg_name not in JWE._ECDH:
                raise ValueError("JWS Algorithm not compatible with this key")

            if 'crv' not in jwk:
                raise ValueError("the crv parameter is missing and is required")

            _crv_to_curve = {
                'P-256': SECP256R1(),
                'P-384': SECP384R1(),
                'P-521': SECP521R1(),
            }

            if (_crv := jwk['crv']) not in _crv_to_curve:
                raise ValueError(f"invalid EC curve: {_crv}")

            key_curve = _crv_to_curve[_crv]

            if all(comp in jwk for comp in ('x', 'y', 'd')):
                ec_key = ec.derive_private_key(
                    conv.int_from_bytes(conv.bytes_from_b64(jwk['d'])),
                    key_curve)
                return cls(algorithm=alg, encryption=enc, key=ec_key, kid=kid)
            else:
                raise ValueError("Invalid EC Key in JWE keys - Must be a private key")

        elif kty == 'oct':
            if 'k' in jwk:
                return cls(algorithm=alg, encryption=enc,
                           key=conv.bytes_from_b64(jwk['k']), kid=kid)
            else:
                raise ValueError("Invalid HMAC JWK")

    def to_jwk(self) -> Dict[str, Any]:
        jwk_dict = {
            'use': 'enc',
            'kid': self._kid,
            'kty': self._kty,
            'alg': self._alg,
            'enc': self._enc,
        }

        if self._kty == 'RSA':
            if self._rsa_privkey is not None:
                pub_num = self._rsa_pubkey.public_numbers()
                priv_num = self._rsa_privkey.private_numbers()

                jwk_dict = {
                    **jwk_dict,
                    "key_ops": ["wrapKey", "unwrapKey"],
                    'e': conv.int_to_b64(pub_num.e),
                    'n': conv.int_to_b64(pub_num.n),
                    'd': conv.int_to_b64(priv_num.d),
                    'p': conv.int_to_b64(priv_num.p),
                    'q': conv.int_to_b64(priv_num.q),
                    'dp': conv.int_to_b64(priv_num.dmp1),
                    'dq': conv.int_to_b64(priv_num.dmq1),
                    'qi': conv.int_to_b64(priv_num.iqmp)
                }

            else:
                pub_num = self._rsa_pubkey.public_numbers()

                jwk_dict = {
                    **jwk_dict,
                    "key_ops": ["wrapKey"],
                    'e': conv.int_to_b64(pub_num.e),
                    'n': conv.int_to_b64(pub_num.n),
                }

        elif self._kty == 'oct':

            if self._alg == 'dir':
                jwk_dict['key_ops'] = ["encrypt", "decrypt"]
            elif self._alg in JWE._AESKW + JWE._AESGSMKW:
                jwk_dict['key_ops'] = ["wrapKey", "unwrapKey"]

            jwk_dict['k'] = conv.bytes_to_b64(self._key)

        elif self._kty == 'EC':
            jwk_dict['key_ops'] = ["deriveBits", "deriveKey"]
            jwk_dict['crv'] = self._crv
            jwk_dict['x'] = self._ec_x
            jwk_dict['y'] = self._ec_y
            jwk_dict['d'] = self._ec_d

        return jwk_dict

    @classmethod
    def random_jwe(cls) -> "JWE":
        alg_list = list(JWE.Algorithm)
        enc_list = list(JWE.Encryption)

        alg_list.remove(JWE.Algorithm.ECDH_ES)
        alg_list.remove(JWE.Algorithm.ECDH_ES_A128KW)
        alg_list.remove(JWE.Algorithm.ECDH_ES_A192KW)
        alg_list.remove(JWE.Algorithm.ECDH_ES_A256KW)

        rand_alg: JWE.Algorithm = choice(alg_list)
        rand_enc = choice(enc_list)

        if (alg := rand_alg.value) == 'dir':
            rand_key = os.urandom(JWE._aes_alg_size[rand_enc.value])
        elif alg in JWE._RSA:
            _m = [2, 3, 4]
            rand_key = rsa.generate_private_key(65537, 1024 * choice(_m))
        else:
            rand_key = os.urandom(JWE._aes_alg_size[alg])

        return cls(rand_alg, rand_enc, rand_key)

    @property
    def key(self) -> jwe_kty:
        if self._kty == 'oct':
            return self._key

        elif self._kty == 'RSA':
            return self._rsa_privkey or self._rsa_pubkey

        elif self._kty == 'EC':
            return self._ec_privkey

        else:
            raise RuntimeError("unreachable expected")

    @property
    def kid(self):
        return self._kid

    @property
    def kty(self):
        return self._kty

    @property
    def alg(self):
        return self._alg

    def encrypt(self, plaintext: bytes, compress=False,
                extra_header=Optional[Dict[str, Any]]):
        if self._alg == 'dir':
            return self._encrypt_dir(plaintext, compress, extra_header)

        if self._alg in JWE._AESKW:
            return self._encrypt_aeskw(plaintext, compress, extra_header)

        if self._alg in JWE._AESGSMKW:
            return self._encrypt_gcmkw(plaintext, compress, extra_header)

        elif self._alg in JWE._RSA:
            return self._encrypt_rsa(plaintext, compress, extra_header)

        elif self._alg in JWE._ECDH:
            return self._encrypt_ecdh(plaintext, compress, extra_header)

    def decrypt(self, token: str) -> bytes:
        sp = token.split('.')
        if len(sp) != 5:
            raise tex.InvalidToken("Invalid JWE structure upon splitting")

        try:
            header_enc = sp[0]
            header = JWE_Header(**conv.doc_from_b64(header_enc))
        except Exception as ex:
            raise tex.InvalidToken(f"JWE Header could not be parsed: {ex}")

        if header.alg != self._alg:
            raise tex.AlgoMismatch(
                "JWE alg of this token is not compatible with this JWK")

        if header.enc != self._enc:
            if self._alg == 'dir':
                raise tex.AlgoMismatch(
                    f"Algo DIR: Encryption type mismatch: {header.enc}, {self._enc}")
            else:
                logging.warning(
                    f"Encryption type mismatch: {header.enc}, {self._enc},\n"
                    "However, in none a non-DIR Mode that shouldn't be a problem")

        try:
            cek_wrapped = conv.bytes_from_b64(sp[1])
            iv = conv.bytes_from_b64(sp[2])
            ciphertext = conv.bytes_from_b64(sp[3])
            tag = conv.bytes_from_b64(sp[4])
        except Exception as ex:
            raise tex.InvalidToken(
                f"one or more of the JWE segments are base64 invalid: {ex}")

        if header.alg == 'dir':
            return self._decrypt_dir(header_enc, header,
                                     iv, ciphertext, tag)
        elif header.alg in JWE._AESKW:
            return self._decrypt_aeskw(header_enc, header, cek_wrapped,
                                       iv, ciphertext, tag)
        elif header.alg in JWE._AESGSMKW:
            return self._decrypt_gcmkw(header_enc, header, cek_wrapped,
                                       iv, ciphertext, tag)
        elif header.alg in JWE._RSA:
            return self._decrypt_rsa(header_enc, header, cek_wrapped,
                                     iv, ciphertext, tag)
        elif header.alg in JWE._ECDH:
            return self._decrypt_ecdh(header_enc, header, cek_wrapped,
                                      iv, ciphertext, tag)
        else:
            raise NotImplemented("Other Algos not yet implemented")

    def party_u_generate(self, apu: str) -> Dict[str, Any]:
        if self._kty != 'EC':
            raise ValueError("This is not an EC Curve key")

        self._key = None
        self._apv = None
        self._apu = conv.bytes_to_b64(f'{apu}:{secrets.token_urlsafe(16)}'.encode())
        self._party_u = True

        jwk_dict = {
            'alg': self._alg,
            'enc': self._enc,
            'apu': self._apu,
            'epk': {
                'kty': self._kty,
                'crv': self._crv,
                'x': self._ec_x,
                'y': self._ec_y,
            }
        }

        JWE_Header(**jwk_dict)  # validate
        return jwk_dict

    def party_v_import(self, ecdh_params: dict,
                       apv: str, override_alg=True) -> Dict[str, Any]:
        if self._kty != 'EC':
            raise ValueError("This is not an EC Curve key")

        px = JWE_Header(**ecdh_params)

        if px.alg not in ("ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"):
            raise ValueError("Invalid ECDH-ES Algorithm")

        px.apv = conv.bytes_to_b64(f'{apv}:{secrets.token_urlsafe(16)}'.encode())

        self._derive_key(px, override_alg)

        self._party_u = False
        self._apu = px.apu
        self._apv = px.apv

        px.epk = self._jwe_header.epk
        return px.dict(exclude_none=True)

    def party_u_import(self, ecdh_params: dict):
        px = JWE_Header(**ecdh_params)

        if px.alg not in ("ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"):
            raise ValueError("Invalid ECDH-ES Algorithm")

        self._derive_key(px, False)
        self._apv = px.apv

    def _encrypt_dir(self, plaintext: bytes, compress=True,
                     extra_header=Optional[Dict[str, Any]]) -> str:
        header = self._jwe_header.copy()
        header.zip = 'DEF' if compress else None

        if compress:
            ziptext = zlib.compress(plaintext)
        else:
            ziptext = plaintext

        # will be used as the associated data
        if extra_header is not None:
            hx = {**extra_header, **header.dict(exclude_none=True)}
        else:
            hx = header.dict(exclude_none=True)
        header_b64 = conv.doc_to_b64(hx)
        iv, ciphertext, tag = JWE.gcm_encrypt(self._key, header_b64.encode(), ziptext)

        jwt = f'{header_b64}..{conv.bytes_to_b64(iv)}.' \
              f'{conv.bytes_to_b64(ciphertext)}.{conv.bytes_to_b64(tag)}'

        return jwt

    def _decrypt_dir(self, header_enc, header, iv, ciphertext, tag):
        plaintext = JWE.gcm_decrypt(self._key, header_enc.encode(), iv, ciphertext, tag)
        if header.zip is not None:
            plaintext = zlib.decompress(plaintext)
        return plaintext

    def _encrypt_aeskw(self, plaintext: bytes, compress=True,
                       extra_header: Optional[Dict[str, Any]] = None) -> str:
        header = self._jwe_header.copy()
        header.zip = 'DEF' if compress else None

        if compress:
            ziptext = zlib.compress(plaintext)
        else:
            ziptext = plaintext

        cek = os.urandom(self._cek_size)

        # will be used as the associated data
        if extra_header is not None:
            hx = {**extra_header, **header.dict(exclude_none=True)}
        else:
            hx = header.dict(exclude_none=True)

        header_b64 = conv.doc_to_b64(hx)

        iv, ciphertext, tag = JWE.gcm_encrypt(cek, header_b64.encode(), ziptext)

        cek_wrapped = aes_key_wrap(self._key, cek)

        jwt = f'{header_b64}.{conv.bytes_to_b64(cek_wrapped)}.{conv.bytes_to_b64(iv)}.' \
              f'{conv.bytes_to_b64(ciphertext)}.{conv.bytes_to_b64(tag)}'

        return jwt

    def _decrypt_aeskw(self, header_enc, header, cek_wrapped, iv, ciphertext, tag):
        cek = aes_key_unwrap(self._key, cek_wrapped)

        plaintext = JWE.gcm_decrypt(cek, header_enc.encode(), iv, ciphertext, tag)

        if header.zip is not None:
            plaintext = zlib.decompress(plaintext)

        return plaintext

    def _encrypt_gcmkw(self, plaintext: bytes, compress=True,
                       extra_header=Optional[Dict[str, Any]]) -> str:
        header: JWE_Header = self._jwe_header.copy()
        header.zip = 'DEF' if compress else None

        if compress:
            ziptext = zlib.compress(plaintext)
        else:
            ziptext = plaintext

        cek = os.urandom(self._cek_size)

        cek_iv, cek_wrapped, cek_tag = JWE.gcm_encrypt(self._key, b'', cek)
        header.iv, header.tag = conv.bytes_to_b64(cek_iv), conv.bytes_to_b64(cek_tag)

        # will be used as the associated data
        if extra_header is not None:
            hx = {**extra_header, **header.dict(exclude_none=True)}
        else:
            hx = header.dict(exclude_none=True)
        header_b64 = conv.doc_to_b64(hx)

        iv, ciphertext, tag = JWE.gcm_encrypt(cek, header_b64.encode(), ziptext)

        jwt = f'{header_b64}.{conv.bytes_to_b64(cek_wrapped)}.{conv.bytes_to_b64(iv)}.' \
              f'{conv.bytes_to_b64(ciphertext)}.{conv.bytes_to_b64(tag)}'

        return jwt

    def _decrypt_gcmkw(self, header_enc, header, cek_wrapped, iv, ciphertext, tag):
        try:
            cek_iv = conv.bytes_from_b64(header.iv)
            cek_tag = conv.bytes_from_b64(header.tag)
        except Exception as ex:
            raise tex.InvalidToken(
                f"one or both of the cek iv, cek tag missing/invalid {ex}")

        cek = JWE.gcm_decrypt(self._key, b'', cek_iv, cek_wrapped, cek_tag)

        plaintext = JWE.gcm_decrypt(cek, header_enc.encode(), iv, ciphertext, tag)

        if header.zip is not None:
            plaintext = zlib.decompress(plaintext)

        return plaintext

    def _encrypt_rsa(self, plaintext: bytes, compress=True,
                     extra_header=Optional[Dict[str, Any]]):
        header = self._jwe_header.copy()
        header.zip = 'DEF' if compress else None

        if compress:
            ziptext = zlib.compress(plaintext)
        else:
            ziptext = plaintext

        cek = os.urandom(self._cek_size)

        cek_wrapped = self._rsa_pubkey.encrypt(
            cek,
            JWE._RSA_Padding[self._alg]
        )

        if extra_header is not None:
            hx = {**extra_header, **header.dict(exclude_none=True)}
        else:
            hx = header.dict(exclude_none=True)
        header_b64 = conv.doc_to_b64(hx)

        iv, ciphertext, tag = JWE.gcm_encrypt(cek, header_b64.encode(), ziptext)

        jwt = f'{header_b64}.{conv.bytes_to_b64(cek_wrapped)}.{conv.bytes_to_b64(iv)}.' \
              f'{conv.bytes_to_b64(ciphertext)}.{conv.bytes_to_b64(tag)}'

        return jwt

    def _decrypt_rsa(self, header_enc, header, cek_wrapped, iv, ciphertext, tag):

        if not self._rsa_privkey:
            raise ValueError("This JWK is not capable of RSA decryption "
                             "as it is a Public Key")

        cek = self._rsa_privkey.decrypt(
            cek_wrapped,
            JWE._RSA_Padding[self._alg]
        )

        plaintext = JWE.gcm_decrypt(cek, header_enc.encode(), iv, ciphertext, tag)

        if header.zip is not None:
            plaintext = zlib.decompress(plaintext)

        return plaintext

    def _encrypt_ecdh(self, plaintext: bytes, compress=True,
                      extra_header=Optional[Dict[str, Any]]) -> str:
        if None in (self._key, self._apu, self._apv, self._party_u):
            raise ValueError("ECDH-ES Key derivation hasn't happened yet")

        header: JWE_Header = self._jwe_header.copy()
        header.zip = 'DEF' if compress else None

        header.apu = self._apu
        header.apv = self._apv

        if compress:
            ziptext = zlib.compress(plaintext)
        else:
            ziptext = plaintext

        if self._alg == 'ECDH-ES':
            cek = self._key
            cek_wrapped = b''
        else:
            cek = os.urandom(JWE._aes_alg_size[self._enc])
            cek_wrapped = aes_key_wrap(self._key, cek)

        # will be used as the associated data
        if extra_header is not None:
            hx = {**extra_header, **header.dict(exclude_none=True)}
        else:
            hx = header.dict(exclude_none=True)
        header_b64 = conv.doc_to_b64(hx)

        iv, ciphertext, tag = JWE.gcm_encrypt(cek, header_b64.encode(), ziptext)

        jwt = f'{header_b64}.{conv.bytes_to_b64(cek_wrapped)}.{conv.bytes_to_b64(iv)}.' \
              f'{conv.bytes_to_b64(ciphertext)}.{conv.bytes_to_b64(tag)}'

        return jwt

    def _decrypt_ecdh(self, header_enc, header: JWE_Header,
                      cek_wrapped, iv, ciphertext, tag):

        if self._party_u is None:
            raise RuntimeError("No key exchange/derivation happened yet")

        if self._party_u and self._apu != header.apu:
            raise tex.TokenException("Incorrect apu value recieved in token")

        elif self._apv is not None and self._apv != header.apv:
            raise tex.TokenException("Incorrect apu value recieved in token")

        if self._key is None:
            self.party_u_import(header.dict())

        if self._alg == 'ECDH-ES':
            cek = self._key
        else:
            cek = aes_key_unwrap(self._key, cek_wrapped)

        plaintext = JWE.gcm_decrypt(cek, header_enc.encode(), iv, ciphertext, tag)

        if header.zip is not None:
            plaintext = zlib.decompress(plaintext)

        return plaintext

    def _derive_key(self, px: JWE_Header, override_alg=True):
        if self._crv != px.epk.crv:
            raise ValueError("Incompatible curve among ECDH peers")

        if override_alg:
            self._alg = px.alg
            self._enc = px.enc
            self._jwe_header.alg = px.alg
            self._jwe_header.enc = px.enc
        else:
            if px.alg != self._alg or px.enc != self._enc:
                raise ValueError("Incompatible alg and/or enc with peer")

        _jwk_crv_to_curve = {
            'P-256': SECP256R1(),
            'P-384': SECP384R1(),
            'P-521': SECP521R1()
        }

        key_curve = _jwk_crv_to_curve[px.epk.crv]

        x = conv.int_from_bytes(conv.bytes_from_b64(px.epk.x))
        y = conv.int_from_bytes(conv.bytes_from_b64(px.epk.y))
        pub_nums = ec.EllipticCurvePublicNumbers(x, y, key_curve)
        peer_key = pub_nums.public_key()

        if peer_key.curve.name != self._ec_privkey.curve.name:
            raise ValueError("Incompatible curve among ECDH peers")

        if self._alg == 'ECDH-ES':
            jwe_alg = self._enc
        else:
            enc_map = {
                "ECDH-ES+A128KW": 'A128GCM',
                "ECDH-ES+A192KW": 'A192GCM',
                "ECDH-ES+A256KW": 'A256GCM'
            }
            jwe_alg = enc_map[self._alg]

        self._key = JWE.concat_kdf(
            self._ec_privkey.exchange(ec.ECDH(), peer_key),
            jwe_alg,
            conv.bytes_from_b64(px.apu).decode(),
            conv.bytes_from_b64(px.apv).decode()
        )
