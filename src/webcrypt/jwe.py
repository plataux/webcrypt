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

# https://datatracker.ietf.org/doc/html/rfc7518#section-3.1

from __future__ import annotations

import enum
import random

from typing import Dict, Any, Union, Optional, Tuple

import os

from random import choice

from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import ec

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers.modes import GCM

from cryptography.hazmat.primitives import serialization as ser

from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap

from cryptography.hazmat.primitives.ciphers.algorithms import AES

from cryptography.hazmat.primitives.constant_time import bytes_eq

import webcrypt.convert as conv
import webcrypt.exceptions as tex

from uuid import uuid4

import pydantic

if int(pydantic.version.VERSION.split('.')[0]) == 2:
    import pydantic.v1 as pydantic
else:
    pass


import zlib

jwe_kty = Union[ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey, rsa.RSAPublicKey, bytes, str]


class JWE_Header(pydantic.BaseModel):
    """
    Pydantic Model to store, validate and serialize JWE during encryption and decryption
    operations
    """

    alg: Optional[str]
    enc: Optional[str]
    kid: Optional[str]

    zip: Optional[str]

    iv: Optional[str]
    tag: Optional[str]

    p2s: Optional[str]
    p2c: Optional[int]

    @pydantic.validator('alg')
    def _val_alg(cls, alg):
        if alg not in ['dir',
                       'RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256',
                       'A128KW', 'A192KW', 'A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
                       "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW"]:
            raise ValueError("Invalid Algorithm")
        return alg

    @pydantic.validator('enc')
    def _val_enc(cls, enc):
        if enc not in ('A128GCM', 'A192GCM', 'A256GCM',
                       "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"):
            raise ValueError("Invalid JWE Encryption Algorithm")
        return enc


JWE_Header.update_forward_refs()


class JWE:
    class Algorithm(enum.Enum):
        # Direct Encryption
        DIR = "dir"

        # wrapping a cek with a 128, 192, 256-bit key. No additional JWT Headers
        A128KW = "A128KW"
        A192KW = "A192KW"
        A256KW = "A256KW"

        # wrapping the cek with 128, 192, 256-bit key, adding the "iv" and "tag" JWT Headers
        A128GCMKW = "A128GCMKW"
        A192GCMKW = "A192GCMKW"
        A256GCMKW = "A256GCMKW"

        # Password Based Encryption
        PBES2_HS256_A128KW = "PBES2-HS256+A128KW"
        PBES2_HS384_A192KW = "PBES2-HS384+A192KW"
        PBES2_HS512_A256KW = "PBES2-HS512+A256KW"

        # RSA Key Wrapping of cek
        RSA1_5 = 'RSA1_5'
        RSA_OAEP = 'RSA-OAEP'
        RSA_OAEP_256 = 'RSA-OAEP-256'

    class Encryption(enum.Enum):
        A128GCM = 'A128GCM'
        A192GCM = 'A192GCM'
        A256GCM = 'A256GCM'

        A128CBC_HS256 = "A128CBC-HS256"
        A192CBC_HS384 = "A192CBC-HS384"
        A256CBC_HS512 = "A256CBC-HS512"

    @staticmethod
    def gcm_encrypt(key: bytes, auth_data: bytes,
                    plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Implementation according to the spec at:
        https://datatracker.ietf.org/doc/html/rfc7518#section-5.3

        :param key: 128, 192 or 256-bit key in byte string form
        :param auth_data: Authenticated Data in byte string form
        :param plaintext: The data to be encrypted in byte string form
        :return: A tuple of the iv, ciphertext, tag all in byte form
        """

        # Use of an IV of size 96 bits is REQUIRED with this algorithm.
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
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        # The requested size of the Authentication Tag output MUST be 128 bits,
        # regardless of the key size.
        assert len(encryptor.tag) == 16

        return iv, ciphertext, encryptor.tag

    @staticmethod
    def gcm_decrypt(key: bytes, auth_data: bytes,
                    iv: bytes, ciphertext: bytes, tag: bytes) -> bytes:
        """
        Implementation according to the spec at:
        https://datatracker.ietf.org/doc/html/rfc7518#section-5.3

        :param key: 128, 192 or 256 AES key in byte string
        :param auth_data: Authenticated data in byte string
        :param iv: Initialization Vector - expecting 96 bits length
        :param ciphertext: encrypted data in bytes
        :param tag: 128 bit tag
        :return: plaintext if decryption is successful

        :raises InvalidToken: if the any of the inputs is invalid, corrupted or tampered with
        """

        try:
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

            ct: bytes = decryptor.update(ciphertext) + decryptor.finalize()
        except Exception as ex:
            raise tex.InvalidToken(f"Could not decrypt token, corrupted or tampered with: {ex}")
        return ct

    @staticmethod
    def cbc_encrypt(comp_key: bytes, auth_data: bytes,
                    plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Implemented according to the spec at:
        https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.2.1


        :param comp_key: Composite Key: the 1st half for HMAC Authentication,
            and the 2nd for Content Encryption
        :param auth_data: Authenticated Data in bytes
        :param plaintext: data to be encrypted in bytes
        :return: a tuple of iv, ciphertext, tag all in bytes format
        """

        if len(comp_key) not in (32, 48, 64):
            raise ValueError("CBC key must be in 32, 48, 64 bytes long")

        key_len = len(comp_key) // 2

        hmac_key = comp_key[:key_len]
        enc_key = comp_key[-key_len:]

        if key_len == 16:
            hash_alg: hashes.HashAlgorithm = hashes.SHA256()
        elif key_len == 24:
            hash_alg = hashes.SHA384()
        elif key_len == 32:
            hash_alg = hashes.SHA512()
        else:
            raise RuntimeError("unexpected key_len value")

        # The IV used is a 128-bit value generated randomly or
        # pseudo-randomly for use in the cipher.
        iv = os.urandom(16)

        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext)
        padded_data += padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # The octet string AL is equal to the number of bits in the
        # Additional Authenticated Data A expressed as a 64-bit unsigned big-endian integer
        al = conv.int_to_bytes(len(auth_data) * 8, order='big', byte_size=8)

        hmac_signer = hmac.HMAC(hmac_key, hash_alg)
        hmac_signer.update(auth_data + iv + ciphertext + al)
        tag = hmac_signer.finalize()[:key_len]

        return iv, ciphertext, tag

    @staticmethod
    def cbc_decrypt(comp_key: bytes, auth_data: bytes,
                    iv: bytes, ciphertext: bytes, tag: bytes) -> bytes:
        """
        Implemented according to the spec at:
        https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.2.2

        :param comp_key: Composite Key: 1st half for HMAC, and 2nd for Content Decryption
        :param auth_data: Authenticated Data in bytes
        :param iv: Initialization Vector in bytes - expecting 128 bit iv
        :param ciphertext: Ciphertext in bytes
        :param tag: Auth tag in bytes
        :return: decrypted plaintext

        :raises InvalidSignature: If the tag is invalid
        :raises InvalidToken: If any of the inputs is invalid, corrupted or tampered with in any way
        """

        if len(comp_key) not in (32, 48, 64):
            raise ValueError("CBC key must be in 32, 36, 64 bytes long")

        key_len = len(comp_key) // 2

        hmac_key = comp_key[:key_len]
        enc_key = comp_key[-key_len:]

        if key_len == 16:
            hash_alg: hashes.HashAlgorithm = hashes.SHA256()
        elif key_len == 24:
            hash_alg = hashes.SHA384()
        elif key_len == 32:
            hash_alg = hashes.SHA512()
        else:
            raise RuntimeError("unexpected key_len value")

        # The octet string AL is equal to the number of bits in the
        # Additional Authenticated Data A expressed as a 64-bit unsigned big-endian integer
        al = conv.int_to_bytes(len(auth_data) * 8, order='big', byte_size=8)

        hmac_signer = hmac.HMAC(hmac_key, hash_alg)
        hmac_signer.update(auth_data + iv + ciphertext + al)

        sig = hmac_signer.finalize()

        if not bytes_eq(sig[:key_len], tag):
            raise tex.InvalidSignature("Tag invalid - Token Fabricated or Tampered With")

        try:
            cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))

            decryptor = cipher.decryptor()
            padded_plain_text = decryptor.update(ciphertext)
            padded_plain_text += decryptor.finalize()
            de_padder = PKCS7(algorithms.AES.block_size).unpadder()
            plaintext: bytes = de_padder.update(padded_plain_text)
            plaintext += de_padder.finalize()

            return plaintext
        except Exception as ex:
            raise tex.TokenException(
                f"Could not decrypt token, corrupted or tampered with: {ex}")

    @staticmethod
    def decode_header(token: str):
        return conv.doc_from_b64(token.split('.')[0])

    _AESKW = ("A128KW", "A192KW", "A256KW")
    _AES_GCM_KW = ("A128GCMKW", "A192GCMKW", "A256GCMKW")
    _PBE = ("PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW")
    _RSA = ('RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256')

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

    _alg_size = {
        'A128KW': 16,
        'A192KW': 24,
        'A256KW': 32,
        'A128GCMKW': 16,
        'A192GCMKW': 24,
        'A256GCMKW': 32,
        'PBES2-HS256+A128KW': 16,
        'PBES2-HS384+A192KW': 24,
        'PBES2-HS512+A256KW': 32,
        'A128GCM': 16,
        'A192GCM': 24,
        'A256GCM': 32,
        'A128CBC-HS256': 32,
        'A192CBC-HS384': 48,
        'A256CBC-HS512': 64
    }

    _enc_size = {
        'A128GCM': 16,
        'A192GCM': 24,
        'A256GCM': 32,
        'A128CBC-HS256': 32,
        'A192CBC-HS384': 48,
        'A256CBC-HS512': 64
    }

    _pbe_hash = {
        "PBES2-HS256+A128KW": hashes.SHA256(),
        "PBES2-HS384+A192KW": hashes.SHA384(),
        "PBES2-HS512+A256KW": hashes.SHA512()
    }

    __slots__ = ('_key', '_alg', '_kty', '_kid',
                 '_jwe_header',
                 '_rsa_privkey', '_rsa_pubkey')

    def __init__(self,
                 algorithm: Algorithm | None = None,
                 key: jwe_kty | None = None,
                 kid: str | None = None):

        if algorithm is None:
            algorithm = JWE.Algorithm.A128KW

        self._jwe_header: JWE_Header = JWE_Header()
        self._alg: JWE.Algorithm = algorithm

        if algorithm == JWE.Algorithm.DIR and (isinstance(key, bytes) or key is None):
            if key is None:
                key = os.urandom(16)

            # both key and jwe_enc are provided
            else:
                key_len = len(key)

                if key_len not in (16, 24, 32, 48, 64):
                    raise ValueError("Invalid AES key size")

            self._key: bytes = key
            self._kty = 'oct'

        elif algorithm.value in JWE._AESKW + JWE._AES_GCM_KW and (
                isinstance(key, bytes) or key is None):
            if key is None:
                key = os.urandom(JWE._alg_size[self._alg.value])

            key_len = len(key)

            if JWE._alg_size[self._alg.value] != key_len:
                raise ValueError("AESKW Algorithm not valid with given key")

            self._key = key
            self._kty = 'oct'

        elif algorithm.value in JWE._RSA and (
                isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)) or key is None):
            if key is None:
                key = rsa.generate_private_key(65537, 2048)

            if key.key_size < 2048:
                raise ValueError("RSA key must be 2048 bits or larger")

            if isinstance(key, rsa.RSAPrivateKey):
                self._rsa_privkey: Union[rsa.RSAPrivateKey, None] = key
                self._rsa_pubkey = key.public_key()
            elif isinstance(key, rsa.RSAPublicKey):
                self._rsa_privkey = None
                self._rsa_pubkey = key
            else:
                raise ValueError(f"Invalid RSA Key: {type(key)}")
            self._key = self._rsa_privkey or self._rsa_pubkey
            self._kty = 'RSA'

        elif algorithm.value in JWE._PBE and (
                isinstance(key, (bytes, str)) or key is None):
            if isinstance(key, str):
                b_key: bytes = key.encode()
            elif isinstance(key, bytes):
                b_key = key
            else:
                b_key = conv.bytes_to_b64(os.urandom(32)).encode()
            self._key = b_key
            self._kty = 'oct'

        else:
            raise ValueError("Unknown JWE Algorithm or invalid key type")

        self._kid = kid if kid is not None else str(uuid4())

        self._jwe_header.alg = self._alg.value
        self._jwe_header.kid = self._kid

    def __str__(self) -> str:
        priv_pub = "private" if self.can_decrypt else "public"
        return f"{self.kty} | {self.alg_name} | {self.kid} | {priv_pub}"

    def __repr__(self) -> str:
        return str(self)

    @classmethod
    def from_jwk(cls, jwk: Dict[str, Any]):
        """
        Load a JWE key from JWK dict format. The following items are required;

        * the "use" element whose value must be ``enc``
        * the "kty", "alg" and "enc" dict keys must be present, and valid for a JWE key

        :param jwk: dict of JWE key parameters
        :return: a valid JWE object based on the provided JWK
        :raises ValueError: if any of the JWK parameters are missing, or invalid
        """

        if 'use' in jwk and (_use := jwk['use']) != 'enc':
            raise ValueError(
                f"not declare to be use for encryption/decryption purposes: {_use}")

        if not all(item in jwk for item in ('kty', 'alg')):
            raise ValueError("Invalid JWK format")

        algo_map = {_ja.value: _ja for _ja in list(JWE.Algorithm)}

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
                return cls(algorithm=alg, key=priv_num.private_key(), kid=kid)
            else:
                return cls(algorithm=alg, key=pub_num.public_key(), kid=kid)

        elif kty == 'EC':
            raise NotImplementedError("EC JWK not implemented yet")

        elif kty == 'oct':
            if 'k' in jwk:
                return cls(algorithm=alg,
                           key=conv.bytes_from_b64(jwk['k']), kid=kid)
            else:
                raise ValueError("Invalid HMAC JWK")

    def to_jwk(self) -> Dict[str, Any]:
        jwk_dict: Dict[str, Any] = {
            'use': 'enc',
            'kid': self._kid,
            'kty': self._kty,
            'alg': self._alg.value,
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

        elif self._kty == 'oct' and self._key is not None:

            if self._alg.value == 'dir':
                jwk_dict['key_ops'] = ["encrypt", "decrypt"]
            elif self._alg.value in JWE._AESKW + JWE._AES_GCM_KW + JWE._PBE:
                jwk_dict['key_ops'] = ["wrapKey", "unwrapKey"]

            jwk_dict['k'] = conv.bytes_to_b64(self._key)

        elif self._kty == 'EC':
            raise NotImplementedError("EC JWK not implemented yet")

        return jwk_dict

    def public_jwk(self):

        if self._kty == 'oct':
            raise ValueError("JWK with kty oct cannot be a public jwk")

        jwk_dict: Dict[str, Any] = {
            'use': 'enc',
            'kid': self._kid,
            'kty': self._kty,
            'alg': self._alg.value,
        }

        if self._kty == 'RSA':
            pub_num = self._rsa_pubkey.public_numbers()
            jwk_dict = {
                **jwk_dict,
                "key_ops": ["wrapKey"],
                'e': conv.int_to_b64(pub_num.e),
                'n': conv.int_to_b64(pub_num.n),
            }

        if self._kty == 'EC':
            raise NotImplementedError("EC JWK not implemented yet")

        return jwk_dict

    def to_pem(self) -> str:
        if self._kty == 'oct' and self._key is not None:
            return conv.bytes_to_b64(self._key)
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
            raise NotImplementedError("EC PEM not implemented yet")
        else:
            raise RuntimeError(f"Unexpected kty: {self._kty}")

    @classmethod
    def from_pem(cls, key_pem: str | bytes,
                 algorithm: Optional[Algorithm] = None,
                 kid=None) -> "JWE":
        if isinstance(key_pem, str):
            key_pem = key_pem.encode()

        if b'PRIVATE' in key_pem:
            priv_key = ser.load_pem_private_key(key_pem, password=None)
            if not isinstance(priv_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
                raise ValueError("Invalid Private Key")
            return cls(algorithm, priv_key, kid)

        elif b'PUBLIC' in key_pem:
            pub_key = ser.load_pem_public_key(key_pem)
            if not isinstance(pub_key, rsa.RSAPublicKey):
                raise ValueError("Invalid Public Key")
            return cls(algorithm, pub_key, kid)

        elif algorithm is None or algorithm.value in [*JWE._AESKW,
                                                      *JWE._AES_GCM_KW,
                                                      *JWE._PBE,
                                                      'dir']:
            return cls(algorithm,
                       conv.bytes_from_b64(key_pem.decode()), kid)
        else:
            raise ValueError("Invalid PEM file")

    @classmethod
    def random_jwe(cls) -> "JWE":
        alg_list = list(JWE.Algorithm)
        enc_list = list(JWE.Encryption)

        rand_alg: JWE.Algorithm = choice(alg_list)
        rand_enc = choice(enc_list)

        if (alg := rand_alg.value) == 'dir':
            rand_key: Any = os.urandom(JWE._alg_size[rand_enc.value])
        elif alg in JWE._RSA:
            _m = [2, 3, 4]
            rand_key = rsa.generate_private_key(65537, 1024 * choice(_m))
        else:
            rand_key = os.urandom(JWE._alg_size[alg])

        return cls(rand_alg, rand_enc, rand_key)

    @property
    def key(self) -> jwe_kty:
        if self._kty == 'oct' and self._key is not None:
            return self._key

        elif self._kty == 'RSA':
            return self._rsa_privkey or self._rsa_pubkey

        else:
            raise RuntimeError("unreachable expected")

    @property
    def can_decrypt(self) -> bool:
        try:
            bool(self.privkey)
            return True
        except ValueError:
            return False

    @property
    def privkey(self) -> Union[bytes, rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]:
        if self._kty == 'oct' and self._key is not None:
            return self._key

        elif self._kty == 'RSA':
            if not self._rsa_privkey:
                raise ValueError("This JWE has not private component")

            return self._rsa_privkey
        else:
            raise RuntimeError(f"Unexpected kty {self._kty}")

    @property
    def pubkey(self) -> Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]:
        if self._kty == 'RSA':
            return self._rsa_pubkey
        else:
            raise RuntimeError("oct keys have no public component")

    @property
    def kid(self):
        return self._kid

    @property
    def kty(self) -> str:
        return self._kty

    @property
    def alg_name(self) -> str:
        return self._alg.value

    @property
    def alg(self) -> Algorithm:
        return self._alg

    def encrypt(self, plaintext: bytes, enc: Encryption = None,
                compress=False,
                extra_header: Optional[Dict[str, Any]] = None) -> str:
        if self._alg.value == 'dir':
            return self._encrypt_dir(plaintext, enc, compress, extra_header)

        elif self._alg.value in JWE._AESKW:
            return self._encrypt_aeskw(plaintext, enc, compress, extra_header)

        elif self._alg.value in JWE._AES_GCM_KW:
            return self._encrypt_gcmkw(plaintext, enc, compress, extra_header)

        elif self._alg.value in JWE._RSA:
            return self._encrypt_rsa(plaintext, enc, compress, extra_header)

        elif self._alg.value in JWE._PBE:
            return self._encrypt_pbe(plaintext, enc, compress, extra_header)

        else:
            raise RuntimeError(f"unexpected enc_alg: {self._alg.value}")

    def decrypt(self, token: str) -> bytes:
        sp = token.split('.')
        if len(sp) != 5:
            raise tex.InvalidToken("Invalid JWE structure upon splitting")

        try:
            header_encoded = sp[0]
            header: JWE_Header = JWE_Header(**conv.doc_from_b64(header_encoded))
        except Exception as ex:
            raise tex.InvalidToken(f"JWE Header could not be parsed: {ex}")

        if header.alg != self._alg.value:
            raise tex.AlgoMismatch(
                "JWE alg of this token is not compatible with this JWK")

        try:
            cek_wrapped = conv.bytes_from_b64(sp[1])
            iv = conv.bytes_from_b64(sp[2])
            ciphertext = conv.bytes_from_b64(sp[3])
            tag = conv.bytes_from_b64(sp[4])
        except Exception as ex:
            raise tex.InvalidToken(
                f"one or more of the JWE segments are base64 invalid: {ex}")

        if header.alg == 'dir':
            return self._decrypt_dir(header_encoded, header,
                                     iv, ciphertext, tag)
        elif header.alg in JWE._AESKW:
            return self._decrypt_aeskw(header_encoded, header, cek_wrapped,
                                       iv, ciphertext, tag)
        elif header.alg in JWE._AES_GCM_KW:
            return self._decrypt_gcmkw(header_encoded, header, cek_wrapped,
                                       iv, ciphertext, tag)
        elif header.alg in JWE._RSA:
            return self._decrypt_rsa(header_encoded, header, cek_wrapped,
                                     iv, ciphertext, tag)
        elif header.alg in JWE._PBE:
            return self._decrypt_pbe(header_encoded, header, cek_wrapped,
                                     iv, ciphertext, tag)
        else:
            raise RuntimeError(f"unrecognized algo: {header.alg}")

    @staticmethod
    def _encrypt_common(header: JWE_Header,
                        enc: JWE.Encryption, cek, cek_wrapped, compress,
                        plaintext, extra_header) -> str:
        header.zip = 'DEF' if compress else None
        header.enc = enc.value
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

        if 'CBC' in enc.value:
            iv, ciphertext, tag = JWE.cbc_encrypt(cek, header_b64.encode(), ziptext)
        elif 'GCM' in enc.value:
            iv, ciphertext, tag = JWE.gcm_encrypt(cek, header_b64.encode(), ziptext)
        else:
            raise RuntimeError(f"Unexpected Encryption algorithm")

        jwt = f'{header_b64}.{conv.bytes_to_b64(cek_wrapped)}.{conv.bytes_to_b64(iv)}.' \
              f'{conv.bytes_to_b64(ciphertext)}.{conv.bytes_to_b64(tag)}'

        return jwt

    @staticmethod
    def _decrypt_common(header, cek, header_enc, iv, ciphertext, tag) -> bytes:
        if 'GCM' in header.enc:
            plaintext = JWE.gcm_decrypt(cek, header_enc.encode(), iv, ciphertext, tag)
        elif 'CBC' in header.enc:
            plaintext = JWE.cbc_decrypt(cek, header_enc.encode(), iv, ciphertext, tag)
        else:
            raise RuntimeError(f"Unexpected Encryption algorithm: {header.enc}")

        if header.zip:
            plaintext = zlib.decompress(plaintext)

        return plaintext

    def _encrypt_dir(self, plaintext: bytes, enc: Encryption | None,
                     compress=True,
                     extra_header: Optional[Dict[str, Any]] = None) -> str:

        cek = self._key

        # if no enc is provided, pick one based on the key size
        if not enc:
            for k, v in JWE._enc_size.items():
                if len(cek) == v:
                    enc = JWE.Encryption(k)
                    break
        else:
            # make sure the key size is compatible with the enc
            if len(cek) != JWE._alg_size[enc.value]:
                raise ValueError(f"Invalid key size for {enc.value}")

        cek_wrapped = b''
        header = self._jwe_header.copy()
        jwt = self._encrypt_common(header=header,
                                   enc=enc, cek=cek, cek_wrapped=cek_wrapped,
                                   compress=compress,
                                   plaintext=plaintext,
                                   extra_header=extra_header)

        return jwt

    def _decrypt_dir(self, header_enc, header: JWE_Header, iv, ciphertext, tag) -> bytes:
        cek = self._key
        return self._decrypt_common(header, cek, header_enc, iv, ciphertext, tag)

    def _encrypt_aeskw(self, plaintext: bytes, enc: Encryption | None,
                       compress=True,
                       extra_header: Optional[Dict[str, Any]] = None) -> str:

        if not enc: enc = JWE.Encryption.A256GCM

        cek = os.urandom(JWE._alg_size[enc.value])
        cek_wrapped = aes_key_wrap(self._key, cek)

        header = self._jwe_header.copy()
        jwt = self._encrypt_common(header, enc, cek, cek_wrapped, compress, plaintext, extra_header)
        return jwt

    def _decrypt_aeskw(self, header_enc, header, cek_wrapped, iv, ciphertext, tag) -> bytes:
        cek = aes_key_unwrap(self._key, cek_wrapped)
        return self._decrypt_common(header, cek, header_enc, iv, ciphertext, tag)

    def _encrypt_gcmkw(self, plaintext: bytes, enc: Encryption | None,
                       compress=True,
                       extra_header: Optional[Dict[str, Any]] = None) -> str:

        if not enc: enc = JWE.Encryption.A256GCM

        cek = os.urandom(JWE._alg_size[enc.value])
        cek_iv, cek_wrapped, cek_tag = JWE.gcm_encrypt(self._key, b'', cek)

        header: JWE_Header = self._jwe_header.copy()
        header.iv, header.tag = conv.bytes_to_b64(cek_iv), conv.bytes_to_b64(cek_tag)

        jwt = self._encrypt_common(header, enc, cek, cek_wrapped, compress, plaintext, extra_header)

        return jwt

    def _decrypt_gcmkw(self, header_enc, header, cek_wrapped, iv, ciphertext, tag) -> bytes:
        try:
            cek_iv = conv.bytes_from_b64(header.iv)
            cek_tag = conv.bytes_from_b64(header.tag)
        except Exception as ex:
            raise tex.InvalidToken(
                f"one or both of the cek iv, cek tag missing/invalid {ex}")

        cek = JWE.gcm_decrypt(self._key, b'', cek_iv, cek_wrapped, cek_tag)

        return self._decrypt_common(header, cek, header_enc, iv, ciphertext, tag)

    def _encrypt_pbe(self, plaintext: bytes, enc: Encryption | None, compress=True,
                     extra_header: Optional[Dict[str, Any]] = None) -> str:

        if not enc: enc = JWE.Encryption.A256GCM

        salt = os.urandom(16)
        count = random.randint(1024, 4096)

        hash_alg = JWE._pbe_hash[self._alg.value]

        salt_val = self._alg.value.encode() + b'\x00' + salt
        kdf = PBKDF2HMAC(algorithm=hash_alg,
                         length=JWE._alg_size[self._alg.value], iterations=count,
                         salt=salt_val)
        wrapper = kdf.derive(key_material=self._key)

        cek = os.urandom(JWE._alg_size[enc.value])
        cek_wrapped = aes_key_wrap(wrapper, cek)

        header = self._jwe_header.copy()
        header.p2c = count
        header.p2s = conv.bytes_to_b64(salt)

        jwt = self._encrypt_common(header, enc, cek, cek_wrapped, compress, plaintext, extra_header)

        return jwt

    def _decrypt_pbe(self, header_enc, header: JWE_Header,
                     cek_wrapped, iv, ciphertext, tag) -> bytes:

        assert header.enc is not None

        if header.p2s is None:
            raise ValueError("missing p2s Salt input")

        if header.p2c is None:
            raise ValueError("missing p2c Iteration Count")

        salt = conv.bytes_from_b64(header.p2s)
        count = header.p2c

        hash_alg = JWE._pbe_hash[self._alg.value]

        salt_val = self._alg.value.encode() + b'\x00' + salt
        kdf = PBKDF2HMAC(algorithm=hash_alg,
                         length=JWE._alg_size[self._alg.value], iterations=count,
                         salt=salt_val)
        wrapper = kdf.derive(key_material=self._key)

        cek = aes_key_unwrap(wrapper, cek_wrapped)

        return self._decrypt_common(header, cek, header_enc, iv, ciphertext, tag)

    def _encrypt_rsa(self, plaintext: bytes, enc: Encryption | None, compress=True,
                     extra_header: Optional[Dict[str, Any]] = None) -> str:

        if not enc: enc = JWE.Encryption.A256GCM

        cek = os.urandom(JWE._alg_size[enc.value])
        cek_wrapped = self._rsa_pubkey.encrypt(
            cek,
            JWE._RSA_Padding[self._alg.value]
        )
        header = self._jwe_header.copy()
        jwt = self._encrypt_common(header, enc, cek, cek_wrapped, compress, plaintext, extra_header)

        return jwt

    def _decrypt_rsa(self, header_enc, header, cek_wrapped, iv, ciphertext, tag) -> bytes:
        if not self._rsa_privkey:
            raise ValueError("This JWK is not capable of RSA decryption "
                             "as it is a Public Key")

        cek = self._rsa_privkey.decrypt(
            cek_wrapped,
            JWE._RSA_Padding[self._alg.value]
        )
        return self._decrypt_common(header, cek, header_enc, iv, ciphertext, tag)
