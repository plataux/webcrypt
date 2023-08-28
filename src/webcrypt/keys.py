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
Generate RSA keys, export and import RSA keys to and from several formats, and use them
to sign and verify messages, and encrypt and decrypt small messages.

AES Key Generation, export and import from multiple formats,
encryption of byte and unicode data, and high level functions to
encrypt and decrypt unicode strings and json-serializable python dicts

Several High level Hybrid Encryption and Decryption functions that combine RSA PKI with AES
session Keys.

"""
from __future__ import annotations

from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.constant_time import bytes_eq

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
import cryptography.hazmat.primitives.asymmetric.ed25519 as ed

from cryptography.hazmat.primitives.keywrap import aes_key_wrap as wrap
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap as unwrap
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.padding import PKCS7

from webcrypt.rfc1751 import key_to_english, english_to_key
from webcrypt.convert import int_to_b64
import webcrypt.convert as conv

import webcrypt.exceptions as tex

from typing import Union, Optional, Dict, Any, List

import os
import re

import json

from math import ceil

from base64 import urlsafe_b64encode, urlsafe_b64decode, b16encode, b16decode
from base64 import b85encode, b85decode

from enum import Enum


# https://searchsecurity.techtarget.com/definition/Advanced-Encryption-Standard

# the first password hashing scheme is the default one.
# Automatically handles if a given hashed password needs to be checked with different schemes


class AES:
    """
    Generates, derives and wraps a valid AES key object, of bit size 128, 192, or 256.

    Contains methods to represent the key bytes in base16, base64, int array and english words.
    encrypt and decrypt methods that use GCM mode, and a random 96-bit Initialization Vector
    (iv) inserted at the head of the ciphertext, with an optional *authenticated data* as input.

    Includes a key derivation static method ``derive_key`` with a few options to derive
    new and existing keys.

    """

    @staticmethod
    def restore_key_bytes(key: str | List[int]) -> bytes:
        """
        Parse and restore AES bytes key from integer array, base16 string, base64 string, or
        english words form.

        For example, to restore a 128-bit key bytes:

        From the int array form:

        ``[248, 18, 53, 68, 190, 54, 178, 157, 158, 75, 102, 201, 136, 20, 15, 35]``

        Or from the hexadecimal form (case insensitive):

        ``F8123544BE36B29D9E4B66C988140F23``

        Or from the base64 form (with padding expected and required):

        ``-BI1RL42sp2eS2bJiBQPIw==``

        Or from Base85:

        ``AQMS)p_Q5BEy)8_yvTzO``

        Or from the english words representation (case-insensitive):

        ``WAST GUST BAKE EVIL CORE ARTY IFFY BOIL LOOT DUG TIP GWYN``

        :param key: AES key in bytes
        :return: AES key (128, 192 or 256 bits) in byte form
        """

        if isinstance(key, list):
            if not len(key) in (16, 24, 32):
                raise ValueError("invalid AES keysize. only 16 bytes,"
                                 "24 bytes, or 32 bytes supported")
            for num in key:
                if not isinstance(num, int):
                    raise ValueError("invalid AES data: only an integer list is accepted")
            return bytes(key)

        elif isinstance(key, str):
            key_len = len(key)

            if len(key.split(' ')) in (12, 18, 24):
                return english_to_key(key.upper())

            elif key_len in (20, 30, 40):
                return b85decode(key)

            elif key_len in (24, 44):
                return urlsafe_b64decode(key)

            elif key_len in (48, 64):
                # Here we upper the key in case the b16 string has been lowered
                return b16decode(key.upper())

            elif key_len == 32:
                try:
                    # Here we upper the key to prevent the clash with a possible B64 string
                    # not entirely sure why that works, but ran millions of unit tests
                    # and seems to work properly
                    return b16decode(key.upper())
                except ValueError:
                    pass
                try:
                    return urlsafe_b64decode(key)

                except Exception:
                    raise ValueError("the given 32 byte string is "
                                     "neither Base16 nor Base64 encoded")
            else:
                raise ValueError("Could not parse the given AES str key")
        else:
            raise ValueError("key to be parsed can only be of type str, or List[int]")

    __slots__ = ('_key',)

    def __init__(self, key: int | bytes | List[int] | str = 128):
        """
        Creates a new random key with a given bit length (128, 192, 256), or restore it from
        bytes form, int array form or various string forms, including base16, base64, and
        english words form.

        :param key: int for new key, bytes, list or str to restore existing keys
        """
        self._key: bytes

        if isinstance(key, int):
            self._key = AESGCM.generate_key(bit_length=key)

        elif isinstance(key, bytes):
            if len(key) in (16, 24, 32):
                self._key = key
            else:
                raise ValueError("Invalid AES keysize")

        elif isinstance(key, (list, str)):
            self._key = AES.restore_key_bytes(key)

        else:
            raise ValueError("Invalid AES input")

    @property
    def key(self) -> bytes:
        """
        byte string representation of this AES key
        """
        return self._key

    @property
    def array(self) -> List[int]:
        """
        int array representation of this AES key. Will look like:

        ``[71, 103, 200, 29, 116, 76, 1, 225, 143, 55, 205, 118, 48, 218, 144, 127]``

        """
        key: Any = self._key
        return list(key)

    @property
    def base16(self) -> str:
        """
        the hexadecimal ``str`` representation of this AES key. will look like:

        ``4767C81D744C01E18F37CD7630DA907F``
        """
        key: Any = self._key
        return b16encode(key).decode()

    @property
    def base64(self) -> str:
        """
        the base64 URL safe string representation of this AES key, will look like:

        ``R2fIHXRMAeGPN812MNqQfw==``
        """
        key: Any = self._key
        return urlsafe_b64encode(key).decode()

    @property
    def base85(self) -> str:
        return b85encode(self._key, False).decode()

    @property
    def words(self) -> str:
        """
        The english words string representation of this AES key, will look like:

        ``ABED SUD BIB TEEM MUDD TUFT GOSH MOOD BOSS BUSY LACK TEA``
        """
        key: Any = self._key
        return key_to_english(key)

    def __str__(self) -> str:
        s = f"""
bytes   : {str(self.key)}\n
integers: {str(self.array)}\n
base16  : {self.base16}\n
base64  : {self.base64}\n
base85  : {self.base85}\n
english : {self.words}
"""

        return s

    def __repr__(self) -> str:
        return str(self._key)

    def __eq__(self, other) -> bool:

        if not isinstance(other, AES):
            return NotImplemented

        if self._key == other._key:
            return True
        else:
            return False

    def encrypt(self, data: bytes, auth_data: bytes = b'') -> bytes:
        """
        AES encryption with GCM Mode, which is fast, open and secure,
        and a good choice for the web apps - GCM is now part of the standard TLS suite.

        uses a 96-bit random iv, which is inserted at the start of the ciphertext.
        Optionally accepts authenticated data byte string, which defaults to ``b''``

        :param data: binary data of less than 4.0 Gb size
        :param auth_data: None-Encrypted Authenticated data, defaults to empty byte string
        :return: Encrypted Binary Data with 12-byte nonce iv inserted at the head

        """

        aesgcm = AESGCM(self._key)
        iv = os.urandom(12)  # 96-bits for best performance
        ciphertext = aesgcm.encrypt(iv, data, auth_data)
        encrypted_data: bytes = iv + ciphertext

        return encrypted_data

    def decrypt(self, data_encrypted: bytes, auth_data: bytes = b'') -> bytes:
        """
        Decrypts the given ciphertext, expecting 96-bit iv at the start, followed by the
        ciphertext and 16-byte tag. Accepts Authenticated Data string, which defaults to b''

        :param data_encrypted: Ciphertext with 96-bit iv at the start, 16-byte tag at the end
        :param auth_data: Optional Authenticated data
        :return: decrypted data
        """
        aesgcm = AESGCM(self._key)
        nonce, ciphertext = data_encrypted[:12], data_encrypted[12:]
        data: bytes = aesgcm.decrypt(nonce, ciphertext, auth_data)
        return data

    def wrap(self, cek: bytes) -> bytes:
        return wrap(self.key, cek)

    def unwrap(self, wrapped_cek) -> bytes:
        return unwrap(self.key, wrapped_cek)


class RSA:
    """
    Generates a new or restores an existing RSA private key, or an RSA Public key of sizes
    2048, 3072, or 4096 bits. If it wraps a private key, it automatically derives the
    corresponding public key upon initialization for faster operation.

    If an instance of this class wraps a Public key only, it can perform the following
    crypto operations:

    * verify signatures by the corresponding private key
    * wraps messages or CEKs
    * encrypt data with randomly generated CEKs
    * export the public key to various formats

    If an instance of this class wraps a private key, in addition to the above, it can perform
    the following crypto operations:

    * hash and sign data, and generate RSA signatures
    * unwrap messages or CEKs
    * decrypt data previously encrypted with the corresponding public key
    * export the private key to various formats
    """

    class SignAlg(Enum):
        """
        Enumeration of RSA Signature Padding Algorithms, ``PSS`` the more recommended option
        """
        PSS = 1
        PKCS1v15 = 2

    class EncryptAlg(Enum):
        """
        Enumeration RSA Encryption Padding Algorithm, ``RSA_OAEP_256``,
        is the more recommended option
        """
        RSA1_5 = 1
        RSA_OAEP = 2
        RSA_OAEP_256 = 3

    _rsa_kty = Union[int, str, bytes, rsa.RSAPrivateKey,
                     rsa.RSAPublicKey, Dict[str, str]]

    _rsa_enc_pad = {
        1: padding.PKCS1v15(),
        2: padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        ),
        3: padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    }

    __slots__ = ('privkey', 'pubkey')

    def __init__(self, key: _rsa_kty = 2048):
        """

        RSA Key types: 2048 and 3072, and 4096

        * 2048 bit RSA (recommended minimal)
        * 3072 bit RSA (recommended)
        * 4096 bit RSA

        :param key:  optional parameter keysize, generate new KeyPair when provided

        """

        self.privkey: Optional[rsa.RSAPrivateKey]
        self.pubkey: rsa.RSAPublicKey

        if isinstance(key, rsa.RSAPrivateKey):
            self.privkey = key
            self.pubkey = self.privkey.public_key()

        elif isinstance(key, rsa.RSAPublicKey):
            self.privkey = None
            self.pubkey = key

        elif isinstance(key, (str, bytes)):
            if isinstance(key, str):
                key = key.encode()

            if b'PRIVATE' in key:
                kx = ser.load_pem_private_key(key, password=None)
                if not isinstance(kx, rsa.RSAPrivateKey):
                    raise ValueError("Invalid RSA Private Key")

                self.privkey = kx
                self.pubkey = self.privkey.public_key()

            elif b'PUBLIC' in key:
                ky = ser.load_pem_public_key(key)

                if not isinstance(ky, rsa.RSAPublicKey):
                    raise ValueError("Invalid RSA Public Key")

                self.privkey = None
                self.pubkey = ky
            else:
                raise ValueError("Invalid PEM file")

        elif isinstance(key, int):
            if key not in (2048, 3072, 4096):
                raise ValueError('RSA keysize can be an int in 2048, 3072, 4096')
            self.privkey = rsa.generate_private_key(65537, key)
            self.pubkey = self.privkey.public_key()

        elif isinstance(key, dict):
            if all(comp in key for comp in ('e', 'n')):
                pub_num = rsa.RSAPublicNumbers(conv.int_from_b64(key['e']),
                                               conv.int_from_b64(key['n']))
                self.pubkey = pub_num.public_key()
            else:
                raise ValueError("invalid RSA key")

            if all(comp in key for comp in ('p', 'q', 'd', 'dp', 'dq', 'qi')):
                priv_num = rsa.RSAPrivateNumbers(
                    conv.int_from_b64(key['p']),
                    conv.int_from_b64(key['q']),
                    conv.int_from_b64(key['d']),
                    conv.int_from_b64(key['dmp1']),
                    conv.int_from_b64(key['dmq1']),
                    conv.int_from_b64(key['iqmp']),
                    pub_num
                )
                self.privkey = priv_num.private_key()
            else:
                self.privkey = None

        else:
            raise ValueError("Invalid RSA key")

    def keysize(self) -> int:
        """
        Calculate the RSA bit-size from the public key of this class

        :return: RSA keysize in bits (2048, 3072 or 4096 bits)
        """
        # return RSA.import_key(self.pubkey).size_in_bits()
        return self.pubkey.key_size

    def sign(self,
             data: Union[str, bytes],
             hash_alg: hashes.HashAlgorithm = hashes.SHA256(),
             sign_padding: RSA.SignAlg = SignAlg.PSS,
             max_pss_salt: bool = False) -> bytes:
        """
        Hashes the given data string with the given hashing algorithm, and generate an RSA
        signature based on the Given Signature Padding

        :param data: unicode or byte string to sign
        :param hash_alg: defaults to SHA256 and is the recommended choice
        :param sign_padding: defaults to PSS and is the recommended choice
        :param max_pss_salt: opt apply the max applicable PSS salt length, defaults to ``False``
        :return: RSA Signature in bytes string form
        """

        if self.privkey is None:
            raise RuntimeError("This key is not capable of signing")

        if isinstance(data, str):
            data = data.encode()

        if sign_padding == RSA.SignAlg.PSS:
            salt_len = padding.PSS.MAX_LENGTH if max_pss_salt else hash_alg.digest_size
            _sign_padding: Any = padding.PSS(
                mgf=padding.MGF1(hash_alg),
                salt_length=salt_len)
        elif sign_padding == RSA.SignAlg.PKCS1v15:
            _sign_padding = padding.PKCS1v15()
        else:
            raise ValueError("Invalid RSA Signature Padding Spec")

        return self.privkey.sign(data, _sign_padding, hash_alg)

    def verify(self,
               data: Union[str, bytes],
               signature: bytes,
               hash_alg=hashes.SHA256(),
               sign_padding=SignAlg.PSS, max_pss_salt=False) -> bool:
        """

        :param data:
        :param signature:
        :param hash_alg:
        :param sign_padding:
        :param max_pss_salt:
        :return:
        """
        if self.pubkey is None:
            raise ValueError("This key seems to have not been initialized yet")

        if isinstance(data, str):
            data = data.encode()

        if sign_padding == RSA.SignAlg.PSS:
            salt_len = padding.PSS.MAX_LENGTH if max_pss_salt else hash_alg.digest_size
            _sign_padding: Any = padding.PSS(
                mgf=padding.MGF1(hash_alg),
                salt_length=salt_len)
        elif sign_padding == RSA.SignAlg.PKCS1v15:
            _sign_padding = padding.PKCS1v15()
        else:
            raise ValueError("Invalid RSA Signature Padding Spec")

        try:
            self.pubkey.verify(signature, data, _sign_padding, hash_alg)
            return True
        except InvalidSignature:
            return False

    def wrap(self,
             message: bytes,
             encryption_alg: EncryptAlg = EncryptAlg.RSA_OAEP) -> bytes:
        """

        In general, encryption with RSA Public Keys is slow, and the message size is limited.
        Moreover, it is not recommended, because if the Private Key is ever leaked,
        Any encrypted Messages that have been previously stored by a bad actor can now be
        deciphered.

        The preferred strategy is a hybrid of RSA and Session AES Key encryption.

        :param encryption_alg:
        :param message:
        :return: Encrypted Message in bytes, of fixed size

        """

        if self.pubkey is None:
            raise ValueError("This key seems to have not been initialized yet")

        ciphertext = self.pubkey.encrypt(
            message,
            RSA._rsa_enc_pad[encryption_alg.value]
        )
        return ciphertext

    def unwrap(self,
               message_encrypted: bytes,
               encryption_alg: EncryptAlg = EncryptAlg.RSA_OAEP) -> bytes:

        if self.privkey is None:
            raise RuntimeError("This key is not capable of signing")

        plaintext = self.privkey.decrypt(
            message_encrypted,
            RSA._rsa_enc_pad[encryption_alg.value]
        )

        return plaintext

    def encrypt(self, data: bytes, cek_size=128) -> bytes:
        cek = AES(cek_size)
        data_encrypted = cek.encrypt(data)
        cek_wrapped = self.wrap(cek.key)
        return cek_wrapped + data_encrypted

    def decrypt(self, data_encrypted: bytes) -> bytes:
        ks = self.keysize() // 8
        cek_wrapped = self.unwrap(data_encrypted[:ks])
        cek = AES(cek_wrapped)
        return cek.decrypt(data_encrypted[ks:])

    def privkey_dict(self) -> Dict[str, str]:
        if self.privkey is None:
            raise ValueError("not a private key")

        priv_num = self.privkey.private_numbers()
        pub_num = self.privkey.public_key().public_numbers()
        components = {
            #  e and n are the public numbers
            "e": int_to_b64(pub_num.e),
            "n": int_to_b64(pub_num.n),

            # d p q dp dq qi are the private numbers
            "d": int_to_b64(priv_num.d),
            "p": int_to_b64(priv_num.p),
            "q": int_to_b64(priv_num.q),
            "dmp1": int_to_b64(priv_num.dmp1),  # dp
            "dmq1": int_to_b64(priv_num.dmq1),  # dq
            "iqmp": int_to_b64(priv_num.iqmp),  # qi
        }
        return components

    def pubkey_dict(self) -> Dict[str, str]:
        pub_num = self.pubkey.public_numbers()
        comps = {
            "e": int_to_b64(pub_num.e),
            "n": int_to_b64(pub_num.n),
        }
        return comps

    def privkey_pem(self) -> str:
        if self.privkey is None:
            raise ValueError("not a private RSA key")

        return self.privkey.private_bytes(
            ser.Encoding.PEM,
            ser.PrivateFormat.PKCS8,
            encryption_algorithm=ser.NoEncryption()).decode()

    def pubkey_pem(self) -> str:
        return self.pubkey.public_bytes(
            ser.Encoding.PEM,
            ser.PublicFormat.SubjectPublicKeyInfo).decode()

    def pubkey_ssh(self,
                   email: Optional[str] = None) -> str:
        """
        generate the ssh-rsa string that is ready to go
        to the ~/.ssh/authorized_keys file

        :param email:
        :return:
        """

        key_text = self.pubkey.public_bytes(ser.Encoding.OpenSSH,
                                            ser.PublicFormat.OpenSSH).decode()

        if email is None:
            return key_text

        if not isinstance(email, str):
            raise ValueError(f"email should be a string {str(email)}")
        ms = r"(^[a-zA-Z0-9_+-]+[a-zA-Z0-9_.+-]*@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
        if not re.fullmatch(ms, email):
            raise ValueError(f"invalid email address: {email}")

        return f'{key_text} {email}'

    def __str__(self) -> str:
        if self.privkey:
            return json.dumps(self.privkey_dict(), indent=1)
        else:
            return json.dumps(self.pubkey_dict(), indent=1)

    def __repr__(self) -> str:
        return str(self)

    def __eq__(self, other) -> bool:
        if not isinstance(other, RSA):
            return NotImplemented

        if self.pubkey_pem() == other.pubkey_pem():
            return True
        else:
            return False


class ECKey:
    class PubHexFormat(Enum):
        RAW = 1
        COMPRESSED = 2
        UNCOMPRESSED = 3

    _ec_kty = Union[int, ec.EllipticCurve,
                    str, bytes,
                    ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey]

    _supported_curves = {
        "secp256k1": ec.SECP256K1(),
        "secp256r1": ec.SECP256R1(),
        "secp384r1": ec.SECP384R1(),
        "secp521r1": ec.SECP521R1(),
    }

    __slots__ = ('privkey', 'pubkey')

    def __init__(self, key: _ec_kty = 256):
        """
        Construct a new key via:

        * ``int`` representing a curve size
        * ``EllipticCurve`` instance

        Construct an existing key from:

        * PEM data in str or bytes format
        * Elliptic Curve object

        :param key:
        """

        self.privkey: Optional[ec.EllipticCurvePrivateKey] = None
        self.pubkey: ec.EllipticCurvePublicKey

        if isinstance(key, int):
            if key == 256:
                curve: ec.EllipticCurve = ec.SECP256R1()
            elif key == 384:
                curve = ec.SECP384R1()
            elif key == 521:
                curve = ec.SECP521R1()
            else:
                raise ValueError("only SECG curves with size 256, 384, 521 supported")
            self.privkey = ec.generate_private_key(curve)
            self.pubkey = self.privkey.public_key()

        elif isinstance(key, (str, bytes)):

            if isinstance(key, str):
                key = key.encode()

            if b'PRIVATE' in key:
                priv_key = ser.load_pem_private_key(key, password=None)

                if not isinstance(priv_key, ec.EllipticCurvePrivateKey):
                    raise ValueError("Invalid EC Private Key")

                self.privkey = priv_key
                self.pubkey = self.privkey.public_key()
            elif b'PUBLIC' in key:
                pub_key = ser.load_pem_public_key(key)

                if not isinstance(pub_key, ec.EllipticCurvePublicKey):
                    raise ValueError("Invalid EC Private Key")

                self.privkey = None
                self.pubkey = pub_key
            else:
                raise ValueError("Invalid PEM file")

        elif isinstance(key, ec.EllipticCurve):
            if key.name not in ECKey._supported_curves:
                raise ValueError("Unsupported Elliptic Curve")

            self.privkey = ec.generate_private_key(key)
            self.pubkey = self.privkey.public_key()

        elif isinstance(key, ec.EllipticCurvePrivateKey):
            if key.curve.name not in ECKey._supported_curves:
                raise ValueError("Unsupported Elliptic Curve")

            self.privkey = key
            self.pubkey = self.privkey.public_key()

        elif isinstance(key, ec.EllipticCurvePublicKey):
            if key.curve.name not in ECKey._supported_curves:
                raise ValueError("Unsupported Elliptic Curve")

            self.privkey = None
            self.pubkey = key

        else:
            raise ValueError("Invalid EC input")

    def __eq__(self, other) -> bool:

        if not isinstance(other, ECKey):
            return NotImplemented

        if self.pubkey_pem() == other.pubkey_pem():
            return True
        else:
            return False

    def sign(self, data: bytes, hash_alg=hashes.SHA256()) -> bytes:
        if self.privkey is None:
            raise ValueError("not a private RSA key")

        signature = self.privkey.sign(data, ec.ECDSA(hash_alg))
        return signature

    def verify(self, data, signature, hash_alg=hashes.SHA256()) -> bool:
        try:
            self.pubkey.verify(signature, data, ec.ECDSA(hash_alg))
            return True
        except InvalidSignature:
            return False

    @property
    def keysize(self) -> int:
        return self.pubkey.key_size

    @property
    def curve(self) -> str:
        return self.pubkey.curve.name

    def privkey_pem(self) -> str:
        if self.privkey is None:
            raise ValueError("not a private EC key")

        return self.privkey.private_bytes(
            ser.Encoding.PEM,
            ser.PrivateFormat.PKCS8,
            encryption_algorithm=ser.NoEncryption()).decode()

    def pubkey_pem(self) -> str:
        return self.pubkey.public_bytes(
            ser.Encoding.PEM,
            ser.PublicFormat.SubjectPublicKeyInfo).decode()

    def privkey_hex(self):
        if self.privkey is None:
            raise ValueError("this EC key is not a private key")
        num: int = self.privkey.private_numbers().private_value

        # ks = int(ceil((self.keysize / 8)))
        # print(ks)
        return conv.int_to_hex(num)

    def pubkey_hex(self, hex_format=PubHexFormat.COMPRESSED):
        if hex_format == ECKey.PubHexFormat.COMPRESSED:
            return self.pubkey.public_bytes(
                encoding=ser.Encoding.X962,
                format=ser.PublicFormat.CompressedPoint).hex()

        else:
            pub_hex = self.pubkey.public_bytes(
                encoding=ser.Encoding.X962,
                format=ser.PublicFormat.UncompressedPoint).hex()

            if hex_format == ECKey.PubHexFormat.UNCOMPRESSED:
                return pub_hex

            elif hex_format == ECKey.PubHexFormat.RAW:
                return pub_hex[2:]

            else:
                raise ValueError("unknown PubkeyFormat")

    @classmethod
    def privkey_from_hex(cls, privkey_hex: str, curve=ec.SECP256R1()) -> "ECKey":
        if isinstance(privkey_hex, str):
            if '0x' == privkey_hex[:2]:
                privkey_hex = privkey_hex[2:]
            kx = ec.derive_private_key(conv.int_from_hex(privkey_hex), curve=curve)
            return cls(kx)
        else:
            raise ValueError("privkey_hex has to be a str")

    @classmethod
    def pubkey_from_hex(cls, pubkey_hex: str,
                        curve=ec.SECP256R1(),
                        pubkey_format=PubHexFormat.COMPRESSED) -> "ECKey":
        if pubkey_format in (ECKey.PubHexFormat.COMPRESSED,
                             ECKey.PubHexFormat.UNCOMPRESSED):
            kx = ec.EllipticCurvePublicKey.from_encoded_point(
                curve=curve,
                data=bytes.fromhex(pubkey_hex))

            return cls(kx)

        elif pubkey_format == ECKey.PubHexFormat.RAW:
            pub_raw = bytes.fromhex(pubkey_hex)

            ks = int(ceil((curve.key_size / 8)))

            pub_nums = ec.EllipticCurvePublicNumbers(
                conv.int_from_bytes(pub_raw[0:ks]),
                conv.int_from_bytes(pub_raw[ks: ks * 2]),
                curve)
            return cls(pub_nums.public_key())

        else:
            raise ValueError("unknown Pubkey Format")

    @staticmethod
    def ecdh_derive_key(privkey: ec.EllipticCurvePrivateKey,
                        pubkey: ec.EllipticCurvePublicKey,
                        cek_bits=128,
                        salt: Optional[bytes] = None,
                        info: Optional[bytes] = None,
                        hash_alg: hashes.HashAlgorithm = hashes.SHA256()):
        shared_key = privkey.exchange(ec.ECDH(), pubkey)

        if not isinstance(cek_bits, int) or cek_bits not in (128, 192, 256):
            raise ValueError('AES Key length can be one of 128, 192, 256')

        derived_key = HKDF(
            algorithm=hash_alg,
            length=int(cek_bits / 8),
            salt=salt,
            info=info,
        ).derive(shared_key)

        return derived_key


class EDKey:
    _ed_types = Union[ed.Ed25519PrivateKey, ed.Ed25519PublicKey, str, bytes]

    __slots__ = ('privkey', 'pubkey')

    def __init__(self, key: Optional[_ed_types] = None):

        if key is None:
            self.privkey: Union[ed.Ed25519PrivateKey, None] = ed.Ed25519PrivateKey.generate()
            self.pubkey: ed.Ed25519PublicKey = self.privkey.public_key()

        elif isinstance(key, ed.Ed25519PrivateKey):
            self.privkey = key
            self.pubkey = self.privkey.public_key()

        elif isinstance(key, ed.Ed25519PublicKey):
            self.privkey = None
            self.pubkey = key

        elif isinstance(key, (str, bytes)):
            if isinstance(key, str):
                key = key.encode()

            if b'PRIVATE' in key:

                priv_key = ser.load_pem_private_key(key, password=None)

                if not isinstance(priv_key, ed.Ed25519PrivateKey):
                    raise ValueError("Invalid ED Curve Private Key")

                self.privkey = priv_key
                self.pubkey = self.privkey.public_key()
            elif b'PUBLIC' in key:

                pub_key = ser.load_pem_public_key(key)

                if not isinstance(pub_key, ed.Ed25519PublicKey):
                    raise ValueError("Invalid ED Curve Public Key")

                self.privkey = None
                self.pubkey = pub_key
            else:
                raise ValueError("Invalid PEM file")

        else:
            raise ValueError("Invalid ED Key")

    def sign(self, data) -> bytes:
        if self.privkey is not None:
            return self.privkey.sign(data)
        else:
            raise RuntimeError("This ED Key cannot sign - not a private key")

    def verify(self, data, signature) -> bool:
        try:
            self.pubkey.verify(signature=signature, data=data)
            return True
        except InvalidSignature:
            return False

    def privkey_pem(self) -> str:
        if self.privkey is None:
            raise ValueError("not a private Ed key")

        return self.privkey.private_bytes(
            ser.Encoding.PEM,
            ser.PrivateFormat.PKCS8,
            encryption_algorithm=ser.NoEncryption()).decode()

    def pubkey_pem(self) -> str:
        return self.pubkey.public_bytes(
            ser.Encoding.PEM,
            ser.PublicFormat.SubjectPublicKeyInfo).decode()

    def privkey_hex(self) -> str:
        if self.privkey is not None:
            pb: bytes = self.privkey.private_bytes(encoding=ser.Encoding.Raw,
                                                   format=ser.PrivateFormat.Raw,
                                                   encryption_algorithm=ser.NoEncryption())
            return pb.hex()
        else:
            raise RuntimeError("This ED Key is not a private key")

    def pubkey_hex(self) -> str:
        return self.pubkey.public_bytes(ser.Encoding.Raw,
                                        ser.PublicFormat.Raw).hex()

    @classmethod
    def privkey_from_hex(cls, privkey_hex: str) -> "EDKey":
        edk = ed.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(privkey_hex))
        return cls(edk)

    @classmethod
    def pubkey_from_hex(cls, pubkey_hex: str) -> "EDKey":
        return cls(ed.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex)))


def encrypt_cbc(comp_key: bytes, plaintext: bytes, auth_data: bytes = b'') -> bytes:
    """

    :param comp_key: Composite Key: First half for HMAC, and second half for Content Encryption
    :param plaintext:
    :param auth_data:
    :return:
    """
    hash_alg: hashes.HashAlgorithm
    if len(comp_key) not in (32, 48, 64):
        raise ValueError("CBC key must be in 32, 48, 64 bytes long")

    if auth_data is None:
        auth_data = b''

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

    return iv + ciphertext + tag


def decrypt_cbc(comp_key: bytes, ciphertext: bytes, auth_data: bytes = b'') -> bytes:
    """

    :param comp_key: Composite Key: First half for HMAC, and second half for Content Encryption
    :param ciphertext:
    :param auth_data:
    :return:
    """
    key_len = len(comp_key) // 2
    iv = ciphertext[:16]
    ct = ciphertext[16:-key_len]
    tag = ciphertext[-key_len:]

    if auth_data is None:
        auth_data = b''

    if len(comp_key) not in (32, 48, 64):
        raise ValueError("CBC key must be in 32, 36, 64 bytes long")

    key_len = len(comp_key) // 2

    hmac_key = comp_key[:key_len]
    enc_key = comp_key[-key_len:]

    hash_alg: hashes.HashAlgorithm
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
    hmac_signer.update(auth_data + iv + ct + al)

    sig = hmac_signer.finalize()

    if not bytes_eq(sig[:key_len], tag):
        raise tex.InvalidSignature("Tag invalid - Token Fabricated or Tampered With")

    try:
        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))

        decryptor = cipher.decryptor()
        padded_plain_text = decryptor.update(ct)
        padded_plain_text += decryptor.finalize()
        de_padder = PKCS7(algorithms.AES.block_size).unpadder()
        plaintext: bytes = de_padder.update(padded_plain_text)
        plaintext += de_padder.finalize()

        return plaintext
    except Exception as ex:
        raise tex.TokenException(
            f"Could not decrypt token, corrupted or tampered with: {ex}")


def encrypt_gcm(key: bytes, plaintext: bytes, auth_data: bytes = b'') -> bytes:
    """
    AES encryption with GCM Mode, which is fast, open and secure,
    and a good choice for the web apps - GCM is now part of the standard TLS suite.

    uses a 96-bit random iv, which is inserted at the start of the ciphertext.
    Optionally accepts authenticated data byte string, which defaults to ``b''``

    :param key: 16, 24 or 32 bytes string
    :param plaintext: binary data of less than 4.0 Gb size
    :param auth_data: None-Encrypted Authenticated data, defaults to empty byte string
    :return: Encrypted Binary Data with 12-byte nonce iv inserted at the head

    """

    aesgcm = AESGCM(key)
    iv = os.urandom(12)  # 96-bits for best performance
    ciphertext = aesgcm.encrypt(iv, plaintext, auth_data)
    encrypted_data: bytes = iv + ciphertext

    return encrypted_data


def decrypt_gcm(key: bytes, ciphertext: bytes, auth_data: bytes = b'') -> bytes:
    """
    Decrypts the given ciphertext, expecting 96-bit iv at the start, followed by the
    ciphertext and 16-byte tag. Accepts Authenticated Data string, which defaults to b''

    :param key:
    :param ciphertext: Ciphertext with 96-bit iv at the start, 16-byte tag at the end
    :param auth_data: Optional Authenticated data
    :return: decrypted data
    """
    aesgcm = AESGCM(key)
    nonce, ciphertext = ciphertext[:12], ciphertext[12:]
    data: bytes = aesgcm.decrypt(nonce, ciphertext, auth_data)
    return data
