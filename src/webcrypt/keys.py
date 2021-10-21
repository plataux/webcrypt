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

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
import cryptography.hazmat.primitives.asymmetric.ed25519 as ed

from webcrypt.rfc1751 import key_to_english, english_to_key

from webcrypt.convert import int_from_b64, int_to_b64

from passlib.context import CryptContext

from typing import Union, Optional, Dict, Any, List

from secrets import token_urlsafe

from os.path import exists
import os
import re

import json

from math import ceil

from base64 import urlsafe_b64encode, urlsafe_b64decode, b16encode, b16decode

from enum import Enum

# https://searchsecurity.techtarget.com/definition/Advanced-Encryption-Standard

# the first password hashing scheme is the default one.
# Automatically handles if a given hashed password needs to be checked with different schemes
_pctx = CryptContext(schemes=[
    "sha256_crypt",
    "bcrypt",
    "des_crypt",
    "md5_crypt"
], deprecated="auto")

_supported_curves = {
    "secp256k1": ec.SECP256K1(),
    "secp256r1": ec.SECP256R1(),
    "secp384r1": ec.SECP384R1(),
    "secp521r1": ec.SECP521R1(),
}


class EllipticPubkeyFormat(Enum):
    RAW = 1
    COMPRESSED = 2
    UNCOMPRESSED = 3


class RSASignAlgorithm(Enum):
    PSS = 1
    PKCS1v15 = 2


class RSAEncryptAlg(Enum):
    RSA1_5 = 1
    RSA_OAEP = 2
    RSA_OAEP_256 = 3


class RSAKeyPair:
    """
    The reason Private Keys are optional is because
    most client applications will be dealing with
    with different hosts/clients public keys/certificates
    to encrypt messages, and verify signatures.
    """

    def __init__(self, keysize: Optional[int] = 2048):
        """

        RSA Key types: 1024, 2048 and 3072, and 4096

        * 1024 bit RSA (not recommended - breakable)
        * 2048 bit RSA (recommended minimal)
        * 3072 bit RSA (recommended)
        * 4096 bit RSA

        :param keysize:  optional parameter keysize, generate new KeyPair when provided

        """

        if keysize is None:
            return

        if not isinstance(keysize, int) or keysize not in (1024, 2048, 3072, 4096):
            raise ValueError('RSA keysize can be an int in (1024, 2048, 3072, 4096)')

        self.privkey: Optional[rsa.RSAPrivateKey] = rsa.generate_private_key(65537,
                                                                             keysize)
        self.pubkey: rsa.RSAPublicKey = self.privkey.public_key()

        # key = RSA.generate(keysize)
        # self.pubkey: str = key.public_key().export_key().decode()
        # self.privkey: Optional[str] = key.export_key(pkcs=8).decode()

    def keysize(self) -> Optional[int]:
        """
        Calculate the RSA bit-size from the public key of this class

        :return: RSA keysize in bits (1024, 2048, 3072 or 4096 bits)
        """
        # return RSA.import_key(self.pubkey).size_in_bits()
        if self.pubkey:
            return self.pubkey.key_size
        else:
            return None

    def export_pem_files(self, directory,
                         pubkey_name='pubkey.pem',
                         privkey_name='privkey.pem',
                         ):
        """
        export the public key, and optionally the private key if available

        :param directory:
        :param pubkey_name: pubkey.pem by default
        :param privkey_name: privkey.pem by default, if available
        :return:
        """
        if directory == '' or directory is None:
            directory = './pemkeys'
        os.makedirs(f'{directory}', mode=0o755, exist_ok=True)

        if self.privkey:
            priv_pem = self.privkey.private_bytes(ser.Encoding.PEM,
                                                  ser.PrivateFormat.PKCS8,
                                                  encryption_algorithm=ser.NoEncryption())
            with open(f'{directory}/{privkey_name}', 'w') as fx:
                fx.write(priv_pem.decode())

        pub_pem = self.pubkey.public_bytes(ser.Encoding.PEM,
                                           ser.PublicFormat.SubjectPublicKeyInfo)
        with open(f'{directory}/{pubkey_name}', 'w') as fx:
            fx.write(pub_pem.decode())

    @classmethod
    def import_pem_files(cls, directory,
                         privkey_name='privkey.pem',
                         pubkey_name='pubkey.pem') -> "RSAKeyPair":
        """
        import the public key, and optionally the private key if available

        :param directory:
        :param pubkey_name: pubkey.pem by default
        :param privkey_name: privkey.pem by default, if available
        :return:
        """
        pubkey_path = f'{directory}/{pubkey_name}'
        privkey_path = f'{directory}/{privkey_name}'

        if not exists(pubkey_path):
            raise ValueError(f'Missing {pubkey_name} file')

        with open(pubkey_path) as fx:
            pubkey_pem = fx.read()

        privkey_pem = None

        if exists(privkey_path):
            with open(privkey_path) as fx:
                privkey_pem = fx.read()

        kp: "RSAKeyPair" = cls(None)

        key = ser.load_pem_public_key(pubkey_pem.encode())

        if isinstance(key, rsa.RSAPublicKey):
            kp.pubkey = key
        else:
            raise TypeError("Incorrect Key Type")
        if privkey_pem:
            key2 = ser.load_pem_private_key(privkey_pem.encode(), password=None)
            if isinstance(key2, rsa.RSAPrivateKey):
                kp.privkey = key2
            else:
                raise TypeError("Incorrect Key Type")
        else:
            kp.privkey = None
        return kp

    def export_pem_data(self) -> Dict[str, bytes]:
        doc = {}

        if not self.pubkey:
            raise RuntimeError("attempting to export uninitialized keypair")

        doc['pubkey'] = self.pubkey.public_bytes(
            ser.Encoding.PEM,
            ser.PublicFormat.SubjectPublicKeyInfo)

        if self.privkey:
            priv_pem = self.privkey.private_bytes(ser.Encoding.PEM,
                                                  ser.PrivateFormat.PKCS8,
                                                  encryption_algorithm=ser.NoEncryption())
            doc['privkey'] = priv_pem

        return doc

    @classmethod
    def import_pem_data(cls, pem_data: Dict[str, bytes]) -> "RSAKeyPair":
        kp: "RSAKeyPair" = cls(None)

        key_pub = ser.load_pem_public_key(pem_data['pubkey'])

        if isinstance(key_pub, rsa.RSAPublicKey):
            kp.pubkey = key_pub
        else:
            raise TypeError("Incorrect Key Type")

        if 'privkey' in pem_data:

            key_priv = ser.load_pem_private_key(pem_data['privkey'],
                                                password=None)
            if isinstance(key_priv, rsa.RSAPrivateKey):
                kp.privkey = key_priv
            else:
                raise TypeError("Incorrect Key Type")
        else:
            kp.privkey = None
        return kp

    def export_to_components(self) -> Dict[str, Dict[str, str]]:
        if not self.pubkey:
            raise RuntimeError("uninitialized RSAKeyPair")

        comps = {}

        comps['pubkey'] = rsa_pubkey_to_components(self.pubkey)

        if self.privkey:
            comps['privkey'] = rsa_privkey_to_components(self.privkey)

        return comps

    @classmethod
    def import_from_components(cls,
                               rsa_comps: Dict[str, Dict[str, str]]) -> "RSAKeyPair":
        kp: "RSAKeyPair" = cls(None)

        kp.pubkey = rsa_pubkey_from_components(rsa_comps['pubkey'])

        if 'privkey' in rsa_comps:
            kp.privkey = rsa_privkey_from_components(rsa_comps['privkey'])
        else:
            kp.privkey = None
        return kp

    def __str__(self) -> str:
        return json.dumps(self.export_pem_data(), indent=1)

    def __repr__(self):
        return json.dumps(self.export_to_components(), indent=1)


class AESKey:
    def __init__(self, keysize: Optional[int] = 128):
        if keysize is not None:
            self._key: Optional[bytes] = aes_genkey(keysize)
        else:
            self._key = None

    @property
    def key(self) -> Optional[bytes]:
        return self._key

    @key.setter
    def key(self, key: bytes):
        if not isinstance(key, bytes) or not len(key) in (16, 24, 32):
            raise ValueError("invalid AES key")
        self._key = key

    @property
    def aes_integers(self) -> List[int]:
        key: Any = self._key
        return list(key)

    @property
    def aes_base16(self) -> str:
        key: Any = self._key
        return b16encode(key).decode()

    @property
    def aes_base64(self) -> str:
        key: Any = self._key
        return urlsafe_b64encode(key).decode()

    @property
    def aes_english(self) -> str:
        key: Any = self._key
        return key_to_english(key)

    def __str__(self) -> str:
        s = f"""
bytes   : {str(self.key)}\n
integers: {str(self.aes_integers)}\n
base16  : {self.aes_base16}\n
base64  : {self.aes_base64}\n
english : {self.aes_english}
"""

        return s

    def __repr__(self) -> str:
        return str(self._key)

    def print(self):
        print(str(self))

    @classmethod
    def import_key(cls, key: Union[str, List[int]]):
        k = cls(None)
        k.key = aes_parse_to_bytes(key)
        return k

    def encrypt(self, data: bytes, auth_data=None) -> bytes:

        if self.key is not None:
            return aes_encrypt(self.key, data, auth_data)
        else:
            raise RuntimeError("Uninitialized AESKey Object")

    def decrypt(self, data_encrypted: bytes,
                auth_data=None) -> bytes:

        if self.key is not None:
            return aes_decrypt(self.key, data_encrypted, auth_data)
        else:
            raise RuntimeError("Uninitialized AESKey")


_rsa_enc_pad = {
    RSAEncryptAlg.RSA1_5: padding.PKCS1v15(),
    RSAEncryptAlg.RSA_OAEP: padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA1()),
        algorithm=hashes.SHA1(),
        label=None
    ),
    RSAEncryptAlg.RSA_OAEP_256: padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
}


def rsa_pubkey_to_components(pubkey: rsa.RSAPublicKey) -> Dict[str, str]:
    pub_num = pubkey.public_numbers()
    components = {
        #  e and n are the public numbers
        "e": int_to_b64(pub_num.e),
        "n": int_to_b64(pub_num.n),
    }
    return components


def rsa_pubkey_from_components(comps: Dict[str, str]) -> rsa.RSAPublicKey:
    pub_num = rsa.RSAPublicNumbers(int_from_b64(comps['e']), int_from_b64(comps['n']))
    return pub_num.public_key()


def rsa_privkey_to_components(privkey: rsa.RSAPrivateKey) -> Dict[str, str]:
    priv_num = privkey.private_numbers()
    pub_num = privkey.public_key().public_numbers()
    components = {
        # "kty": "RSA",
        # "alg": "RS256",

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


def rsa_privkey_from_components(comps: Dict[str, str]) -> rsa.RSAPrivateKey:
    pub_num = rsa.RSAPublicNumbers(int_from_b64(comps['e']), int_from_b64(comps['n']))
    priv_num = rsa.RSAPrivateNumbers(
        int_from_b64(comps['p']),
        int_from_b64(comps['q']),
        int_from_b64(comps['d']),
        int_from_b64(comps['dmp1']),
        int_from_b64(comps['dmq1']),
        int_from_b64(comps['iqmp']),
        pub_num
    )
    return priv_num.private_key()


def rsa_pubkey_from_pem(pubkey_pem: bytes | str) -> rsa.RSAPublicKey:
    pubkey_pem = pubkey_pem if isinstance(pubkey_pem, bytes) else pubkey_pem.encode()
    key = ser.load_pem_public_key(pubkey_pem)
    if isinstance(key, rsa.RSAPublicKey):
        return key
    else:
        raise TypeError("Unexpected Key type during deserialization")


def rsa_pubkey_to_pem(pubkey: rsa.RSAPublicKey) -> bytes:
    return pubkey.public_bytes(
        ser.Encoding.PEM,
        ser.PublicFormat.SubjectPublicKeyInfo)


def rsa_privkey_from_pem(privkey_pem: bytes | str) -> rsa.RSAPrivateKey:
    privkey_pem = privkey_pem if isinstance(privkey_pem, bytes) else privkey_pem.encode()
    key = ser.load_pem_private_key(privkey_pem, password=None)

    if isinstance(key, rsa.RSAPrivateKey):
        return key
    else:
        raise TypeError("Unexpected Key type during deserialization")


def rsa_privkey_to_pem(privkey: rsa.RSAPrivateKey) -> bytes:
    return privkey.private_bytes(ser.Encoding.PEM,
                                 ser.PrivateFormat.PKCS8,
                                 encryption_algorithm=ser.NoEncryption())


def rsa_genkeypair(keysize: int = 2048) -> RSAKeyPair:
    """

    RSA Key types: 1024, 2048 and 3072, and 4096

    * 1024 bit RSA (not recommended - breakable)
    * 2048 bit RSA (recommended minimal)
    * 3072 bit RSA (recommended)
    * 4096 bit RSA

    :param keysize: bits of the RSA keys
    :type keysize: int
    :return: a dict of pubkey and privkey
    :rtype: dict
    """

    if not isinstance(keysize, int):
        raise ValueError('RSA keysize is a mandatory int parameter')

    return RSAKeyPair(keysize)


def rsa_sign(privkey: Union[bytes, str, rsa.RSAPrivateKey],
             data: Union[str, bytes],
             hash_alg=hashes.SHA256(),
             sign_padding=RSASignAlgorithm.PSS, max_pss_salt=False) -> bytes:
    if isinstance(data, str):
        data = data.encode()

    if isinstance(privkey, (bytes, str)):
        privkey = rsa_privkey_from_pem(privkey)

    salt_len = padding.PSS.MAX_LENGTH if max_pss_salt else hash_alg.digest_size

    if sign_padding == RSASignAlgorithm.PSS:
        signature = privkey.sign(data,
                                 padding.PSS(
                                     mgf=padding.MGF1(hash_alg),
                                     salt_length=salt_len),
                                 hash_alg)
    elif sign_padding == RSASignAlgorithm.PKCS1v15:
        signature = privkey.sign(data,
                                 padding.PKCS1v15(),
                                 hash_alg)
    else:
        raise ValueError("Invalid RSA Signature Padding")

    return signature


def rsa_verify(pubkey: Union[bytes, str, rsa.RSAPublicKey],
               data: Union[str, bytes],
               signature: bytes,
               hash_alg=hashes.SHA256(),
               sign_padding=RSASignAlgorithm.PSS, max_pss_salt=False) -> bool:
    if not isinstance(data, (str, bytes)):
        raise ValueError("message can only be str or bytes")

    if isinstance(data, str):
        data = data.encode()

    if isinstance(pubkey, (bytes, str)):
        pubkey = rsa_pubkey_from_pem(pubkey)

    if sign_padding == RSASignAlgorithm.PSS:
        salt_len = padding.PSS.MAX_LENGTH if max_pss_salt else hash_alg.digest_size
        _padding = padding.PSS(
            mgf=padding.MGF1(algorithm=hash_alg),
            salt_length=salt_len)
    else:
        _padding = padding.PKCS1v15()
    try:
        pubkey.verify(signature, data, _padding, hash_alg)
        return True
    except InvalidSignature:
        return False


def rsa_encrypt(pubkey: Union[bytes, str, rsa.RSAPublicKey],
                message: bytes,
                encryption_alg: RSAEncryptAlg = RSAEncryptAlg.RSA_OAEP) -> bytes:
    """

    In general, encryption with RSA Public Keys is slow, and the message size is limited.
    Moreover, it is not recommended, because if the Private Key is ever leaked,
    Any encrypted Messages that have been previously stored by a bad actor can now be
    deciphered.

    The preferred strategy is a hybrid of RSA and Session AES Key encryption.

    :param encryption_alg:
    :param pubkey:
    :param message:
    :return: Encrypted Message in bytes, of fixed size
    """
    if isinstance(pubkey, (bytes, str)):
        pubkey = rsa_pubkey_from_pem(pubkey)

    ciphertext = pubkey.encrypt(
        message,
        _rsa_enc_pad[encryption_alg]
    )
    return ciphertext


def rsa_decrypt(privkey: Union[bytes, str, rsa.RSAPrivateKey],
                message_encrypted: bytes,
                encryption_alg: RSAEncryptAlg = RSAEncryptAlg.RSA_OAEP) -> bytes:
    if isinstance(privkey, (bytes, str)):
        privkey = rsa_privkey_from_pem(privkey)

    plaintext = privkey.decrypt(
        message_encrypted,
        _rsa_enc_pad[encryption_alg]
    )

    return plaintext


def rsa_gen_ssh_authorized_key(pubkey: rsa.RSAPublicKey,
                               email: Optional[str] = None) -> str:
    """
    generate the ssh-rsa string that is ready to go
    to the ~/.ssh/authorized_keys file

    :param pubkey:
    :param email:
    :return:
    """

    key_text = pubkey.public_bytes(ser.Encoding.OpenSSH, ser.PublicFormat.OpenSSH).decode()

    if email is None:
        return key_text

    if not isinstance(email, str):
        raise ValueError(f"email should be a string {str(email)}")
    ms = r"(^[a-zA-Z0-9_+-]+[a-zA-Z0-9_.+-]*@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
    if not re.fullmatch(ms, email):
        raise ValueError(f"invalid email address: {email}")

    return f'{key_text} {email}'


def aes_genkey(keysize=128) -> bytes:
    """
    Generate AES Key.

    * AES-128 (16 bytes)
    * AES-192 (24 bytes)
    * AES-256 (32 bytes)

    :param keysize: AES keysize can be 128, 192, 256
    :type keysize: int
    :return: AES key
    :rtype: bytes
    """
    return AESGCM.generate_key(bit_length=keysize)


def aes_export(key: bytes) -> AESKey:
    k = AESKey(None)
    k.key = key
    return k


def aes_parse_to_bytes(key: Union[str, List[int]]) -> bytes:
    """
    Parse an AES key from integer array, base16 string, base64 string,
    or english words form

    :param key: AES key in bytes
    :return: AES key (128, 192 or 256 bits) in byte data type
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
            return english_to_key(key)

        elif key_len in (24, 44):
            return urlsafe_b64decode(key)

        elif key_len in (48, 64):
            # Here we upper the key in case the b16 string has been lowered
            return b16decode(key.upper())

        elif key_len == 32:
            try:
                # Here we upper the key to prevent the clash with a possible B64 string
                # not entirely sure why that words, but ran millions of unit tests
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


def aes_encrypt(aeskey: bytes | AESKey, data: bytes,
                auth_data=None) -> bytes:
    """
    AES encryption with GCM Mode, which is fast, open and secure,
    and a good choice for the web.
    GCM is now part of the standard TLS suite

    :param auth_data: None-Encrypted Authenticated data
    :param aeskey: 128, 192 or 256 bit AES binary key
    :param data: binary data of less than 4.0 Gb size
    :return: Encrypted Binary Data with 12-byte nonce iv appended at the head

    """

    if isinstance(aeskey, bytes):
        aesgcm = AESGCM(aeskey)
    elif aeskey.key is not None:
        aesgcm = AESGCM(aeskey.key)
    else:
        raise ValueError("Uninitialized AESKey")

    nonce = os.urandom(12)  # 96-bits for best performance
    ciphertext = aesgcm.encrypt(nonce, data, auth_data)

    encrypted_data: bytes = nonce + ciphertext

    return encrypted_data


def aes_decrypt(aeskey: bytes | AESKey, data_encrypted: bytes,
                auth_data: Optional[bytes] = None) -> bytes:
    """
    AES decryption in GCM mode

    :param auth_data: Authenticated Non-Encrypted Data
    :param aeskey: 128, 192 or 256 AES key
    :param data_encrypted:
    :return:
    """
    if isinstance(aeskey, bytes):
        aesgcm = AESGCM(aeskey)
    elif aeskey.key is not None:
        aesgcm = AESGCM(aeskey.key)
    else:
        raise ValueError("Uninitialized AESKey")

    nonce, ciphertext = data_encrypted[:12], data_encrypted[12:]

    data: bytes = aesgcm.decrypt(nonce, ciphertext, auth_data)

    return data


def aes_encrypt_to_base64(aeskey: bytes | AESKey, bin_data: bytes) -> str:
    enc_data = aes_encrypt(aeskey, bin_data)
    enc_data_b64 = urlsafe_b64encode(enc_data).decode()
    return enc_data_b64


def aes_decrypt_from_base64(aeskey: bytes | AESKey, encr_b64: str) -> bytes:
    dt = aes_decrypt(aeskey, urlsafe_b64decode(encr_b64.encode()))
    return dt


def hybrid_encrypt(pubkey: Union[bytes, str, rsa.RSAPublicKey], bindata: bytes,
                   keysize=128) -> bytes:
    new_aes = aes_genkey(keysize)
    aes_enc = aes_encrypt(new_aes, bindata)
    rsa_enc = rsa_encrypt(pubkey, new_aes)
    return rsa_enc + aes_enc


def hybrid_decrypt(privkey: Union[bytes, str, rsa.RSAPrivateKey],
                   bindata: bytes) -> bytes:
    if isinstance(privkey, str) or isinstance(privkey, bytes):
        privkey = rsa_privkey_from_pem(privkey)

    rsa_keysize = int(privkey.key_size / 8)

    aes_key = rsa_decrypt(privkey, bindata[:rsa_keysize])
    return aes_decrypt(aes_key, bindata[rsa_keysize:])


def doc_aes_encrypt_to_b64(aeskey: bytes | AESKey, document: Dict[Any, Any]) -> str:
    doc_b = json.dumps(document).encode()
    encryp_b = aes_encrypt(aeskey, doc_b)
    encryp_b64str = urlsafe_b64encode(encryp_b).decode()
    return encryp_b64str


def doc_aes_decrypt_from_b64(aeskey: bytes | AESKey, encr_b64: str) -> Dict[Any, Any]:
    dt_json = aes_decrypt(aeskey, urlsafe_b64decode(encr_b64.encode())).decode()
    out: Dict[Any, Any] = json.loads(dt_json)
    return out


def doc_hybrid_encrypt_to_b64(pubkey: Union[bytes, str, rsa.RSAPublicKey],
                              document: Dict[Any, Any], keysize: int = 128) -> str:
    doc_b = json.dumps(document).encode()
    encryp_b = hybrid_encrypt(pubkey, doc_b, keysize=keysize)
    encryp_b64str = urlsafe_b64encode(encryp_b).decode()
    return encryp_b64str


def doc_hybrid_decrypt_from_b64(privkey: Union[bytes, str, rsa.RSAPrivateKey],
                                encr_b64: str) -> Dict[Any, Any]:
    dt_json = hybrid_decrypt(privkey, urlsafe_b64decode(encr_b64.encode()))
    out: Dict[Any, Any] = json.loads(dt_json)
    return out


def password_generate(byte_size: int = 12) -> str:
    """
    URL safe random password of at least 10 bytes strength

    :param byte_size:
    :return:
    """
    if byte_size < 10:
        raise ValueError("Only Accepting at least 10 bytes of password strength")
    return token_urlsafe(byte_size)


def password_verify(plain_password: str, hashed_password: str) -> bool:
    is_valid: bool = _pctx.verify(plain_password, hashed_password)
    return is_valid


def password_hash(password: str) -> str:
    ph: str = _pctx.hash(password)
    return ph


def ec_privkey_generate(curve=ec.SECP256K1()) -> ec.EllipticCurvePrivateKey:
    if curve.name not in _supported_curves:
        raise ValueError(
            "Only these curves supported: secp256k1, secp256r1, secp384r1, secp521r1")
    k = ec.generate_private_key(curve)
    return k


def ec_privkey_to_hex(privkey: ec.EllipticCurvePrivateKey):
    keysize = privkey.key_size
    print(keysize)
    num: int = privkey.private_numbers().private_value
    return num.to_bytes(int(ceil((keysize / 8))), "big").hex()


def ec_privkey_from_hex(privkey_hex: str,
                        curve=ec.SECP256K1()) -> ec.EllipticCurvePrivateKey:
    if isinstance(privkey_hex, str):
        if '0x' == privkey_hex[:2]:
            privkey_hex = privkey_hex[2:]
        kx = ec.derive_private_key(int(privkey_hex, 16), curve=curve)
        return kx
    else:
        raise ValueError("privkey_hex has to be a str")


def ec_pubkey_to_hex(pubkey: ec.EllipticCurvePublicKey,
                     pubkey_format=EllipticPubkeyFormat.COMPRESSED) -> str:
    if pubkey_format == EllipticPubkeyFormat.COMPRESSED:
        return pubkey.public_bytes(
            encoding=ser.Encoding.X962,
            format=ser.PublicFormat.CompressedPoint).hex()

    else:
        pub_hex = pubkey.public_bytes(
            encoding=ser.Encoding.X962,
            format=ser.PublicFormat.UncompressedPoint).hex()

        if pubkey_format == EllipticPubkeyFormat.UNCOMPRESSED:
            return pub_hex

        elif pubkey_format == EllipticPubkeyFormat.RAW:
            return pub_hex[2:]

        else:
            raise ValueError("unknown PubkeyFormat")


def ec_pubkey_from_hex(pubkey_hex: str,
                       curve=ec.SECP256K1(),
                       pubkey_format=EllipticPubkeyFormat.COMPRESSED) -> \
        ec.EllipticCurvePublicKey:
    if pubkey_format in (EllipticPubkeyFormat.COMPRESSED, EllipticPubkeyFormat.UNCOMPRESSED):
        return ec.EllipticCurvePublicKey.from_encoded_point(curve=curve,
                                                            data=bytes.fromhex(pubkey_hex))

    elif pubkey_format == EllipticPubkeyFormat.RAW:
        pub_raw = bytes.fromhex(pubkey_hex)

        ks = int(ceil((curve.key_size / 8)))

        pn = ec.EllipticCurvePublicNumbers(int.from_bytes(pub_raw[0:ks], "big"),
                                           int.from_bytes(pub_raw[ks: ks * 2], "big"),
                                           curve)
        return pn.public_key()

    else:
        raise ValueError("unknown Pubkey Format")


def ec_dh_derive_key(privkey: ec.EllipticCurvePrivateKey, pubkey: ec.EllipticCurvePublicKey,
                     keysize=128,
                     salt: Optional[bytes] = None,
                     info: Optional[bytes] = None):
    shared_key = privkey.exchange(ec.ECDH(), pubkey)

    if not isinstance(keysize, int) or keysize not in (128, 192, 256):
        raise ValueError('AES Key length can be one of 128, 192, 256')

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=int(keysize / 8),
        salt=salt,
        info=info,
    ).derive(shared_key)

    return derived_key


def ec_sign(privkey: ec.EllipticCurvePrivateKey,
            data: bytes | str,
            hash_alg=hashes.SHA256()) -> bytes:
    if isinstance(data, str):
        data = data.encode()

    signature = privkey.sign(data, ec.ECDSA(hash_alg))
    return signature


def ec_verify(pubkey: ec.EllipticCurvePublicKey,
              data: bytes | str,
              signature: bytes, hash_alg=hashes.SHA256()) -> bool:
    if isinstance(data, str):
        data = data.encode()

    try:
        pubkey.verify(signature, data, ec.ECDSA(hash_alg))
        return True
    except InvalidSignature:
        return False


def ed_privkey_generate() -> ed.Ed25519PrivateKey:
    return ed.Ed25519PrivateKey.generate()


def ed_privkey_to_hex(privkey: ed.Ed25519PrivateKey) -> str:
    pb: bytes = privkey.private_bytes(encoding=ser.Encoding.Raw,
                                      format=ser.PrivateFormat.Raw,
                                      encryption_algorithm=ser.NoEncryption())
    return pb.hex()


def ed_privkey_from_hex(privkey_hex: str) -> ed.Ed25519PrivateKey:
    edk = ed.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(privkey_hex))
    return edk


def ed_pubkey_to_hex(pubkey: ed.Ed25519PublicKey) -> str:
    return pubkey.public_bytes(ser.Encoding.Raw,
                               ser.PublicFormat.Raw).hex()


def ed_pubkey_from_hex(pubkey_hex: str) -> ed.Ed25519PublicKey:
    return ed.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))


def ed_sign(privkey: ed.Ed25519PrivateKey, data: bytes) -> bytes:
    return privkey.sign(data)


def ed_verify(pubkey: ed.Ed25519PublicKey, data: bytes, signature: bytes) -> bool:
    try:
        pubkey.verify(signature=signature, data=data)
        return True
    except InvalidSignature:
        return False


def curve_sign_doc(privkey: Union[ec.EllipticCurvePrivateKey, ed.Ed25519PrivateKey],
                   msg: str) -> Dict[str, str]:
    if isinstance(privkey, ec.EllipticCurvePrivateKey):
        sig = urlsafe_b64encode(ec_sign(privkey, msg.encode())).decode()
        curve = privkey.curve.name
        pubkey = ec_pubkey_to_hex(privkey.public_key())
    elif isinstance(privkey, ed.Ed25519PrivateKey):
        sig = urlsafe_b64encode(ed_sign(privkey, msg.encode())).decode()
        curve = "Curve25519"
        pubkey = ed_pubkey_to_hex(privkey.public_key())
    else:
        raise ValueError(f"Unsupported Private key: {type(privkey)}")
    sig_doc = {
        "msg": msg,
        "sig": sig,
        "pubkey": pubkey,
        "curve": curve
    }
    return sig_doc


def curve_verify_doc(doc: Dict[str, str]) -> bool:
    sig = doc["sig"]
    msg = doc["msg"]
    pubkey_hex = doc["pubkey"]
    curve = doc["curve"]
    if curve == 'Curve25519':
        pubkey: Any = ed_pubkey_from_hex(pubkey_hex)
        return ed_verify(pubkey, msg.encode(), urlsafe_b64decode(sig))
    elif curve in _supported_curves:
        pubkey = ec_pubkey_from_hex(pubkey_hex, curve=_supported_curves[curve])
        return ec_verify(pubkey, msg.encode(), urlsafe_b64decode(sig))
    else:
        raise ValueError(
            "Only these curves supported: Curve25519, "
            "secp256k1, secp256r1, secp384r1, secp521r1")


def hmac_genkey(hash_alg: hashes.HashAlgorithm = hashes.SHA512()):
    return os.urandom(hash_alg.digest_size)


def hmac_sign(key: bytes, data: bytes | str, hash_alg=hashes.SHA256()) -> bytes:
    h = hmac.HMAC(key, hash_alg)

    if isinstance(data, str):
        data = data.encode()

    h.update(data)

    return h.finalize()


def hmac_verify(key: bytes, data: bytes | str, signature: bytes,
                hash_alg=hashes.SHA256()) -> bool:
    h = hmac.HMAC(key, hash_alg)

    if isinstance(data, str):
        data = data.encode()

    h.update(data)

    try:
        h.verify(signature)
        return True
    except InvalidSignature:
        return False
