"""
Generate RSA keys, export and import RSA keys to and from several formats, and use them
to sign and verify messages, and encrypt and decrypt small messages.

AES Key Generation, export and import from multiple formats,
encryption of byte and unicode data, and high level functions to encrypt and decrypt unicode
strings and json-serializable python dicts

Several High level Hybrid Encryption and Decryption functions that combine RSA PKI with AES
session Keys.

"""

from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Random import get_random_bytes
from Cryptodome.Signature import pss
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA

from Cryptodome.Util.RFC1751 import key_to_english
from Cryptodome.Util.RFC1751 import english_to_key

from typing import Union, Optional, Dict, Any, List

from secrets import token_urlsafe
from passlib.context import CryptContext

from os.path import exists
import os
import re

import json

from jose import jwk

from base64 import urlsafe_b64encode, urlsafe_b64decode, b16encode, b16decode

# https://searchsecurity.techtarget.com/definition/Advanced-Encryption-Standard

# the first password hashing scheme is the default one.
# Automatically handles if a given hashed password needs to be checked with different schemes
_pctx = CryptContext(schemes=[
    "sha256_crypt",
    "bcrypt",
    "des_crypt",
    "md5_crypt"
], deprecated="auto")


class RSAKeyPair:
    """
    Stores the public Key in ASN.1 DER format (SubjectPublicKeyInfo).

    Stores the private Key in PKCS#8 format (PrivateKeyInfo), which is optional.

    The reason Private Keys are optional is because most client applications will be dealing with
    with different hosts/clients public keys/certificates
    to encrypt messages, and verify signatures.
    """

    def __init__(self, keysize: Optional[int] = 2048):
        """

        RSA Key types: 1024, 2048 and 3072, and 4096
        Key size of 1024 can be used to sign and verify JWTs withAlgorithm RS256

        * 1024 bit RSA
        * 2048 bit RSA (recommended - most common)
        * 3072 bit RSA
        * 4096 bit RSA (none-standard)

        initialize RSAKeyPair with an existing Public key in PEM format, and optionally
        a Private key in PEM PKCS#8 format

        :param keysize:  optional parameter keysize, generate new KeyPair when provided

        """

        if keysize is None:
            return

        if not isinstance(keysize, int) or keysize not in (1024, 2048, 3072, 4096):
            raise ValueError('RSA keysize my be an int in (1024, 2048, 3072, 4096)')

        key = RSA.generate(keysize)

        self.pubkey: str = key.public_key().export_key().decode()
        self.privkey: Optional[str] = key.export_key(pkcs=8).decode()

    def keysize(self) -> int:
        """
        Calculate the RSA bit-size from the public key of this class

        :return: RSA keysize in bits (1024, 2048, 3072 or 4096 bits)
        """
        return RSA.import_key(self.pubkey).size_in_bits()

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
            with open(f'{directory}/{privkey_name}', 'w') as fx:
                fx.write(self.privkey)

        with open(f'{directory}/{pubkey_name}', 'w') as fx:
            fx.write(self.pubkey)

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
            pubkey = fx.read()

        privkey = None

        if exists(privkey_path):
            with open(privkey_path) as fx:
                privkey = fx.read()

        kp: "RSAKeyPair" = cls(None)
        kp.pubkey = pubkey
        kp.privkey = privkey
        return kp

    def export_jwk(self) -> Dict[str, Dict[str, str]]:
        jx = {
            'pubkey': jwk.construct(self.pubkey, 'RS256').to_dict(),
        }
        if self.privkey:
            jx['privkey'] = jwk.construct(self.privkey, 'RS256').to_dict()
        return jx

    @classmethod
    def import_jwk(cls, jwk_pair: Dict[str, Dict[str, str]]) -> 'RSAKeyPair':

        pubkey = jwk.RSAKey(jwk_pair['pubkey'], 'RS256').to_pem()[:-1].decode()

        if 'privkey' in jwk_pair:
            privkey = jwk.RSAKey(jwk_pair['privkey'], 'RS256').to_pem()[:-1].decode()
        else:
            privkey = None

        kp: "RSAKeyPair" = cls(None)
        kp.pubkey = pubkey
        kp.privkey = privkey
        return kp

    def export_rsa_objects(self: Any) -> Dict[str, RSA.RsaKey]:
        dx = {
            'pubkey': RSA.import_key(self.pubkey)
        }

        if self.privkey:
            dx['privkey'] = RSA.import_key(self.privkey)

        return dx

    @classmethod
    def import_rsa_objects(cls, rsa_pair: Dict[str, RSA.RsaKey]):
        pubkey = rsa_pair['pubkey'].export_key('PEM').decode()

        if 'privkey' in rsa_pair:
            privkey: Any = rsa_pair['privkey'].export_key(format='PEM', pkcs=8).decode()
        else:
            privkey = None

        kp: "RSAKeyPair" = cls(None)
        kp.pubkey = pubkey
        kp.privkey = privkey
        return kp

    def __str__(self) -> str:
        return json.dumps({'pubkey': self.pubkey, 'privkey': self.privkey})

    def __repr__(self):
        return json.dumps(self.export_jwk(), indent=2)

    @classmethod
    def import_json(cls, rsa_jwk_json: str):
        dx: Dict[str, Any] = json.loads(rsa_jwk_json)

        if 'pubkey' in dx:
            return cls.import_jwk(dx)

        elif "kty" in dx and dx.get("kty") == "RSA":
            return cls.import_jwk({'pubkey': dx})


class AESKey:
    def __init__(self, keysize: Optional[int] = None):
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
        k = cls()
        k.key = aes_parse_to_bytes(key)
        return k


def rsa_genkeypair(keysize: int = 2048) -> RSAKeyPair:
    """
    RSA Key types: 1024, 2048 and 3072, and 4096
    Key size of 1024 can be used to sign and verify JWTs withAlgorithm RS256

    * 1024 bit RSA
    * 2048 bit RSA (recommended - most common)
    * 3072 bit RSA
    * 4096 bit RSA (none-standard)

    :param keysize: bits of the RSA keys
    :type keysize: int
    :return: a dict of pubkey and privkey
    :rtype: dict
    """

    if not isinstance(keysize, int):
        raise ValueError('RSA keysize is a mandatory int parameter')

    return RSAKeyPair(keysize)


def rsa_sign(privkey: Union[bytes, str, RSA.RsaKey], message: Union[str, bytes]) -> bytes:
    if not isinstance(message, (str, bytes)):
        raise ValueError("message can only be str of bytes")

    if isinstance(message, str):
        message = message.encode()

    if isinstance(privkey, (bytes, str)):
        privkey = RSA.import_key(privkey)
    message_hash = SHA256.new(message)
    signature = pss.new(privkey).sign(message_hash)
    return signature


def rsa_verify(pubkey: Union[bytes, str, RSA.RsaKey], message: Union[str, bytes],
               signature: bytes) -> bool:
    if not isinstance(message, (str, bytes)):
        raise ValueError("message can only be str of bytes")

    if isinstance(message, str):
        message = message.encode()

    if isinstance(pubkey, (bytes, str)):
        pubkey = RSA.import_key(pubkey)
    message_hash = SHA256.new(message)
    verifier = pss.new(pubkey)
    try:
        verifier.verify(message_hash, signature)
        return True
    except ValueError:
        return False


def rsa_encrypt(pubkey: Union[bytes, str, RSA.RsaKey], message: bytes) -> bytes:
    """
    In general, encryption with RSA Public Keys is slow, and the message size is limited.
    Moreover, it is not recommended, because if the Private Key is ever leaked,
    Any encrypted Messages that have been previously stored by a bad actor can now be
    deciphered.

    Here are the limits:

    * 1024 RSA - 86  bytes
    * 2048 RSA - 214 bytes
    * 3072 RSA - 342 bytes
    * 4096 RSA - 470 bytes

    The preferred strategy is a hybrid of RSA and Session AES Key encryption.

    :param pubkey:
    :param message:
    :return: Encrypted Message in bytes, of fixed size
    """
    if isinstance(pubkey, (bytes, str)):
        pubkey = RSA.import_key(pubkey)

    cipher_rsa = PKCS1_OAEP.new(pubkey)
    return cipher_rsa.encrypt(message)


def rsa_decrypt(privkey: Union[bytes, str, RSA.RsaKey], message_encrypted: bytes) -> bytes:
    if isinstance(privkey, (bytes, str)):
        privkey = RSA.import_key(privkey)
    cipher_rsa = PKCS1_OAEP.new(privkey)
    return cipher_rsa.decrypt(message_encrypted)


def rsa_gen_pubkey(privkey: Union[bytes, str, RSA.RsaKey], fmt: str = 'PEM') -> bytes:
    """
    generate a new public key from an existing RSA private key

    :param privkey: in PEM bytes, str or RSA.RsaKey object
    :param fmt: can be one of 'PEM', 'DER', 'OpenSSH'
    :return: public key in bytes
    """
    if not isinstance(fmt, str) or fmt not in ("PEM", "DER", "OpenSSH"):
        raise ValueError("RSA pubkey fmt can only be a str: 'PEM', 'DER', 'OpenSSH'")

    if isinstance(privkey, (bytes, str)):
        privkey = RSA.import_key(privkey)
    return privkey.public_key().export_key(format=fmt)


def rsa_gen_ssh_authorized_key(privkey: Union[bytes, str, RSA.RsaKey],
                               email: Optional[str] = None) -> str:
    """
    generate the ssh-rsa string that is ready to go to the ~/.ssh/authorized_keys file
    :param privkey:
    :param email:
    :return:
    """

    key_text = rsa_gen_pubkey(privkey, fmt='OpenSSH').decode()

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
    if not isinstance(keysize, int) or keysize not in (128, 192, 256):
        raise ValueError('AES Key length can be one of 128, 192, 256')
    return get_random_bytes(int(keysize / 8))


def aes_export(key: bytes) -> AESKey:
    k = AESKey()
    k.key = key
    return k


def aes_parse_to_bytes(key: Union[str, List[int]]) -> bytes:
    """
    Parse an AES key from integer array, base16 string, base64 string, or english words form
    :param key:
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


def aes_encrypt(aeskey: bytes, data: bytes) -> bytes:
    """
    AES encryption with GCM Mode, which is one of the fastest, and a good choice for the web.
    GCM is now part of the standard TLS suite
    :param aeskey: 128, 192 or 256 bit AES binary key
    :param data:
    :return: Encrypted Binary Data
    """
    cipher: Any = AES.new(aeskey, mode=AES.MODE_GCM)

    ciphertext, tag = cipher.encrypt_and_digest(data)

    # to decrypt, we will need to split these three values
    # cipher.nonce=16 bytes, tag=16 bytes, ciphertext the rest of the bytes
    encrypted_data: bytes = cipher.nonce + tag + ciphertext

    return encrypted_data


def aes_decrypt(aeskey: bytes, data_encrypted: bytes) -> bytes:
    """
    AES decryption in GCM mode
    :param aeskey: 128, 192 or 256 AES key
    :param data_encrypted:
    :return:
    """
    nonce, tag, ciphertext = data_encrypted[:16], data_encrypted[16:32], data_encrypted[32:]

    cipher: Any = AES.new(aeskey, AES.MODE_GCM, nonce)

    data: bytes = cipher.decrypt_and_verify(ciphertext, tag)

    return data


def aes_encrypt_to_base64(aeskey: bytes, bin_data: bytes) -> str:
    encryp_b = aes_encrypt(aeskey, bin_data)
    encryp_b64str = urlsafe_b64encode(encryp_b).decode()
    return encryp_b64str


def aes_decrypt_from_base64(aeskey: bytes, encr_b64: str) -> bytes:
    dt = aes_decrypt(aeskey, urlsafe_b64decode(encr_b64.encode()))
    return dt


def hybrid_encrypt(pubkey: Union[bytes, str, RSA.RsaKey], bindata: bytes,
                   keysize=128) -> bytes:
    new_aes = aes_genkey(keysize)

    aes_enc = aes_encrypt(new_aes, bindata)

    rsa_enc = rsa_encrypt(pubkey, new_aes)

    return rsa_enc + aes_enc


def hybrid_decrypt(privkey: Union[bytes, str, RSA.RsaKey], bindata: bytes) -> bytes:
    if isinstance(privkey, (bytes, str)):
        privkey = RSA.import_key(privkey)

    rsa_keysize = privkey.size_in_bytes()
    aes_key = rsa_decrypt(privkey, bindata[:rsa_keysize])

    return aes_decrypt(aes_key, bindata[rsa_keysize:])


def doc_aes_encrypt_to_b64(aeskey: bytes, document: Dict[Any, Any]) -> str:
    doc_b = json.dumps(document).encode()
    encryp_b = aes_encrypt(aeskey, doc_b)
    encryp_b64str = urlsafe_b64encode(encryp_b).decode()
    return encryp_b64str


def doc_aes_decrypt_from_b64(aeskey: bytes, encr_b64: str) -> Dict[Any, Any]:
    dt_json = aes_decrypt(aeskey, urlsafe_b64decode(encr_b64.encode())).decode()
    out: Dict[Any, Any] = json.loads(dt_json)
    return out


def doc_hybrid_encrypt_to_b64(pubkey: Union[bytes, str, RSA.RsaKey],
                              document: Dict[Any, Any], keysize: int = 128) -> str:
    doc_b = json.dumps(document).encode()
    encryp_b = hybrid_encrypt(pubkey, doc_b, keysize=keysize)
    encryp_b64str = urlsafe_b64encode(encryp_b).decode()
    return encryp_b64str


def doc_hybrid_decrypt_from_b64(privkey: Union[bytes, str, RSA.RsaKey],
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
