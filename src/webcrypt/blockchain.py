from __future__ import annotations

from cryptography.hazmat.primitives import serialization

from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import ec

from webcrypt._blockchain_math import (ecdsa_raw_sign,
                                       ecdsa_raw_recover,
                                       ecdsa_raw_verify,
                                       int_to_big_endian,
                                       int_to_byte,
                                       pad32)

import sha3

_curve = ec.SECP256K1()


def hexstring_from_int(num: int, bits=256) -> str:
    return num.to_bytes(int(bits / 8), "big").hex()


def hexstring_to_int(hex_string: str) -> int:
    return int(hex_string, 16)


def eth_gen_privkey() -> str:
    k = ec.generate_private_key(curve=_curve)
    n: int = k.private_numbers().private_value
    return hexstring_from_int(n)


def eth_gen_pubkey_compressed(privkey_hex: str) -> str:
    if isinstance(privkey_hex, str):
        if '0x' == privkey_hex[:2]:
            privkey_hex = privkey_hex[2:]
        kx = ec.derive_private_key(hexstring_to_int(privkey_hex), _curve)
    else:
        raise ValueError("privkey has to be a str, int or EllipticCurvePrivateKey type")

    return kx.public_key().public_bytes(encoding=serialization.Encoding.X962,
                                        format=serialization.PublicFormat.CompressedPoint).hex()


def eth_gen_address(pubkey_hex: str, with_checksum=True) -> str:
    if '0x' == pubkey_hex[:2]:
        pubkey_hex = pubkey_hex[2:]

    pub_obj = ec.EllipticCurvePublicKey.from_encoded_point(curve=_curve,
                                                           data=bytes.fromhex(pubkey_hex))

    pnums = pub_obj.public_numbers()

    pub_raw = pnums.x.to_bytes(32, 'big') + pnums.y.to_bytes(32, 'big')

    kh = sha3.keccak_256()
    kh.update(pub_raw)

    k_digest = kh.hexdigest()

    address = k_digest[-40:]

    if not with_checksum:
        return address

    address_byte_array = address.encode('utf-8')

    keccak_hash = sha3.keccak_256()
    keccak_hash.update(address_byte_array)
    keccak_digest = keccak_hash.hexdigest()

    # checksum = '0x'
    checksum = ''
    for i in range(len(address)):
        address_char = address[i]
        keccak_char = keccak_digest[i]
        if int(keccak_char, 16) >= 8:
            checksum += address_char.upper()
        else:
            checksum += str(address_char)

    return checksum


def msg_add_prefix(msg: str) -> str:
    return "\x19Ethereum Signed Message:\n" + str(len(msg)) + msg


def sig_to_bytes(rsv: Tuple[int, int, int]) -> bytes:
    """
    :param rsv: tuple of the r, s, v of a signature
    :return: raw signature in bytes
    """
    r, s, v = rsv
    vb = int_to_byte(v)
    rb = pad32(int_to_big_endian(r))
    sb = pad32(int_to_big_endian(s))
    return b''.join((rb, sb, vb))


def sig_from_bytes(sig) -> Tuple[int, int, int]:
    """
    :param sig: signature in bytes
    :return: a tuple of r, s, v of the signature
    """
    r = int.from_bytes(sig[0:32], "big")
    s = int.from_bytes(sig[32:64], "big")
    v = int.from_bytes(sig[64:], "big")
    return r, s, v


def eth_sign_msg(privkey_hex: str, msg: str, with_prefix=True) -> str:
    if with_prefix:
        msg_hash = sha3.keccak_256(msg_add_prefix(msg).encode()).digest()
    else:
        msg_hash = sha3.keccak_256(msg.encode()).digest()

    r, s, v = ecdsa_raw_sign(msg_hash, bytes.fromhex(privkey_hex))
    return sig_to_bytes((r, s, v)).hex()


def eth_verify_msg(sig_hex: str, msg: str, with_prefix=True) -> bool:
    r, s, v = sig_from_bytes(bytes.fromhex(sig_hex))

    if with_prefix:
        msg_hash = sha3.keccak_256(msg_add_prefix(msg).encode()).digest()
    else:
        msg_hash = sha3.keccak_256(msg.encode()).digest()

    pubkey_raw = ecdsa_raw_recover(msg_hash, (r, s, v))

    return ecdsa_raw_verify(msg_hash, (r, s), pubkey_raw)
