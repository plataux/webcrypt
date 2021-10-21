from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.utils import (decode_dss_signature,
                                                             encode_dss_signature)

from base64 import urlsafe_b64encode, urlsafe_b64decode

from typing import Dict, Any, Union, Tuple

import json


def int_to_bytes(num: int, order="big", byte_size=None) -> bytes:
    return num.to_bytes(byte_size or (num.bit_length() + 7) // 8 or 1, order)


def int_from_bytes(num_bytes: bytes, order="big") -> int:
    return int.from_bytes(num_bytes, order)


def int_to_b64(num: int, order="big", byte_size=None) -> str:
    return bytes_to_b64(int_to_bytes(num, order, byte_size))


def int_from_b64(num_b64: str, order="big"):
    return int_from_bytes(bytes_from_b64(num_b64), order)


def bytes_to_b64(data: bytes, remove_padding=True) -> str:
    text = urlsafe_b64encode(data).decode()
    if remove_padding:
        return text.replace('=', '')
    else:
        return text


def bytes_from_b64(data_b64: str, ensure_padding=True) -> bytes:
    if ensure_padding:
        rem = len(data_b64) % 4
        if rem > 0:
            data_b64 += "=" * (4 - rem)
    return urlsafe_b64decode(data_b64)


def ec_sig_der_to_raw(sig_der: bytes, byte_size=None) -> bytes:
    r, s = decode_dss_signature(sig_der)
    raw = int_to_bytes(r, byte_size=byte_size) + int_to_bytes(s, byte_size=byte_size)
    return raw


def ec_sig_der_from_raw(sig_raw: bytes) -> bytes:
    t = int(len(sig_raw) / 2)
    r, s = int_from_bytes(sig_raw[:t]), int_from_bytes(sig_raw[t:])
    return encode_dss_signature(r, s)


def ec_sig_der_to_raw_b64(sig_der, byte_size=None) -> str:
    return bytes_to_b64(ec_sig_der_to_raw(sig_der, byte_size=byte_size))


def ec_sig_der_from_raw_b64(sig_raw_b64: str) -> bytes:
    sig_raw = bytes_from_b64(sig_raw_b64)
    return ec_sig_der_from_raw(sig_raw)


def doc_to_b64(doc: Dict[str, str], sort_keys: bool = False) -> str:
    dt = json.dumps(
        doc,
        sort_keys=sort_keys,
        separators=(",", ":"),
    ).encode("utf-8")
    return bytes_to_b64(dt)


def doc_from_b64(doc_b64: str) -> Dict[str, str]:
    return json.loads(bytes_from_b64(doc_b64))


def doc_to_bytes(doc: Dict[Any, Any], sort_keys: bool = False) -> bytes:
    dt = json.dumps(
        doc,
        sort_keys=sort_keys,
        separators=(",", ":"),
    ).encode("utf-8")
    return dt


def doc_from_bytes(doc: bytes) -> Dict[Any, Any]:
    return json.loads(doc)
