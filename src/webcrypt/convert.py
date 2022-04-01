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


from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.utils import (decode_dss_signature,
                                                             encode_dss_signature)

from base64 import urlsafe_b64encode, urlsafe_b64decode

from typing import Dict, Any, List, Literal, Tuple

import json


def int_to_bytes(num: int, order: Literal["little", "big"] = "big", byte_size=None) -> bytes:
    """
    Convert a positive int to a bytes string. if byte_size kwarg is None, a byte string with
    enough length to contain the integer will be calculated and used.

    :param num: a positive int
    :param order: "big" or "little"
    :param byte_size: Optional byte string size, automatically calculated if left None
    :return: bytes representation of the given positive num
    """
    return num.to_bytes(byte_size or (num.bit_length() + 7) // 8 or 1, order, signed=False)


def int_from_bytes(num_bytes: bytes, order: Literal["little", "big"] = "big") -> int:
    """
    Convert a byte string to a positive int object

    :param num_bytes: byte string that represent a positive integer
    :param order: "big" or "little"
    :return: python int object
    """
    return int.from_bytes(num_bytes, order)


def int_to_hex(num: int, order: Literal["little", "big"] = "big", byte_size=None) -> str:
    """
    positive python int object to hexadecimal unicode string with optional byte size param.
    Optional byte size. If byte size is larger than needed for the int it is zero padded.

    :param num: positive python int
    :param order: "big" or "little"
    :param byte_size: Optional byte string size for the int (possibly with padding)
    :return:
    """
    b = int_to_bytes(num, order, byte_size)
    return b.hex()


def int_from_hex(num_b16: str, order: Literal["little", "big"] = "big") -> int:
    """
    Convert a hexadecimal string to the equivalent integer value as a python int object.
    Case insensitive

    :param num_b16: integer represented as a base16 unicode string, case insensitive
    :param order: "big" or "little" byte order
    :return: python int object parsed from the base16 string
    """
    b = bytes.fromhex(num_b16)
    return int_from_bytes(b, order)


def int_to_b64(num: int, order: Literal["little", "big"] = "big",
               byte_size=None, remove_padding=True) -> str:
    """
    positive, python int object to base64 unicode string, with default option to remove
    LSB b64 padding.

    Optional byte size. If byte size is larger than needed for the int it is MSB zero padded.

    :param num: positive python int object
    :param order: "big" or "little" byte order
    :param byte_size: Optional byte size to fit the the int
    :param remove_padding: option to remove Base64 LSB padding. True by default
    :return:
    """
    return bytes_to_b64(int_to_bytes(num, order, byte_size), remove_padding=remove_padding)


def int_from_b64(num_b64: str,
                 order: Literal["little", "big"] = "big", ensure_padding=True) -> int:
    """
    convert a base64 unicode representation of an integer to a positive python int object.
    If b64 padding (the ``=`` char) is needed, it is automatically calculated and added before
    the conversion.

    :param num_b64: base64 unicode representation of a positive integer
    :param order: "big" or "little" byte order
    :return: positive python int object
    :param ensure_padding: add padding as needed for a valid Base64 string. True by default
    """
    return int_from_bytes(bytes_from_b64(num_b64, ensure_padding=ensure_padding), order)


def bytes_to_b64(data: bytes, remove_padding=True) -> str:
    """
    byte string to URL safe Base64 string, with option to remove B64 LSB padding

    :param data: byte string
    :param remove_padding: remove b64 padding (``=`` char). True by default
    :return: base64 unicode string
    """
    text = urlsafe_b64encode(data).decode()
    if remove_padding:
        return text.replace('=', '')
    else:
        return text


def bytes_from_b64(data_b64: str, ensure_padding=True) -> bytes:
    """
    base64 string to byte string

    :param data_b64:
    :param ensure_padding:
    :return:
    """
    if ensure_padding:
        remainder = len(data_b64) % 4
        if remainder > 0:
            data_b64 += ("=" * (4 - remainder))
    return urlsafe_b64decode(data_b64)


def doc_to_b64(doc: Dict[Any, Any], sort_keys: bool = False) -> str:
    dt = json.dumps(
        doc,
        sort_keys=sort_keys,
        separators=(",", ":"),
    ).encode("utf-8")
    return bytes_to_b64(dt)


def doc_from_b64(doc_b64: str) -> Dict[Any, Any]:
    doc: Dict[Any, Any] = json.loads(bytes_from_b64(doc_b64))
    return doc


def doc_to_bytes(doc: Dict[Any, Any], sort_keys: bool = False) -> bytes:
    dt = json.dumps(
        doc,
        sort_keys=sort_keys,
        separators=(",", ":"),
    ).encode("utf-8")
    return dt


def doc_from_bytes(doc: bytes) -> Dict[Any, Any]:
    doc_dict: Dict[Any, Any] = json.loads(doc)
    return doc_dict


def ec_sig_der_to_raw(sig_der: bytes, byte_size=None) -> bytes:
    """
    Elliptic Curve Signature from DER format to RAW format

    :param sig_der: EC Signature in DER format
    :param byte_size: byte size to fit each EC sig component. auto-fitted by default
    :return:  RAW representation of EC signature
    """
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


def symbols_from_bytes(key: bytes, vocab: str | List[str]) -> List[str]:
    """
    Based on a given ordered list (or string) of symbol vocab, encode a byte string to
    a List of symbols

    :param key:
    :param vocab:
    :return:
    """
    integer = int_from_bytes(key)
    array = []
    bx = len(vocab)
    while integer:
        integer, value = divmod(integer, bx)
        array.append(vocab[value])
    return list(reversed(array))


def symbols_to_bytes(array: str | List[str], vocab: str | List[str]) -> bytes:
    """

    Based on a given ordered list (or string) of symbol vocab,
    restore bytes from an array (or string)
    of symbols

    :param array:
    :param vocab:
    :return:
    """
    integer = 0
    bx = len(vocab)
    for symbol in array:
        value = vocab.index(symbol)
        integer *= bx
        integer += value
    return int_to_bytes(integer)


def basic_auth_creds_encode(username: str, password: str) -> str:
    if not all((username, password)):
        raise ValueError("Basic Auth Creds cannot be empty string or None")

    if not (len(username) and len(password)):
        raise ValueError("Basic Auth username or password cannot be an empty string")

    if ":" in username:
        raise ValueError("username cannot contain the colon character")

    return urlsafe_b64encode(f"{username}:{password}".encode()).decode()


def basic_auth_creds_decode(creds_encoded: str) -> Tuple[str, str]:
    if not creds_encoded:
        raise ValueError("Basic Auth Creds cannot be None")

    pd = urlsafe_b64decode(creds_encoded).decode().split(":", 1)

    if len(pd) != 2:
        raise ValueError("Invalid Encoded Basic Auth String")

    if not (len(pd[0]) and len(pd[1])):
        raise ValueError("Basic Auth username or password cannot be an empty string")

    return pd[0], pd[1]
