
"""
Code copied, minorely adjusted, and inlined from https://github.com/ethereum/eth-keys
"""

import hashlib
import hmac
from typing import (Any, Callable, Optional, Tuple)  # noqa: F401

#
# SECPK1N
#
SECPK1_P = 2**256 - 2**32 - 977  # type: int
SECPK1_N = 115792089237316195423570985008687907852837564279074904382605163141518161494337  # type: int  # noqa: E501
SECPK1_A = 0  # type: int  # noqa: E501
SECPK1_B = 7  # type: int  # noqa: E501
SECPK1_Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240  # type: int  # noqa: E501
SECPK1_Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424  # type: int  # noqa: E501
SECPK1_G = (SECPK1_Gx, SECPK1_Gy)  # type: Tuple[int, int]


P = SECPK1_P
N = SECPK1_N
A = SECPK1_A

G = SECPK1_G
Gx = SECPK1_Gx
Gy = SECPK1_Gy
B = SECPK1_B


def pad32(value: bytes) -> bytes:
    return value.rjust(32, b'\x00')


def int_to_big_endian(value: int) -> bytes:
    return value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")


def big_endian_to_int(value: bytes) -> int:
    return int.from_bytes(value, "big")


def int_to_byte(value: int) -> bytes:
    return bytes([value])


def inv(a: int, n: int) -> int:
    if a == 0:
        return 0
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        r = high // low
        nm, new = hm - lm * r, high - low * r
        lm, low, hm, high = nm, new, lm, low
    return lm % n


def to_jacobian(p: Tuple[int, int]) -> Tuple[int, int, int]:
    o = (p[0], p[1], 1)
    return o


def jacobian_double(p: Tuple[int, int, int]) -> Tuple[int, int, int]:
    if not p[1]:
        return 0, 0, 0
    ysq = (p[1] ** 2) % P
    S = (4 * p[0] * ysq) % P
    M = (3 * p[0] ** 2 + A * p[2] ** 4) % P
    nx = (M**2 - 2 * S) % P
    ny = (M * (S - nx) - 8 * ysq ** 2) % P
    nz = (2 * p[1] * p[2]) % P
    return nx, ny, nz


def jacobian_add(p: Tuple[int, int, int],
                 q: Tuple[int, int, int]) -> Tuple[int, int, int]:
    if not p[1]:
        return q
    if not q[1]:
        return p
    U1 = (p[0] * q[2] ** 2) % P
    U2 = (q[0] * p[2] ** 2) % P
    S1 = (p[1] * q[2] ** 3) % P
    S2 = (q[1] * p[2] ** 3) % P
    if U1 == U2:
        if S1 != S2:
            return 0, 0, 1
        return jacobian_double(p)
    H = U2 - U1
    R = S2 - S1
    H2 = (H * H) % P
    H3 = (H * H2) % P
    U1H2 = (U1 * H2) % P
    nx = (R ** 2 - H3 - 2 * U1H2) % P
    ny = (R * (U1H2 - nx) - S1 * H3) % P
    nz = (H * p[2] * q[2]) % P
    return nx, ny, nz


def from_jacobian(p: Tuple[int, int, int]) -> Tuple[int, int]:
    z = inv(p[2], P)
    return (p[0] * z ** 2) % P, (p[1] * z ** 3) % P


def jacobian_multiply(a: Tuple[int, int, int],
                      n: int) -> Tuple[int, int, int]:
    if a[1] == 0 or n == 0:
        return 0, 0, 1
    if n == 1:
        return a
    if n < 0 or n >= N:
        return jacobian_multiply(a, n % N)
    if (n % 2) == 0:
        return jacobian_double(jacobian_multiply(a, n // 2))
    elif (n % 2) == 1:
        return jacobian_add(jacobian_double(jacobian_multiply(a, n // 2)), a)
    else:
        raise Exception("Invariant: Unreachable code path")


def fast_multiply(a: Tuple[int, int],
                  n: int) -> Tuple[int, int]:
    return from_jacobian(jacobian_multiply(to_jacobian(a), n))


def fast_add(a: Tuple[int, int],
             b: Tuple[int, int]) -> Tuple[int, int]:
    return from_jacobian(jacobian_add(to_jacobian(a), to_jacobian(b)))


def decode_public_key(public_key_bytes: bytes) -> Tuple[int, int]:
    left = big_endian_to_int(public_key_bytes[0:32])
    right = big_endian_to_int(public_key_bytes[32:64])
    return left, right


def encode_raw_public_key(raw_public_key: Tuple[int, int]) -> bytes:
    left, right = raw_public_key
    return b''.join((
        pad32(int_to_big_endian(left)),
        pad32(int_to_big_endian(right)),
    ))


def private_key_to_public_key(private_key_bytes: bytes) -> bytes:
    private_key_as_num = big_endian_to_int(private_key_bytes)

    if private_key_as_num >= N:
        raise Exception("Invalid privkey")

    raw_public_key = fast_multiply(G, private_key_as_num)
    public_key_bytes = encode_raw_public_key(raw_public_key)
    return public_key_bytes


def compress_public_key(uncompressed_public_key_bytes: bytes) -> bytes:
    x, y = decode_public_key(uncompressed_public_key_bytes)
    if y % 2 == 0:
        prefix = b"\x02"
    else:
        prefix = b"\x03"
    return prefix + pad32(int_to_big_endian(x))


def decompress_public_key(compressed_public_key_bytes: bytes) -> bytes:
    if len(compressed_public_key_bytes) != 33:
        raise ValueError("Invalid compressed public key")

    prefix = compressed_public_key_bytes[0]
    if prefix not in (2, 3):
        raise ValueError("Invalid compressed public key")

    x = big_endian_to_int(compressed_public_key_bytes[1:])
    y_squared = (x**3 + A * x + B) % P
    y_abs = pow(y_squared, ((P + 1) // 4), P)

    if (prefix == 2 and y_abs & 1 == 1) or (prefix == 3 and y_abs & 1 == 0):
        y = (-y_abs) % P
    else:
        y = y_abs

    return encode_raw_public_key((x, y))


def deterministic_generate_k(msg_hash: bytes,
                             private_key_bytes: bytes,
                             digest_fn: Callable[[], Any] = hashlib.sha256) -> int:
    v_0 = b'\x01' * 32
    k_0 = b'\x00' * 32

    k_1 = hmac.new(k_0, v_0 + b'\x00' + private_key_bytes + msg_hash, digest_fn).digest()
    v_1 = hmac.new(k_1, v_0, digest_fn).digest()
    k_2 = hmac.new(k_1, v_1 + b'\x01' + private_key_bytes + msg_hash, digest_fn).digest()
    v_2 = hmac.new(k_2, v_1, digest_fn).digest()

    kb = hmac.new(k_2, v_2, digest_fn).digest()
    k = big_endian_to_int(kb)
    return k


def ecdsa_raw_sign(msg_hash: bytes,
                   private_key_bytes: bytes) -> Tuple[int, int, int]:
    z = big_endian_to_int(msg_hash)
    k = deterministic_generate_k(msg_hash, private_key_bytes)

    r, y = fast_multiply(G, k)
    s_raw = inv(k, N) * (z + r * big_endian_to_int(private_key_bytes)) % N

    v = 27 + ((y % 2) ^ (0 if s_raw * 2 < N else 1))
    s = s_raw if s_raw * 2 < N else N - s_raw

    return r, s, v


def ecdsa_raw_verify(msg_hash: bytes,
                     rs: Tuple[int, int],
                     public_key_bytes: bytes) -> bool:
    raw_public_key = decode_public_key(public_key_bytes)

    r, s = rs

    w = inv(s, N)
    z = big_endian_to_int(msg_hash)

    u1, u2 = z * w % N, r * w % N
    x, y = fast_add(
        fast_multiply(G, u1),
        fast_multiply(raw_public_key, u2),
    )
    return bool(r == x and (r % N) and (s % N))


def ecdsa_raw_recover(msg_hash: bytes,
                      rsv: Tuple[int, int, int]) -> bytes:
    # v, r, s = vrs
    # v += 27
    r, s, v = rsv

    if not (27 <= v <= 34):
        raise ValueError("%d must in range 27-31" % v)

    x = r

    xcubedaxb = (x * x * x + A * x + B) % P
    beta = pow(xcubedaxb, (P + 1) // 4, P)
    y = beta if v % 2 ^ beta % 2 else (P - beta)
    # If xcubedaxb is not a quadratic residue, then r cannot be the x coord
    # for a point on the curve, and so the sig is invalid
    if (xcubedaxb - y * y) % P != 0 or not (r % N) or not (s % N):
        raise ValueError("Invalid signature")
    z = big_endian_to_int(msg_hash)
    Gz = jacobian_multiply((Gx, Gy, 1), (N - z) % N)
    XY = jacobian_multiply((x, y, 1), s)
    Qr = jacobian_add(Gz, XY)
    Q = jacobian_multiply(Qr, inv(r, N))
    raw_public_key = from_jacobian(Q)

    return encode_raw_public_key(raw_public_key)
