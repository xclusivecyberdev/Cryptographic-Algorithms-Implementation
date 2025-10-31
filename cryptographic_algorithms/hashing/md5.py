"""Pure Python MD5 implementation.

The code follows RFC 1321 closely and keeps intermediate values in
Python integers for clarity.  It is intentionally compact yet readable,
making it suitable for instructional use.
"""

from __future__ import annotations

import math


# Constants for the sine table used in MD5 key schedule
_K = [int((1 << 32) * abs(math.sin(i + 1))) & 0xFFFFFFFF for i in range(64)]

# Per-round shift amounts
_S = [
    7, 12, 17, 22,
    5, 9, 14, 20,
    4, 11, 16, 23,
    6, 10, 15, 21,
]


def _left_rotate(x: int, amount: int) -> int:
    return ((x << amount) | (x >> (32 - amount))) & 0xFFFFFFFF


def _to_bytes(word: int) -> bytes:
    return word.to_bytes(4, "little")


def md5(message: bytes) -> bytes:
    """Compute the MD5 hash of *message* returning a 16-byte digest."""

    # Initial values per RFC 1321
    a0 = 0x67452301
    b0 = 0xEFCDAB89
    c0 = 0x98BADCFE
    d0 = 0x10325476

    original_bit_len = (8 * len(message)) & 0xFFFFFFFFFFFFFFFF
    message += b"\x80"
    while len(message) % 64 != 56:
        message += b"\x00"
    message += original_bit_len.to_bytes(8, "little")

    for chunk_start in range(0, len(message), 64):
        chunk = message[chunk_start : chunk_start + 64]
        m = [int.from_bytes(chunk[i : i + 4], "little") for i in range(0, 64, 4)]

        A, B, C, D = a0, b0, c0, d0

        for i in range(64):
            if 0 <= i <= 15:
                F = (B & C) | (~B & D)
                g = i
            elif 16 <= i <= 31:
                F = (D & B) | (~D & C)
                g = (5 * i + 1) % 16
            elif 32 <= i <= 47:
                F = B ^ C ^ D
                g = (3 * i + 5) % 16
            else:
                F = C ^ (B | ~D)
                g = (7 * i) % 16

            F = (F + A + _K[i] + m[g]) & 0xFFFFFFFF
            A, D, C, B = D, C, B, (B + _left_rotate(F, _S[(i // 16) * 4 + i % 4])) & 0xFFFFFFFF

        a0 = (a0 + A) & 0xFFFFFFFF
        b0 = (b0 + B) & 0xFFFFFFFF
        c0 = (c0 + C) & 0xFFFFFFFF
        d0 = (d0 + D) & 0xFFFFFFFF

    return b"".join(_to_bytes(word) for word in (a0, b0, c0, d0))


def md5_hex(message: bytes) -> str:
    return md5(message).hex()
