"""Number theory utilities used across asymmetric algorithms.

This module implements fundamental arithmetic primitives required for
cryptographic algorithms such as RSA and Diffie-Hellman.  The functions
are deliberately implemented from first principles and heavily annotated
with docstrings to support learning.
"""

from __future__ import annotations

import secrets
from typing import Tuple


def gcd(a: int, b: int) -> int:
    """Return the greatest common divisor of *a* and *b* using Euclid's algorithm."""
    while b:
        a, b = b, a % b
    return abs(a)


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean algorithm.

    Returns a triple ``(g, x, y)`` such that ``g == gcd(a, b)`` and ``ax + by = g``.
    The coefficients ``x`` and ``y`` are particularly useful when computing modular
    inverses.
    """

    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return old_r, old_s, old_t


def mod_inverse(a: int, modulus: int) -> int:
    """Return the modular inverse of ``a`` modulo ``modulus``.

    Raises:
        ValueError: If the inverse does not exist.
    """

    g, x, _ = extended_gcd(a, modulus)
    if g != 1:
        raise ValueError(f"Inverse for {a} modulo {modulus} does not exist")
    return x % modulus


# Deterministic set of bases recommended for 64-bit security margin.  For
# educational purposes we allow primes up to 2048 bits and therefore include a
# few additional bases commonly used in literature.
_MILLER_RABIN_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23)


def _decompose(n: int) -> Tuple[int, int]:
    """Return ``(s, d)`` such that ``n - 1 == 2**s * d`` with ``d`` odd."""
    s = 0
    d = n - 1
    while d % 2 == 0:
        s += 1
        d //= 2
    return s, d


def is_probable_prime(n: int, rounds: int = 12) -> bool:
    """Return ``True`` if ``n`` is probably prime using the Miller-Rabin test."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    s, d = _decompose(n)
    bases = _MILLER_RABIN_BASES[:rounds]

    for a in bases:
        if a % n == 0:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bit_length: int) -> int:
    """Return a probable prime of the requested bit length.

    The function keeps sampling random odd integers until the Miller-Rabin
    test accepts them.  A modest default of 12 rounds keeps the
    implementation fast yet secure enough for experimentation.
    """

    if bit_length < 16:
        raise ValueError("Bit length must be at least 16 bits for educational purposes")

    while True:
        candidate = secrets.randbits(bit_length) | (1 << (bit_length - 1)) | 1
        if is_probable_prime(candidate):
            return candidate
