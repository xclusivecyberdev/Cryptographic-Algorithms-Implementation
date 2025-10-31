"""Educational RSA implementation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from cryptographic_algorithms.utils import number_theory as nt


@dataclass
class RSAKeyPair:
    """Simple RSA key pair with utility helpers."""

    public_exponent: int
    modulus: int
    private_exponent: int

    def encrypt(self, plaintext: int) -> int:
        return pow(plaintext, self.public_exponent, self.modulus)

    def decrypt(self, ciphertext: int) -> int:
        return pow(ciphertext, self.private_exponent, self.modulus)

    @property
    def public_key(self) -> Tuple[int, int]:
        return self.public_exponent, self.modulus

    @property
    def private_key(self) -> Tuple[int, int, int]:
        return self.public_exponent, self.modulus, self.private_exponent


def generate_keypair(bit_length: int = 512, public_exponent: int = 65537) -> RSAKeyPair:
    """Generate an RSA key pair.

    Args:
        bit_length: Desired length of the modulus.  Two primes of roughly
            half the bit length are generated.
        public_exponent: Public exponent to use.  ``65537`` is the standard
            choice in practice.
    """

    if bit_length < 256:
        raise ValueError("Bit length should be >= 256 for meaningful security")

    half = bit_length // 2
    while True:
        p = nt.generate_prime(half)
        q = nt.generate_prime(bit_length - half)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if nt.gcd(public_exponent, phi) == 1:
            modulus = p * q
            d = nt.mod_inverse(public_exponent, phi)
            return RSAKeyPair(public_exponent, modulus, d)


def encrypt_bytes(message: bytes, key: Tuple[int, int]) -> int:
    e, n = key
    m_int = int.from_bytes(message, "big")
    if m_int >= n:
        raise ValueError("Message too large for the modulus")
    return pow(m_int, e, n)


def decrypt_bytes(ciphertext: int, key_pair: RSAKeyPair) -> bytes:
    m_int = pow(ciphertext, key_pair.private_exponent, key_pair.modulus)
    length = (key_pair.modulus.bit_length() + 7) // 8
    return m_int.to_bytes(length, "big").lstrip(b"\x00")
