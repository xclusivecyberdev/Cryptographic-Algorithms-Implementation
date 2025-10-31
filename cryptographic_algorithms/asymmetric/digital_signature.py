"""Digital signature scheme built on top of RSA and SHA-256."""

from __future__ import annotations

from dataclasses import dataclass

from cryptographic_algorithms.asymmetric import rsa
from cryptographic_algorithms.hashing import sha256


@dataclass
class RSASignatureScheme:
    """Minimalistic RSA signature scheme using a hash-then-sign approach."""

    key_pair: rsa.RSAKeyPair

    def sign(self, message: bytes) -> int:
        digest = int.from_bytes(sha256.sha256(message), "big")
        return pow(digest, self.key_pair.private_exponent, self.key_pair.modulus)

    def verify(self, message: bytes, signature: int) -> bool:
        digest = int.from_bytes(sha256.sha256(message), "big")
        verification = pow(signature, self.key_pair.public_exponent, self.key_pair.modulus)
        return digest == verification
