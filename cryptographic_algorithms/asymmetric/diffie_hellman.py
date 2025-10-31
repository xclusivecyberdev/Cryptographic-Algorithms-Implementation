"""Diffie-Hellman key exchange utilities."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from cryptographic_algorithms.utils import number_theory as nt


@dataclass
class DiffieHellmanParameters:
    prime: int
    generator: int


@dataclass
class DiffieHellmanParticipant:
    params: DiffieHellmanParameters
    private_key: int

    @classmethod
    def generate(cls, params: DiffieHellmanParameters) -> "DiffieHellmanParticipant":
        private = secrets.randbelow(params.prime - 2) + 2
        return cls(params, private)

    @property
    def public_key(self) -> int:
        return pow(self.params.generator, self.private_key, self.params.prime)

    def compute_shared_secret(self, other_public: int) -> int:
        return pow(other_public, self.private_key, self.params.prime)


def generate_parameters(bit_length: int = 256) -> DiffieHellmanParameters:
    """Generate Diffie-Hellman parameters ``(p, g)`` with safe prime ``p``."""

    while True:
        q = nt.generate_prime(bit_length - 1)
        p = 2 * q + 1
        if nt.is_probable_prime(p):
            # Use a generator of the subgroup of order q
            for g in range(2, p - 1):
                if pow(g, 2, p) != 1 and pow(g, q, p) == 1:
                    return DiffieHellmanParameters(prime=p, generator=g)
