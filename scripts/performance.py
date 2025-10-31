"""Simple micro-benchmarks for the educational cryptography suite."""

from __future__ import annotations

import timeit

from cryptographic_algorithms.asymmetric import diffie_hellman, rsa
from cryptographic_algorithms.hashing import md5, sha256
from cryptographic_algorithms.symmetric import aes, des


def benchmark(label: str, func, number: int = 1000) -> tuple[str, float]:
    timer = timeit.Timer(func)
    seconds = timer.timeit(number=number) / number
    return label, seconds


def main() -> None:
    results = []

    aes_cipher = aes.AES(b"\x00" * 16)
    plaintext = b"\x00" * 16
    results.append(benchmark("AES-128 encrypt_block", lambda: aes_cipher.encrypt_block(plaintext)))

    des_cipher = des.DES(bytes.fromhex("133457799BBCDFF1"))
    des_plaintext = bytes.fromhex("0123456789ABCDEF")
    results.append(benchmark("DES encrypt_block", lambda: des_cipher.encrypt_block(des_plaintext)))

    sha_data = b"cryptography"
    results.append(benchmark("SHA-256", lambda: sha256.sha256(sha_data)))
    results.append(benchmark("MD5", lambda: md5.md5(sha_data)))

    results.append(benchmark("RSA keygen", lambda: rsa.generate_keypair(256), number=5))
    key_pair = rsa.generate_keypair(256)
    results.append(benchmark("RSA encrypt", lambda: key_pair.encrypt(42)))

    params = diffie_hellman.generate_parameters(128)
    alice = diffie_hellman.DiffieHellmanParticipant.generate(params)
    bob = diffie_hellman.DiffieHellmanParticipant.generate(params)
    public_bob = bob.public_key
    results.append(benchmark("Diffie-Hellman", lambda: alice.compute_shared_secret(public_bob)))

    print("Algorithm".ljust(25), "Seconds (avg)")
    print("-" * 40)
    for label, seconds in results:
        print(label.ljust(25), f"{seconds:.6f}")


if __name__ == "__main__":
    main()
