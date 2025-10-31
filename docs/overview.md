# Cryptographic Algorithms – Theory and Security Notes

This repository implements classical cryptographic algorithms from the
ground up.  The focus is on clarity and pedagogy: every algorithm is
accompanied by mathematical derivations, security discussions, and unit
tests.  The implementations are not intended for production use.

## Symmetric Encryption

### Advanced Encryption Standard (AES)
- **Mathematics**: AES operates on 128-bit blocks arranged as a 4x4 state
  matrix over the finite field GF(2^8).  Core transformations include
  `SubBytes` (non-linear substitution), `ShiftRows` (row-wise rotation),
  `MixColumns` (matrix multiplication in GF(2^8)), and `AddRoundKey`.
- **Security**: AES-128 remains unbroken when used with secure modes of
  operation such as CBC with random IVs or modern AEAD modes.

### Data Encryption Standard (DES)
- **Mathematics**: DES is a 16-round Feistel network with 48-bit round
  keys derived from a 56-bit main key.  Non-linear behaviour stems from
  carefully designed S-boxes.
- **Security**: Due to the short key size, DES is vulnerable to brute
  force.  We implement it for historical and educational completeness.

## Asymmetric Encryption and Signatures

### RSA
- **Key Generation**: Choose distinct primes ``p`` and ``q``, compute the
  modulus ``n = pq`` and Euler's totient ``phi = (p-1)(q-1)``.  Select a
  public exponent ``e`` coprime to ``phi`` and compute the modular
  inverse ``d`` such that ``ed ≡ 1 (mod phi)``.
- **Security**: Relies on the difficulty of factoring ``n``.  Proper
  padding (e.g. OAEP) is required for secure deployment.

### Diffie–Hellman Key Exchange
- **Mathematics**: Operates in the multiplicative group of integers
  modulo a prime.  Each party selects a secret exponent; the shared
  secret is ``g^{ab} mod p``.
- **Security**: Vulnerable to man-in-the-middle attacks unless combined
  with authentication.

### RSA Digital Signatures
- **Approach**: We use a hash-then-sign paradigm.  Messages are hashed via
  SHA-256 and the digest is exponentiated with the private key.  The
  verifier raises the signature to the public exponent and compares it to
  the expected digest.

## Hash Functions

### SHA-256
- **Construction**: Merkle–Damgård construction with 64 rounds of
  Davies–Meyer compression.  Boolean functions `Ch`, `Maj`, and rotation
  operations provide diffusion.

### MD5
- **Historical Context**: MD5 shares the Merkle–Damgård structure but is
  now considered broken due to collision attacks.  We implement it to
  contrast modern and legacy designs.

## Blockchain Prototype

Our blockchain module implements the essentials: chained blocks with
hash references, proof-of-work mining, and integrity checks.  Difficulty
is intentionally low to keep the examples quick to run.

## Security Caveats

- The code prioritises readability over side-channel resistance.
- There is no constant-time arithmetic or defence against timing leaks.
- Key sizes are tunable but default to values that keep unit tests fast.

## Further Reading

- Menezes, van Oorschot, and Vanstone – *Handbook of Applied Cryptography*
- Katz and Lindell – *Introduction to Modern Cryptography*
- NIST FIPS 197 – AES Specification
- NIST FIPS 180-4 – Secure Hash Standard
