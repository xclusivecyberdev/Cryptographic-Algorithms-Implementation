# Cryptographic Algorithms Implementation

An educational Python codebase that re-implements foundational
cryptographic algorithms from first principles.  The repository is
organised as a teaching aid: every module contains rich documentation,
mathematical background, and references to common attacks.

## Implemented Components

| Category | Algorithms |
| --- | --- |
| Symmetric encryption | AES-128 (ECB/CBC), DES (ECB/CBC) |
| Asymmetric encryption | RSA key generation, encryption/decryption |
| Key exchange | Diffie–Hellman with safe prime generation |
| Digital signatures | RSA hash-then-sign scheme |
| Hashing | SHA-256, MD5 |
| Distributed ledger | Minimal blockchain with proof-of-work |

## Project Layout

```
cryptographic_algorithms/
  symmetric/       AES and DES implementations
  asymmetric/      RSA, Diffie–Hellman, and digital signatures
  hashing/         SHA-256 and MD5
  blockchain/      Simple blockchain prototype
  utils/           Number-theory helpers and padding routines
scripts/
  performance.py   Micro-benchmarks comparing algorithms
notebooks/
  *.ipynb          Interactive walk-throughs and visualisations
```

Additional background information lives in [`docs/overview.md`](docs/overview.md).

## Getting Started

Create a virtual environment and install the development dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt  # generated automatically by notebooks
```

(Dependencies are optional: the core library only relies on the Python
standard library.)

## Running Tests

```bash
pytest
```

The unit test suite exercises each algorithm against published test
vectors and cross-verifies encrypt/decrypt and sign/verify pairs.

## Performance Benchmarks

A light-weight benchmark script is provided to compare the runtime of
various algorithms on your machine:

```bash
python scripts/performance.py
```

The script uses the `timeit` module and summarises the results in a
simple table.  The numbers are illustrative—they are not meant to match
highly optimised native libraries.

## Interactive Notebooks

The `notebooks/` directory contains Jupyter notebooks that demonstrate
how the algorithms operate, including:

- Step-by-step AES round visualisation.
- RSA key generation followed by encryption/decryption.
- Blockchain mining demonstration.

Launch them with `jupyter lab` or `jupyter notebook` after installing the
optional dependencies.

## Disclaimer

This repository is for educational exploration only.  Do **not** use the
code for securing sensitive data or production systems.
