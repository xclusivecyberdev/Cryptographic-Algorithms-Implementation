"""Padding helpers for block ciphers."""

from __future__ import annotations

BLOCK_SIZE = 16


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Apply PKCS#7 padding to ``data``."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Remove PKCS#7 padding from ``data``.

    The function validates padding strictly and raises ``ValueError`` if the
    padding is malformed, mirroring how real cryptographic libraries defend
    against padding oracle attacks.
    """

    if not data or len(data) % block_size != 0:
        raise ValueError("Input is not padded or block size incorrect")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding")
    return data[:-pad_len]


def zero_pad(data: bytes, block_size: int) -> bytes:
    """Pad ``data`` with zero bytes (used by DES for simplicity)."""
    remainder = len(data) % block_size
    if remainder == 0:
        return data
    return data + bytes(block_size - remainder)


def zero_unpad(data: bytes) -> bytes:
    """Remove trailing zero padding."""
    return data.rstrip(b"\x00")
