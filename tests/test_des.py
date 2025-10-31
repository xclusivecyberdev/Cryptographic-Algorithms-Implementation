import os

from cryptographic_algorithms.symmetric.des import DES


def test_encrypt_block():
    key = bytes.fromhex("133457799BBCDFF1")
    plaintext = bytes.fromhex("0123456789ABCDEF")
    expected = bytes.fromhex("85E813540F0AB405")
    cipher = DES(key)
    assert cipher.encrypt_block(plaintext) == expected


def test_decrypt_block():
    key = bytes.fromhex("133457799BBCDFF1")
    ciphertext = bytes.fromhex("85E813540F0AB405")
    cipher = DES(key)
    assert cipher.decrypt_block(ciphertext) == bytes.fromhex("0123456789ABCDEF")


def test_cbc_roundtrip():
    key = os.urandom(8)
    iv = os.urandom(8)
    cipher = DES(key)
    message = b"DES educational mode"
    ciphertext = cipher.encrypt_cbc(message, iv)
    assert cipher.decrypt_cbc(ciphertext, iv) == message
