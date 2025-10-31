import os

import pytest

from cryptographic_algorithms.symmetric.aes import AES


@pytest.fixture
def aes_cipher():
    return AES(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))


def test_encrypt_block(aes_cipher):
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    assert aes_cipher.encrypt_block(plaintext) == expected


def test_decrypt_block(aes_cipher):
    ciphertext = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    expected = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert aes_cipher.decrypt_block(ciphertext) == expected


def test_cbc_roundtrip():
    key = os.urandom(16)
    iv = os.urandom(16)
    cipher = AES(key)
    message = b"Cryptography with AES"
    ciphertext = cipher.encrypt_cbc(message, iv)
    assert cipher.decrypt_cbc(ciphertext, iv) == message
