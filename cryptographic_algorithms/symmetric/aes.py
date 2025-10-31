"""Educational implementation of AES-128.

The implementation intentionally prioritises readability and extensive
comments over raw performance.  It supports encryption and decryption in
Electronic Code Book (ECB) and Cipher Block Chaining (CBC) modes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List

from cryptographic_algorithms.utils.padding import pkcs7_pad, pkcs7_unpad

Nb = 4  # block size in 32-bit words
Nk = 4  # key size in 32-bit words for AES-128
Nr = 10  # number of rounds


S_BOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

INV_S_BOX = [0] * 256
for idx, value in enumerate(S_BOX):
    INV_S_BOX[value] = idx

R_CON = [
    0x00000000,
    0x01000000,
    0x02000000,
    0x04000000,
    0x08000000,
    0x10000000,
    0x20000000,
    0x40000000,
    0x80000000,
    0x1B000000,
    0x36000000,
]


def _sub_word(word: int) -> int:
    return (
        (S_BOX[(word >> 24) & 0xFF] << 24)
        | (S_BOX[(word >> 16) & 0xFF] << 16)
        | (S_BOX[(word >> 8) & 0xFF] << 8)
        | S_BOX[word & 0xFF]
    )


def _rot_word(word: int) -> int:
    return ((word << 8) | (word >> 24)) & 0xFFFFFFFF


def key_expansion(key: bytes) -> List[int]:
    """Expand the 128-bit key into round keys."""
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes long")

    words = [int.from_bytes(key[i : i + 4], "big") for i in range(0, len(key), 4)]

    for i in range(Nk, Nb * (Nr + 1)):
        temp = words[i - 1]
        if i % Nk == 0:
            temp = _sub_word(_rot_word(temp)) ^ R_CON[i // Nk]
        words.append(words[i - Nk] ^ temp)
    return words


def _bytes_to_state(block: bytes) -> List[List[int]]:
    return [[block[r + 4 * c] for c in range(4)] for r in range(4)]



def _state_to_bytes(state: List[List[int]]) -> bytes:
    return bytes(state[r][c] for c in range(4) for r in range(4))



def _add_round_key(state: List[List[int]], round_key: List[List[int]]) -> None:
    for r in range(4):
        for c in range(4):
            state[r][c] ^= round_key[r][c]



def _words_to_matrix(words: Iterable[int]) -> List[List[int]]:
    matrix = [[0] * 4 for _ in range(4)]
    for c, word in enumerate(words):
        matrix[0][c] = (word >> 24) & 0xFF
        matrix[1][c] = (word >> 16) & 0xFF
        matrix[2][c] = (word >> 8) & 0xFF
        matrix[3][c] = word & 0xFF
    return matrix



def _sub_bytes(state: List[List[int]]) -> None:
    for r in range(4):
        for c in range(4):
            state[r][c] = S_BOX[state[r][c]]



def _inv_sub_bytes(state: List[List[int]]) -> None:
    for r in range(4):
        for c in range(4):
            state[r][c] = INV_S_BOX[state[r][c]]



def _shift_rows(state: List[List[int]]) -> None:
    for r in range(1, 4):
        state[r] = state[r][r:] + state[r][:r]



def _inv_shift_rows(state: List[List[int]]) -> None:
    for r in range(1, 4):
        state[r] = state[r][-r:] + state[r][:-r]



def _xtime(byte: int) -> int:
    byte <<= 1
    if byte & 0x100:
        byte ^= 0x11B
    return byte & 0xFF



def _mix_columns(state: List[List[int]]) -> None:
    for c in range(4):
        t = state[0][c] ^ state[1][c] ^ state[2][c] ^ state[3][c]
        temp0 = state[0][c]
        state[0][c] ^= t ^ _xtime(state[0][c] ^ state[1][c])
        state[1][c] ^= t ^ _xtime(state[1][c] ^ state[2][c])
        state[2][c] ^= t ^ _xtime(state[2][c] ^ state[3][c])
        state[3][c] ^= t ^ _xtime(state[3][c] ^ temp0)



def _inv_mix_columns(state: List[List[int]]) -> None:
    for c in range(4):
        u = _xtime(_xtime(state[0][c] ^ state[2][c]))
        v = _xtime(_xtime(state[1][c] ^ state[3][c]))
        state[0][c] ^= u
        state[1][c] ^= v
        state[2][c] ^= u
        state[3][c] ^= v
    _mix_columns(state)







@dataclass
class AES:
    """AES cipher supporting ECB and CBC modes."""

    key: bytes

    def __post_init__(self) -> None:
        self.round_keys = key_expansion(self.key)

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("Block size must be exactly 16 bytes")
        state = _bytes_to_state(block)

        _add_round_key(state, _words_to_matrix(self.round_keys[0:Nb]))
        for rnd in range(1, Nr):
            _sub_bytes(state)
            _shift_rows(state)
            _mix_columns(state)
            _add_round_key(state, _words_to_matrix(self.round_keys[rnd * Nb : (rnd + 1) * Nb]))
        _sub_bytes(state)
        _shift_rows(state)
        _add_round_key(state, _words_to_matrix(self.round_keys[Nr * Nb : (Nr + 1) * Nb]))
        return _state_to_bytes(state)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("Block size must be exactly 16 bytes")
        state = _bytes_to_state(block)

        _add_round_key(state, _words_to_matrix(self.round_keys[Nr * Nb : (Nr + 1) * Nb]))
        for rnd in range(Nr - 1, 0, -1):
            _inv_shift_rows(state)
            _inv_sub_bytes(state)
            _add_round_key(state, _words_to_matrix(self.round_keys[rnd * Nb : (rnd + 1) * Nb]))
            _inv_mix_columns(state)
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, _words_to_matrix(self.round_keys[0:Nb]))
        return _state_to_bytes(state)

    def encrypt_ecb(self, plaintext: bytes) -> bytes:
        padded = pkcs7_pad(plaintext, 16)
        return b"".join(self.encrypt_block(padded[i : i + 16]) for i in range(0, len(padded), 16))

    def decrypt_ecb(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext must be a multiple of 16 bytes")
        blocks = [self.decrypt_block(ciphertext[i : i + 16]) for i in range(0, len(ciphertext), 16)]
        return pkcs7_unpad(b"".join(blocks), 16)

    def encrypt_cbc(self, plaintext: bytes, iv: bytes) -> bytes:
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes long")
        padded = pkcs7_pad(plaintext, 16)
        blocks = []
        previous = iv
        for i in range(0, len(padded), 16):
            block = bytes(a ^ b for a, b in zip(padded[i : i + 16], previous))
            encrypted = self.encrypt_block(block)
            blocks.append(encrypted)
            previous = encrypted
        return b"".join(blocks)

    def decrypt_cbc(self, ciphertext: bytes, iv: bytes) -> bytes:
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes long")
        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext must be a multiple of 16 bytes")
        blocks = []
        previous = iv
        for i in range(0, len(ciphertext), 16):
            decrypted = self.decrypt_block(ciphertext[i : i + 16])
            blocks.append(bytes(a ^ b for a, b in zip(decrypted, previous)))
            previous = ciphertext[i : i + 16]
        return pkcs7_unpad(b"".join(blocks), 16)
