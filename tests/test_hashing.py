from cryptographic_algorithms.hashing import md5, sha256


def test_md5_known_vector():
    assert md5.md5_hex(b"abc") == "900150983cd24fb0d6963f7d28e17f72"


def test_sha256_known_vector():
    assert sha256.sha256_hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
