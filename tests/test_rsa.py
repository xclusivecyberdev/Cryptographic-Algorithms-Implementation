from cryptographic_algorithms.asymmetric import digital_signature, rsa


def test_rsa_roundtrip():
    key_pair = rsa.generate_keypair(256)
    message = b"RSA"
    ciphertext = rsa.encrypt_bytes(message, key_pair.public_key)
    assert rsa.decrypt_bytes(ciphertext, key_pair) == message


def test_signature_verification():
    key_pair = rsa.generate_keypair(256)
    scheme = digital_signature.RSASignatureScheme(key_pair)
    message = b"Sign me"
    signature = scheme.sign(message)
    assert scheme.verify(message, signature)
    assert not scheme.verify(message + b"!", signature)
