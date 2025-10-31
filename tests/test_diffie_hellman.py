from cryptographic_algorithms.asymmetric import diffie_hellman


def test_shared_secret_matches():
    params = diffie_hellman.generate_parameters(128)
    alice = diffie_hellman.DiffieHellmanParticipant.generate(params)
    bob = diffie_hellman.DiffieHellmanParticipant.generate(params)
    assert alice.compute_shared_secret(bob.public_key) == bob.compute_shared_secret(alice.public_key)
