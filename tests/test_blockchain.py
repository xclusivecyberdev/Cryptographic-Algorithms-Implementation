from cryptographic_algorithms.blockchain.blockchain import Blockchain


def test_blockchain_integrity():
    chain = Blockchain(difficulty=2)
    chain.add_block({"amount": 1})
    chain.add_block({"amount": 2})
    assert chain.is_valid()
    # Tamper with block
    chain.chain[1].data["amount"] = 999
    assert not chain.is_valid()
