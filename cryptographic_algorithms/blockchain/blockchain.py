"""Tiny blockchain implementation demonstrating core ideas."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import List

from cryptographic_algorithms.hashing import sha256


@dataclass
class Block:
    index: int
    timestamp: float
    data: dict
    previous_hash: str
    nonce: int = 0
    hash: str = field(init=False)

    def __post_init__(self) -> None:
        self.hash = self.compute_hash()

    def compute_hash(self) -> str:
        block_string = json.dumps(
            {
                "index": self.index,
                "timestamp": self.timestamp,
                "data": self.data,
                "previous_hash": self.previous_hash,
                "nonce": self.nonce,
            },
            sort_keys=True,
        ).encode()
        return sha256.sha256_hex(block_string)


@dataclass
class Blockchain:
    difficulty: int = 2
    chain: List[Block] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.chain:
            self.chain.append(self.create_genesis_block())

    def create_genesis_block(self) -> Block:
        return Block(index=0, timestamp=time.time(), data={"genesis": True}, previous_hash="0")

    @property
    def last_block(self) -> Block:
        return self.chain[-1]

    def add_block(self, data: dict) -> Block:
        new_block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            data=data,
            previous_hash=self.last_block.hash,
        )
        mined_block = self.proof_of_work(new_block)
        self.chain.append(mined_block)
        return mined_block

    def proof_of_work(self, block: Block) -> Block:
        prefix = "0" * self.difficulty
        while not block.hash.startswith(prefix):
            block.nonce += 1
            block.hash = block.compute_hash()
        return block

    def is_valid(self) -> bool:
        prefix = "0" * self.difficulty
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]
            if current.hash != current.compute_hash():
                return False
            if current.previous_hash != previous.hash:
                return False
            if not current.hash.startswith(prefix):
                return False
        return True
