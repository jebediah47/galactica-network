from datetime import datetime, timezone
import hashlib
import json
import random

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


class Transaction:
    def __init__(self, amount, sender, recipient):
        self.amount = amount
        self.sender = sender
        self.recipient = recipient

    def to_json(self):
        return json.dumps(self.__dict__)


class Block:
    nonce = random.random() * 999999999

    def __init__(self, previous_hash, transaction: Transaction):
        self.previous_hash = previous_hash
        self.transaction = transaction.to_json()
        self.timestamp = str(datetime.now(timezone.utc))

    def get_hash(self):
        sha_input = json.dumps(self.__dict__, sort_keys=True)
        return hashlib.sha256(sha_input.encode()).hexdigest()


class Chain:
    # Singleton instance of the Chain class
    instance = None

    def __new__(cls, *args, **kwargs):
        if not Chain.instance:
            Chain.instance = super(Chain, cls).__new__(cls, *args, **kwargs)
        return Chain.instance

    chain = [Block]

    def __init__(self):
        self.chain = [Block(None, Transaction(10, "Genesis", "Satoshi"))]

    def get_last_block(self):
        return self.chain[-1]

    @staticmethod
    def mine(nonce: int):
        solution = 1
        print("⛏️ Mining...")

        while True:
            md5_input = hashlib.md5(f"{nonce + solution}".encode())
            attempt = md5_input.hexdigest()

            if attempt[:6] == "000000":
                print(f"🎉 Success! {attempt}")
                return solution

            solution += 1

    def add_block(self, transaction: Transaction, sender_public_key, signature):
        pbk = sender_public_key.encode("utf-8")
        public_key = serialization.load_pem_public_key(pbk, backend=default_backend())
        try:
            public_key.verify(
                signature,
                hashlib.sha256(transaction.to_json().encode("ascii")).hexdigest().encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            new_block = Block(self.get_last_block().get_hash(), transaction)
            self.mine(new_block.nonce)
            self.chain.append(new_block)
        except InvalidSignature:
            print('invalid!')
