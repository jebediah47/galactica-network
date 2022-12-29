from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import json
import hashlib


class Transaction:
    def __init__(self, amount, sender, recipient):
        self.amount = amount
        self.sender = sender
        self.recipient = recipient

    def to_json(self):
        return json.dumps(self.__dict__)


class Block:
    def __init__(self, previous_hash, transaction: Transaction):
        self.previous_hash = previous_hash
        self.transaction = transaction.to_json()
        self.timestamp = str(datetime.now(timezone.utc))

    def get_hash(self):
        sha_input = json.dumps(self.__dict__, sort_keys=True)
        return hashlib.sha256(sha_input.encode()).hexdigest()


class Chain:
    chain = [Block]

    def __init__(self):
        self.chain = [Block("", Transaction(10, "Genesis", "Satoshi"))]

    def get_last_block(self):
        return self.chain[-1]

    def add_block(self, transaction: Transaction):
        new_block = Block(self.get_last_block().get_hash(), transaction)
        self.chain.append(new_block)


chain_instance = Chain()


class Wallet:
    public_key: str
    private_key: str

    def __init__(self):
        keypair = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        # Encode the public key as SPKI and PEM
        public_key_bytes = keypair.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.public_key = public_key_bytes.decode("utf-8")

        # Encode the private key as PKCS#8 and PEM
        private_key_bytes = keypair.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        self.private_key = private_key_bytes.decode("utf-8")

    def create_transaction(self, amount, recipient):
        transaction = Transaction(amount, self.public_key, recipient)
        chain_instance.add_block(transaction=transaction)


if __name__ == "__main__":
    alice = Wallet()
    bob = Wallet()
    alice.create_transaction(10, bob.public_key)
    print(json.dumps(chain_instance.chain[1].__dict__, indent=4))
