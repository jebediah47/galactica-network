from blockchain import Transaction, Chain
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


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
        Chain.instance.add_block(transaction=transaction)
