from blockchain import Transaction, Chain
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from Crypto.Hash import keccak
import hashlib


def generate_address(public_key: bytes) -> str:
    # Hash the public key using the Keccak-256 hash function
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(public_key)
    hash_bytes = keccak_hash.digest()

    # Take the last 20 bytes of the hash and convert them to an address
    address = '0x' + hash_bytes[-20:].hex()
    return address


class Wallet:
    public_key = None
    private_key = None
    wallet_address = None

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
        self.wallet_address = generate_address(public_key_bytes)

        # Encode the private key as PKCS#8 and PEM
        private_key_bytes = keypair.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        self.private_key = private_key_bytes.decode("utf-8")

    def create_transaction(self, amount, recipient):
        private_key = serialization.load_pem_private_key(
            self.private_key.encode("utf-8"),
            password=None
        )
        transaction = Transaction(amount, self.wallet_address, recipient)
        sig = private_key.sign(
            hashlib.sha256(transaction.to_json().encode("ascii")).hexdigest().encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        Chain.instance.add_block(transaction=transaction, sender_public_key=self.public_key, signature=sig)
