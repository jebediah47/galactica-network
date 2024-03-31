from blockchain import Chain
from wallet import Wallet
import json

if __name__ == "__main__":
    Chain()
    alice = Wallet(initial_balance=69.69)
    bob = Wallet(initial_balance=72.8)
    print("Initial Balance:", alice.get_balance())
    print("Initial Balance:", bob.get_balance())
    alice.create_transaction(72, bob.wallet_address)
    bob.create_transaction(6.9, alice.wallet_address)
    print(json.dumps(Chain.instance.chain[1].__dict__, indent=4))
    print(json.dumps(Chain.instance.chain[2].__dict__, indent=4))
