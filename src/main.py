from blockchain import Chain
from wallet import Wallet
import json

if __name__ == "__main__":
    Chain()
    alice = Wallet()
    bob = Wallet()
    alice.create_transaction(10, bob.wallet_address)
    print(json.dumps(Chain.instance.chain[1].__dict__, indent=4))
