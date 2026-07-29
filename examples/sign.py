# sign.py: the 32 byte digest an HSM or Fireblocks signer must see, with no network write
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from eth_account import Account
from eth_utils import keccak
from crx_maker import ACCT, _digest

# a sample dict in rfq.opened shape, with fixture values from the signing docs page
RFQ = {"taker": "0x1111111111111111111111111111111111111111",
       "pair_id": "0x" + keccak(text="USD/JPY").hex(), "side": "buy",
       "settlement": 1790000000000, "notional": "1500000.00", "premium_bps": 15,
       "chain": "base"}

digest = _digest(RFQ, "156.4321", 250, 1789990000, "q-001")
sig = Account.unsafe_sign_hash(digest, ACCT.key).signature.to_0x_hex()
recovered = Account._recover_hash(digest, signature=sig)
assert recovered == ACCT.address, f"recovered {recovered} != signer {ACCT.address}"

print("terms_hash", "0x" + digest.hex())
print("sig", sig)
print("recovers to", recovered)
