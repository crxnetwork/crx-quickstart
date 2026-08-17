import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from eth_account import Account
from eth_utils import keccak
from crx_maker import CUSTODY, SIGNER, _leg, _nonce, leg_digest

RFQ = {"rfq_id": "0x" + "ab" * 32, "chain": "base", "pair": "USDJPY",
       "pair_id": "0x" + keccak(text="USD/JPY").hex(),
       "leg_id": "0x" + "51" * 32, "join_ref": "0x" + "c9" * 32,
       "side": -1, "notional": "1500000.00", "premium_bps": 15,
       "expiry": 1790000000000, "quote_expiry": 1789900000000}

leg = _leg(RFQ, "156.432100", _nonce(CUSTODY, "q-001"))
digest = leg_digest(RFQ["chain"], leg)
sig = Account.unsafe_sign_hash(digest, SIGNER.key).signature.to_0x_hex()
recovered = Account._recover_hash(digest, signature=sig)
assert recovered == SIGNER.address, f"recovered {recovered} != signer {SIGNER.address}"

print("leg_hash", "0x" + digest.hex())
print("sig", sig)
print("recovers to", recovered)
