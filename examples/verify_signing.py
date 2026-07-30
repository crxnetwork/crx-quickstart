# verify_signing.py: recompute the signing math against the worked fixture, offline and without env
from decimal import Decimal

from eth_abi import encode
from eth_account import Account
from eth_utils import keccak

# --- the same constants crx_maker.py derives ---
TERMS_TYPE = ("Terms(address taker,address maker,uint256 notional,"
              "uint16 imBpsTaker,uint16 imBpsMaker,uint16 premiumBps,"
              "uint40 expiry,uint64 nonce,bytes instrument)")
TERMS_TYPEHASH = keccak(text=TERMS_TYPE)
DOMAIN_TYPEHASH = keccak(text="EIP712Domain(string name,string version,"
                              "uint256 chainId,address verifyingContract)")

# --- the fixture, copied from api/signing.md ---
CHAIN_ID = 84532
VERIFYING_CONTRACT = "0x8B1473D7e32E57d906f81567154a843b13cccE15"   # a fixture
TAKER = "0x1111111111111111111111111111111111111111"
MAKER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"                # the public Anvil test key
NOTIONAL = int(Decimal("1500000.00").scaleb(6))                     # = 1500000000000
IM_BPS_TAKER = 250
IM_BPS_MAKER = 180
PREMIUM_BPS = 15
EXPIRY = 1789990000
CLIENT_QUOTE_ID = "q-001"
PAIR_TEXT = "USD/JPY"
SIDE = 1                                                            # buy is +1
SETTLEMENT_MS = 1790000000000                                       # wire settlement, unix ms
RATE_SCALED = int(Decimal("156.4321").scaleb(6))                    # = 156432100
ANVIL_PK = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"

EXPECT_INSTRUMENT = "0x0135b8bafff3570683af968b8d36b91b1a19465141d9712425e9f76c68ff8cb15201006ab13b80000000000952f6e4"
EXPECT_KECCAK_INSTR = "0x6d948f925ce346f204fd7a0133a56bed3bbeec98f156e88747da479f949aa671"
EXPECT_DOMAIN_SEP = "0x2ab09df26fbdc3158d4e0588e388b6805f375822b6ee336a2234c1993a811e83"
EXPECT_NONCE = 10340973521660193082
EXPECT_STRUCT_HASH = "0x2b9338f9459c6474129e4c4efca4eed422d4bb3d05a93e9c6ad36a551221b1ec"
EXPECT_TERMS_HASH = "0x637a4ad24405a410bdf315c2f8e999381b3136303d99e546701127fc8bfd4712"
EXPECT_SIG = ("0x9e28154d2bfcb26a912d9c93d80eb49cca709945f1013690683cd83952ea23994585e850687547fe2f8"
              "33670bcb99ceaa016615ea5768af276221f7d49daaa611c")


def check(label, got, want):
    got = got if isinstance(got, str) else "0x" + got.hex()
    assert got.lower() == want.lower(), f"{label}: got {got}, want {want}"
    print("ok", label, got)


def main():
    # nonce: low 8 bytes of keccak256(maker || client_quote_id)
    nonce = int.from_bytes(
        keccak(bytes.fromhex(MAKER[2:]) + CLIENT_QUOTE_ID.encode())[-8:], "big")
    assert nonce == EXPECT_NONCE, f"nonce: got {nonce}, want {EXPECT_NONCE}"
    print("ok", "nonce", nonce)

    # the wire carries settlement in unix ms while the signed u40 header packs seconds
    pair_id = keccak(text=PAIR_TEXT)
    instrument = (b"\x01" + pair_id + (SIDE & 0xFF).to_bytes(1, "big")
                  + (SETTLEMENT_MS // 1000).to_bytes(5, "big") + RATE_SCALED.to_bytes(8, "big"))
    assert len(instrument) == 47, f"instrument length: got {len(instrument)}, want 47"
    check("instrument", instrument, EXPECT_INSTRUMENT)

    keccak_instr = keccak(instrument)
    check("keccak(instrument)", keccak_instr, EXPECT_KECCAK_INSTR)

    domain_sep = keccak(encode(
        ["bytes32", "bytes32", "bytes32", "uint256", "address"],
        [DOMAIN_TYPEHASH, keccak(text="CRX"), keccak(text="rulebook-1.0"),
         CHAIN_ID, VERIFYING_CONTRACT]))
    check("domainSeparator", domain_sep, EXPECT_DOMAIN_SEP)

    # structHash over the nine Terms fields, instrument hashed last as its keccak
    struct_hash = keccak(encode(
        ["bytes32", "address", "address", "uint256", "uint16", "uint16",
         "uint16", "uint40", "uint64", "bytes32"],
        [TERMS_TYPEHASH, TAKER, MAKER, NOTIONAL, IM_BPS_TAKER, IM_BPS_MAKER,
         PREMIUM_BPS, EXPIRY, nonce, keccak_instr]))
    check("structHash", struct_hash, EXPECT_STRUCT_HASH)

    # terms_hash is the raw 0x1901 EIP-712 digest
    terms_hash = keccak(b"\x19\x01" + domain_sep + struct_hash)
    check("terms_hash", terms_hash, EXPECT_TERMS_HASH)

    acct = Account.from_key(ANVIL_PK)
    assert acct.address == MAKER, f"derived address {acct.address} != fixture maker {MAKER}"
    sig = Account.unsafe_sign_hash(terms_hash, acct.key).signature.to_0x_hex()
    check("signature", sig, EXPECT_SIG)
    recovered = Account._recover_hash(terms_hash, signature=sig)
    assert recovered == MAKER, f"recovered {recovered} != maker {MAKER}"
    print("ok", "recovers to maker", recovered)

    print("all checks passed")


if __name__ == "__main__":
    main()
