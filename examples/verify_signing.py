from decimal import Decimal

from eth_abi import encode
from eth_account import Account
from eth_utils import keccak

LEG_TYPE = ("Leg(address seat,bytes32 legId,bytes32 joinRef,bytes32 pair,"
            "uint8 instrumentId,int8 side,uint256 notional,uint64 rate,"
            "uint16 imBps,int16 premiumBps,uint40 expiry,uint64 nonce,"
            "uint64 quoteExpiry)")
LEG_TYPEHASH = keccak(text=LEG_TYPE)
DOMAIN_TYPEHASH = keccak(text="EIP712Domain(string name,string version,"
                              "uint256 chainId,address verifyingContract)")

CHAIN_ID = 84532
VERIFYING_CONTRACT = "0x8B1473D7e32E57d906f81567154a843b13cccE15"
SEAT = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
LEG_ID = "0x" + "51" * 32
JOIN_REF = "0x" + "c9" * 32
PAIR_TEXT = "USD/JPY"
INSTRUMENT_ID = 1          # non-deliverable forward
SIDE = 1                   # +1 long base, -1 short
NOTIONAL = int(Decimal("1500000.00").scaleb(6))
RATE_SCALED = int(Decimal("156.432100").scaleb(6))
IM_BPS = 100
PREMIUM_BPS = 15
EXPIRY_MS = 1790000000000
QUOTE_EXPIRY_MS = 1789900000000
CLIENT_QUOTE_ID = "q-001"
ANVIL_PK = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"

EXPECT_TYPEHASH = "0xed58881040e9bb236e6bdeb1542698f7e4b79e5b05e4dd8eec08cc2e6ac868fa"
EXPECT_PAIR = "0x35b8bafff3570683af968b8d36b91b1a19465141d9712425e9f76c68ff8cb152"
EXPECT_DOMAIN_SEP = "0x2ab09df26fbdc3158d4e0588e388b6805f375822b6ee336a2234c1993a811e83"
EXPECT_NONCE = 10340973521660193082
EXPECT_STRUCT_HASH = "0xe865aef3e71f66dbf8587ad5983daa0a635fbb56e25a114a37e38f6dc49a12ea"
EXPECT_LEG_HASH = "0x1d4a34965bb30a2c5d303774521df41470c0c10bc01e0a7f397343a1c73af41b"
EXPECT_SIG = ("0x1f993377b84c2aa24a736bcd4f043357f1f5f2ad0b785aded6e51f7636c681e9"
              "62f7ee41704ef66980dd7ba1819d6c85374ba1245034068f2e0d2196cf4646d41c")


def check(label, got, want):
    got = got if isinstance(got, str) else "0x" + got.hex()
    assert got.lower() == want.lower(), f"{label}: got {got}, want {want}"
    print("ok", label, got)


def main():
    check("leg_typehash", LEG_TYPEHASH, EXPECT_TYPEHASH)

    nonce = int.from_bytes(
        keccak(bytes.fromhex(SEAT[2:]) + CLIENT_QUOTE_ID.encode())[-8:], "big")
    assert nonce == EXPECT_NONCE, f"nonce: got {nonce}, want {EXPECT_NONCE}"
    print("ok", "nonce", nonce)

    pair = keccak(text=PAIR_TEXT)
    check("pair", pair, EXPECT_PAIR)

    domain_sep = keccak(encode(
        ["bytes32", "bytes32", "bytes32", "uint256", "address"],
        [DOMAIN_TYPEHASH, keccak(text="CRX"), keccak(text="rulebook-1.0"),
         CHAIN_ID, VERIFYING_CONTRACT]))
    check("domainSeparator", domain_sep, EXPECT_DOMAIN_SEP)

    struct_hash = keccak(encode(
        ["bytes32", "address", "bytes32", "bytes32", "bytes32", "uint8", "int8",
         "uint256", "uint64", "uint16", "int16", "uint40", "uint64", "uint64"],
        [LEG_TYPEHASH, SEAT, bytes.fromhex(LEG_ID[2:]), bytes.fromhex(JOIN_REF[2:]),
         pair, INSTRUMENT_ID, SIDE, NOTIONAL, RATE_SCALED, IM_BPS, PREMIUM_BPS,
         EXPIRY_MS // 1000, nonce, QUOTE_EXPIRY_MS // 1000]))
    check("structHash", struct_hash, EXPECT_STRUCT_HASH)

    leg_hash = keccak(b"\x19\x01" + domain_sep + struct_hash)
    check("leg_hash", leg_hash, EXPECT_LEG_HASH)

    acct = Account.from_key(ANVIL_PK)
    assert acct.address == SEAT, f"derived address {acct.address} != fixture seat {SEAT}"
    sig = Account.unsafe_sign_hash(leg_hash, acct.key).signature.to_0x_hex()
    check("signature", sig, EXPECT_SIG)
    recovered = Account._recover_hash(leg_hash, signature=sig)
    assert recovered == SEAT, f"recovered {recovered} != seat {SEAT}"
    print("ok", "recovers to seat", recovered)

    print("all checks passed")


if __name__ == "__main__":
    main()
