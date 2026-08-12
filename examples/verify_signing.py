from decimal import Decimal

from eth_abi import encode
from eth_account import Account
from eth_utils import keccak

TERMS_TYPE = ("Terms(address taker,address maker,uint256 notional,"
              "uint16 imBpsTaker,uint16 imBpsMaker,int16 premiumBps,"
              "uint40 expiry,uint64 nonce,uint8 instrumentId,bytes32 pair,"
              "int8 side,uint40 settlement,uint64 rate)")
TERMS_TYPEHASH = keccak(text=TERMS_TYPE)
DOMAIN_TYPEHASH = keccak(text="EIP712Domain(string name,string version,"
                              "uint256 chainId,address verifyingContract)")

CHAIN_ID = 84532
VERIFYING_CONTRACT = "0x8B1473D7e32E57d906f81567154a843b13cccE15"
TAKER = "0x1111111111111111111111111111111111111111"
MAKER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
NOTIONAL = int(Decimal("1500000.00").scaleb(6))
IM_BPS_TAKER = 250
IM_BPS_MAKER = 180
PREMIUM_BPS = 15
EXPIRY = 1789990000
CLIENT_QUOTE_ID = "q-001"
PAIR_TEXT = "USD/JPY"
INSTRUMENT_ID = 1          # non-deliverable forward
SIDE = 1                   # +1 buy, -1 sell
SETTLEMENT_MS = 1790000000000
RATE_SCALED = int(Decimal("156.4321").scaleb(6))
ANVIL_PK = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"

EXPECT_PAIR = "0x35b8bafff3570683af968b8d36b91b1a19465141d9712425e9f76c68ff8cb152"
EXPECT_DOMAIN_SEP = "0x2ab09df26fbdc3158d4e0588e388b6805f375822b6ee336a2234c1993a811e83"
EXPECT_NONCE = 10340973521660193082
EXPECT_STRUCT_HASH = "0x7b91ff86960ec7f338facc953b11c19b0c1d7904aea865f4387c5fb5a65ed1b6"
EXPECT_TERMS_HASH = "0x2e8b63d6d5588a2d80c76f6c7816cf8e106494552a8c823276ac1b755a09cd45"
EXPECT_SIG = ("0x5dd947ff43b1b51f004f8e66790c334b495c1b9b6184c4885025009fc5289a00"
              "2bfb80879835fb0b80b6d9616d317e29f8ecfc6f664db774335d5434751183581c")


def check(label, got, want):
    got = got if isinstance(got, str) else "0x" + got.hex()
    assert got.lower() == want.lower(), f"{label}: got {got}, want {want}"
    print("ok", label, got)


def main():
    nonce = int.from_bytes(
        keccak(bytes.fromhex(MAKER[2:]) + CLIENT_QUOTE_ID.encode())[-8:], "big")
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
        ["bytes32", "address", "address", "uint256", "uint16", "uint16", "int16",
         "uint40", "uint64", "uint8", "bytes32", "int8", "uint40", "uint64"],
        [TERMS_TYPEHASH, TAKER, MAKER, NOTIONAL, IM_BPS_TAKER, IM_BPS_MAKER,
         PREMIUM_BPS, EXPIRY, nonce, INSTRUMENT_ID, pair, SIDE,
         SETTLEMENT_MS // 1000, RATE_SCALED]))
    check("structHash", struct_hash, EXPECT_STRUCT_HASH)

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
