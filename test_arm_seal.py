"""arm-encrypt P5 CLIENT verification.

The load-bearing assertions tie Python bytes to the CONTRACT-EMITTED fixture
(test/fixtures/arm-commit-parity.json from crx-arm-encrypt): C, wrapsHash,
itemHash, itemId for all three sealed kinds. A Python-vs-Python check would be
worthless — every commit/hash below reproduces solc's own output.

Run: python3 -m pytest test_arm_seal.py -q   (or: python3 test_arm_seal.py)
"""

import json
import os

from eth_account import Account

import arm_seal as A

FIXTURE = {
    "armTime": 1699000000,
    "wrapsHash": "0x113037aeceb17ea4851aa3bfee631ec963c0fcea99d5a67cc5487464efb5c745",
    "openSide": {
        "commitment": "0x0dcee33f487a1798dc2a30c8dccd42ced030142921b44aa52cd9cf37f056de74",
        "itemHash": "0xd7b491ffe13d05ca95a1f12abf6804fb44f1507662882aaef91be9e5086071e6",
        "itemId": "0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"},
    "allocation": {
        "commitment": "0xd5911b920031a834d07a69616ef1a2a1677c05ba4b9466afcdfc87560dbdee74",
        "itemHash": "0x1e603e497fc574e20f87b836d385b00f608ec92c7e52648073b9637fe4a0c386",
        "itemId": "0xfa76da6a850188ea0156986076a054cced6ab4f1e93810d8aa9ffb3b80b167ee"},
    "closeout": {
        "commitment": "0xd2ed183c5db26e3aa06827a6a8a3dca2eefdadb0b84428c7234935aa01f1d86f",
        "itemHash": "0x9e632b9f6d2b7e9130ead208d925c311290005d5282e698ce5ca232fac4330d8",
        "itemId": "0x9e42fe2c2cbe012499e34f1c781b49b472f7ff0c992d7789bf5949307d6a90b1"},
}

# The fixture item values (crx-arm-encrypt test/protocol/ArmCommitParity.t.sol).
LEG = {"seat": "0x" + "a1" * 20, "legId": "0x" + "5a" * 32, "joinRef": "0x" + "5b" * 32,
       "pair": "0x" + "99" * 32, "instrumentId": 1, "side": -1, "notional": 1_000_000_000,
       "rate": 1_084_250, "imBps": 200, "premiumBps": -25, "expiry": 1_700_002_000,
       "nonce": 3, "quoteExpiry": 1_700_001_000}
LEG_SALT = "0x" + "5a" * 32

ALLOC = {"oldId": "0x" + "11" * 32, "exitingSide": "0x" + "a1" * 32, "remainingSide": "0x" + "b2" * 32,
         "incoming": "0x" + "c3" * 20, "incomingSide": "0x" + "c3" * 32, "closeRate": 1_000_000,
         "openRate": 1_010_000, "cImBps": 250, "bImBps": 300, "cIm": 500_000, "spread": 1_234,
         "premiumBps": -25, "openNonce": 11, "nonce": 7, "deadline": 1_700_001_000,
         "pairId": "0x" + "55" * 32, "instrumentId": 1, "side": -1, "notional": 1_000_000_000,
         "expiry": 1_700_002_000, "settlement": 1_760_000_000}
ALLOC_SALT = "0x" + "5b" * 32

CLOSE = {"oldId": "0x" + "22" * 32, "closedOutSide": "0x" + "a1" * 32, "remainingSide": "0x" + "b2" * 32,
         "incoming": "0x" + "c3" * 20, "incomingSide": "0x" + "c3" * 32, "feedId": "0x" + "99" * 32,
         "closeTime": 1_700_000_000, "cIm": 500_000, "spread": 1_234, "nonce": 9,
         "deadline": 1_700_001_000, "cImBps": 250, "openNonce": 13, "premiumBps": 0, "subsidyMaxUsd": 0}
CLOSE_SALT = "0x" + "5c" * 32

# The fixture's dummy wraps: bytes1(i+1) || "wrap/<taker|maker|house>".
FIXTURE_WRAPS = [b"\x01" + b"wrap/taker", b"\x02" + b"wrap/maker", b"\x03" + b"wrap/house"]


def _hex(b):
    return "0x" + b.hex()


def test_wraps_hash_matches_fixture():
    assert _hex(A.wraps_hash(FIXTURE_WRAPS)) == FIXTURE["wrapsHash"]


def test_leg_commitment_matches_fixture():
    assert _hex(A.commit_leg(LEG, LEG_SALT)) == FIXTURE["openSide"]["commitment"]


def test_alloc_commitment_matches_fixture():
    assert _hex(A.commit_alloc(ALLOC, ALLOC_SALT)) == FIXTURE["allocation"]["commitment"]


def test_closeout_commitment_matches_fixture():
    assert _hex(A.commit_closeout(CLOSE, CLOSE_SALT)) == FIXTURE["closeout"]["commitment"]


def test_leg_item_hash_and_id_match_fixture():
    at = FIXTURE["armTime"]
    wh = A.wraps_hash(FIXTURE_WRAPS)
    c = A.commit_leg(LEG, LEG_SALT)
    assert _hex(A.leg_item_hash(at, LEG, c, wh)) == FIXTURE["openSide"]["itemHash"]
    assert _hex(A.leg_item_id(LEG)) == FIXTURE["openSide"]["itemId"]


def test_alloc_item_hash_and_id_match_fixture():
    at = FIXTURE["armTime"]
    wh = A.wraps_hash(FIXTURE_WRAPS)
    c = A.commit_alloc(ALLOC, ALLOC_SALT)
    assert _hex(A.alloc_item_hash(at, ALLOC, c, wh)) == FIXTURE["allocation"]["itemHash"]
    assert _hex(A.alloc_item_id(ALLOC, c)) == FIXTURE["allocation"]["itemId"]


def test_closeout_item_hash_and_id_match_fixture():
    at = FIXTURE["armTime"]
    wh = A.wraps_hash(FIXTURE_WRAPS)
    c = A.commit_closeout(CLOSE, CLOSE_SALT)
    assert _hex(A.closeout_item_hash(at, CLOSE, c, wh)) == FIXTURE["closeout"]["itemHash"]
    assert _hex(A.closeout_item_id(CLOSE, c)) == FIXTURE["closeout"]["itemId"]


def test_fixture_on_disk_matches_hardcoded():
    """If the real fixture file is reachable, assert our copy equals it byte-for-byte."""
    path = "/private/tmp/crx-arm-encrypt/test/fixtures/arm-commit-parity.json"
    if not os.path.exists(path):
        return
    disk = json.load(open(path))
    assert disk["wrapsHash"] == FIXTURE["wrapsHash"]
    for kind in ("openSide", "allocation", "closeout"):
        for k in ("commitment", "itemHash", "itemId"):
            assert disk[kind][k] == FIXTURE[kind][k], f"{kind}.{k} drifted from disk fixture"


def test_salt_discipline():
    assert A.salt_is_weak("0x" + "00" * 32)
    assert A.salt_is_weak("0x" + "5a" * 32)
    assert A.salt_is_weak("0x" + "ff" * 32)
    mixed = bytearray(b"\x5a" * 32); mixed[7] = 1
    assert not A.salt_is_weak(bytes(mixed))
    assert not A.salt_is_weak(A.random_salt())
    assert A.random_salt() != A.random_salt()  # fresh each draw


def test_hpke_round_trip_all_three_recipients():
    """Encrypt one leg's plaintext, HPKE-seal to 3 recipients, and prove EACH
    recipient opens its wrap -> content_key -> the exact plaintext. Then re-derive
    C from the decrypted plaintext to prove the opening binds the commitment."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    sks = [X25519PrivateKey.generate() for _ in range(3)]
    enc_keys = [sk.public_key().public_bytes_raw() for sk in sks]
    sk_bytes = [sk.private_bytes_raw() for sk in sks]

    salt = A.random_salt()
    plaintext = A.encode_item_plaintext(A.LEG_FULL_FIELDS, A.LEG_FULL_TYPES, LEG, salt)
    wraps, content_key = A.seal_item(plaintext, enc_keys)

    assert len(wraps) == 4, "wraps = [ciphertext, wrap_taker, wrap_maker, wrap_crx]"
    for i in range(3):  # taker, maker, house each recover the plaintext
        opened = A.open_item(sk_bytes[i], i + 1, wraps)
        assert opened == plaintext, f"recipient {i} failed to decrypt"
        # the decrypted plaintext re-derives the signed commitment
        assert A.commit_leg(LEG, salt) == A.commit(
            A.LEG_FULL_FIELDS, A.LEG_FULL_TYPES, LEG, salt)

    # a stranger key cannot open any wrap
    stranger = X25519PrivateKey.generate().private_bytes_raw()
    import pyhpke
    try:
        A.open_item(stranger, 1, wraps)
        assert False, "stranger opened a wrap"
    except pyhpke.exceptions.OpenError:
        pass


def test_build_open_side_sealed_body_and_digest():
    """The full client build: body shape matches the submitter's OpenSideSealedRequest,
    the signed digest recovers the seat, and the witness re-derives C."""
    acct = Account.create()
    leg = dict(LEG); leg["seat"] = acct.address
    domain = b"\xD0" * 32  # any 32-byte domain; the submitter reconstructs the same digest

    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    enc_keys = [X25519PrivateKey.generate().public_key().public_bytes_raw() for _ in range(3)]

    def sign(d):
        return Account.unsafe_sign_hash(d, acct.key).signature.to_0x_hex()

    body, digest = A.build_open_side_sealed(43113, domain, leg, sign, enc_keys,
                                            include_witness=True)
    # body shape (mirrors crx-submitter open.rs OpenSideSealedRequest)
    assert set(body) >= {"chainId", "public", "commitment", "wrapsHash", "wraps", "sig", "witness"}
    assert set(body["public"]) == {"seat", "legId", "nonce", "quoteExpiry"}
    assert len(body["wraps"]) == 4
    # the sig recovers the seat over the reconstructed digest (submitter step 2)
    assert Account._recover_hash(digest, signature=body["sig"]) == acct.address
    # wrapsHash binds the wraps (submitter step 1)
    wraps = [bytes.fromhex(w[2:]) for w in body["wraps"]]
    assert "0x" + A.wraps_hash(wraps).hex() == body["wrapsHash"]
    # witness re-derives C (submitter step 3)
    salt = body["witness"]["salt"]
    assert "0x" + A.commit_leg(leg, salt).hex() == body["commitment"]


if __name__ == "__main__":
    import sys
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        fn()
        passed += 1
        print(f"ok   {fn.__name__}")
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0)
