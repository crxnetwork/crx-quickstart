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


def test_hpke_round_trip_self_and_house_only():
    """Encrypt one leg's plaintext, HPKE-seal to ONLY {self, house}, and prove each
    of those two opens its wrap -> content_key -> the exact plaintext. Then re-derive
    C from the decrypted plaintext to prove the opening binds the commitment. The
    COUNTERPARTY is never a recipient: its key must fail to open any wrap, and the
    maker builds the envelope from self+house keys alone."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    # the arming seat (self) and CRX (house) — the ONLY two recipients
    self_sk = X25519PrivateKey.generate()
    house_sk = X25519PrivateKey.generate()
    enc_keys = [self_sk.public_key().public_bytes_raw(),
                house_sk.public_key().public_bytes_raw()]
    sk_bytes = [self_sk.private_bytes_raw(), house_sk.private_bytes_raw()]

    # the counterparty (taker) key is NOT passed to the maker's seal
    taker_sk = X25519PrivateKey.generate()

    salt = A.random_salt()
    plaintext = A.encode_item_plaintext(A.LEG_FULL_FIELDS, A.LEG_FULL_TYPES, LEG, salt)
    wraps, content_key = A.seal_item(plaintext, enc_keys)

    assert len(wraps) == 3, "wraps = [ciphertext, wrap_self, wrap_house]"
    for i in range(2):  # self, house each recover the plaintext
        opened = A.open_item(sk_bytes[i], i + 1, wraps)
        assert opened == plaintext, f"recipient {i} failed to decrypt"
        # the decrypted plaintext re-derives the signed commitment
        assert A.commit_leg(LEG, salt) == A.commit(
            A.LEG_FULL_FIELDS, A.LEG_FULL_TYPES, LEG, salt)

    import pyhpke
    # the counterparty (taker) is not a recipient — its key opens NO wrap
    for idx in (1, 2):
        try:
            A.open_item(taker_sk.private_bytes_raw(), idx, wraps)
            assert False, "taker opened a wrap — counterparty leak"
        except pyhpke.exceptions.OpenError:
            pass
    # an unrelated stranger key likewise cannot open any wrap
    stranger = X25519PrivateKey.generate().private_bytes_raw()
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
    # the maker builds with ONLY its own key + the house key — no taker key exists here
    enc_keys = [X25519PrivateKey.generate().public_key().public_bytes_raw() for _ in range(2)]

    def sign(d):
        return Account.unsafe_sign_hash(d, acct.key).signature.to_0x_hex()

    body, digest = A.build_open_side_sealed(43113, domain, leg, sign, enc_keys,
                                            include_witness=True)
    # body shape (mirrors crx-submitter open.rs OpenSideSealedRequest)
    assert set(body) >= {"chainId", "public", "commitment", "wrapsHash", "wraps", "sig", "witness"}
    assert set(body["public"]) == {"seat", "legId", "nonce", "quoteExpiry"}
    assert len(body["wraps"]) == 3  # [ciphertext, wrap_self, wrap_house]
    # the sig recovers the seat over the reconstructed digest (submitter step 2)
    assert Account._recover_hash(digest, signature=body["sig"]) == acct.address
    # wrapsHash binds the wraps (submitter step 1)
    wraps = [bytes.fromhex(w[2:]) for w in body["wraps"]]
    assert "0x" + A.wraps_hash(wraps).hex() == body["wrapsHash"]
    # witness re-derives C (submitter step 3)
    salt = body["witness"]["salt"]
    assert "0x" + A.commit_leg(leg, salt).hex() == body["commitment"]


def _fresh_enc_keys():
    """A maker's OWN two recipients [self, house] — the taker key is never here."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    self_sk = X25519PrivateKey.generate()
    house_sk = X25519PrivateKey.generate()
    enc = [self_sk.public_key().public_bytes_raw(), house_sk.public_key().public_bytes_raw()]
    sks = [self_sk.private_bytes_raw(), house_sk.private_bytes_raw()]
    return enc, sks


DOM = b"\xD0" * 32  # any 32-byte domain; the submitter reconstructs the same digest


def _acct_signer(acct):
    return lambda d: Account.unsafe_sign_hash(d, acct.key).signature.to_0x_hex()


def _alloc_parties():
    """Three distinct seat accounts for a true allocation (exitingSide/incomingSide/
    remainingSide all distinct in ALLOC). Returns (signers, exiting, incoming, remaining)."""
    ex, inc, rem = Account.create(), Account.create(), Account.create()
    signers = {"exiting": _acct_signer(ex), "incoming": _acct_signer(inc),
               "remaining": _acct_signer(rem)}
    return signers, ex, inc, rem


# ── ALLOCATION builder (multi-signature) ──────────────────────────────────────
def test_alloc_builder_csprng_salt_present_and_32b():
    signers, ex, inc, rem = _alloc_parties()
    item = dict(ALLOC); item["incoming"] = inc.address
    enc, _ = _fresh_enc_keys()
    b1, _ = A.build_allocation_sealed(43113, DOM, item, signers, enc,
                                      ex.address, rem.address, include_witness=True)
    b2, _ = A.build_allocation_sealed(43113, DOM, item, signers, enc,
                                      ex.address, rem.address, include_witness=True)
    s1 = bytes.fromhex(b1["witness"]["salt"][2:])
    assert len(s1) == 32
    assert not A.salt_is_weak(s1)
    assert b1["witness"]["salt"] != b2["witness"]["salt"]  # fresh CSPRNG each build


def test_alloc_builder_weak_salt_raises():
    """POSITIVE CONTROL: a weak (all-equal) salt is REFUSED by the builder. Without
    the guard it would sail through — the whole point of the [[salt brute-force]] fix."""
    signers, ex, inc, rem = _alloc_parties()
    item = dict(ALLOC); item["incoming"] = inc.address
    enc, _ = _fresh_enc_keys()
    ok, _ = A.build_allocation_sealed(43113, DOM, item, signers, enc,
                                      ex.address, rem.address, salt=A.random_salt())
    assert ok["commitment"].startswith("0x")
    import pytest
    with pytest.raises(ValueError):
        A.build_allocation_sealed(43113, DOM, item, signers, enc,
                                  ex.address, rem.address, salt=b"\x5b" * 32)


def test_alloc_builder_commitment_and_wrapshash_selfconsistent():
    signers, ex, inc, rem = _alloc_parties()
    item = dict(ALLOC); item["incoming"] = inc.address
    enc, _ = _fresh_enc_keys()
    salt = A.random_salt()
    body, consent = A.build_allocation_sealed(43113, DOM, item, signers, enc,
                                              ex.address, rem.address,
                                              salt=salt, include_witness=True)
    assert set(body) >= {"chainId", "public", "exitingSeat", "remainingSeat",
                         "commitment", "wrapsHash", "wraps", "sigs", "witness"}
    assert "sig" not in body  # allocation carries `sigs`, never a singular `sig`
    assert len(body["sigs"]) == 3  # allocation: [exiting, incoming, remaining]
    assert len(body["wraps"]) == 3  # [ciphertext, wrap_self, wrap_house]
    assert body["commitment"] == "0x" + A.commit_alloc(item, salt).hex()
    wraps = [bytes.fromhex(w[2:]) for w in body["wraps"]]
    assert body["wrapsHash"] == "0x" + A.wraps_hash(wraps).hex()
    assert Account._recover_hash(consent, signature=body["sigs"][0]) == ex.address
    assert "0x" + A.commit_alloc(item, body["witness"]["salt"]).hex() == body["commitment"]


def test_alloc_builder_plain_close_two_sigs():
    """Plain close (incomingSide == remainingSide): 2 sigs, BOTH over the SAME consent
    digest, and the client sets incoming == remainingSeat (allocation.rs:228-240)."""
    ex, rem = Account.create(), Account.create()
    signers = {"exiting": _acct_signer(ex), "remaining": _acct_signer(rem)}
    item = dict(ALLOC)
    item["incomingSide"] = item["remainingSide"]  # plain-close shape
    item["incoming"] = rem.address
    enc, _ = _fresh_enc_keys()
    salt = A.random_salt()
    body, consent = A.build_allocation_sealed(43113, DOM, item, signers, enc,
                                              ex.address, rem.address, salt=salt)
    assert len(body["sigs"]) == 2  # plain close: [exiting, remaining]
    assert Account._recover_hash(consent, signature=body["sigs"][0]) == ex.address
    assert Account._recover_hash(consent, signature=body["sigs"][1]) == rem.address


def test_alloc_builder_fixture_pinned_values():
    """Deliverable pin: the fixture alloc's C / itemHash / itemId reproduce the
    contract-emitted fixture (via the module funcs; the fixture salt is weak so the
    builder guard would reject it — parity lives in the funcs, the guard in the builder)."""
    at = FIXTURE["armTime"]
    wh = A.wraps_hash(FIXTURE_WRAPS)
    c = A.commit_alloc(ALLOC, ALLOC_SALT)
    assert _hex(c) == FIXTURE["allocation"]["commitment"]
    assert _hex(wh) == FIXTURE["wrapsHash"]
    assert _hex(A.alloc_item_hash(at, ALLOC, c, wh)) == FIXTURE["allocation"]["itemHash"]
    assert _hex(A.alloc_item_id(ALLOC, c)) == FIXTURE["allocation"]["itemId"]


def test_alloc_builder_hpke_self_house_only_no_counterparty_leak():
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    import pyhpke
    signers, ex, inc, rem = _alloc_parties()
    item = dict(ALLOC); item["incoming"] = inc.address
    enc, sks = _fresh_enc_keys()
    taker_sk = X25519PrivateKey.generate().private_bytes_raw()
    salt = A.random_salt()
    body, _ = A.build_allocation_sealed(43113, DOM, item, signers, enc,
                                        ex.address, rem.address,
                                        salt=salt, include_witness=True)
    wraps = [bytes.fromhex(w[2:]) for w in body["wraps"]]
    want = A.encode_item_plaintext(A.ALLOC_FULL_FIELDS, A.ALLOC_FULL_TYPES, item, salt)
    for i in range(2):  # self, house open their wrap -> plaintext
        assert A.open_item(sks[i], i + 1, wraps) == want
    for idx in (1, 2):  # the counterparty opens NO wrap
        try:
            A.open_item(taker_sk, idx, wraps)
            assert False, "taker opened an alloc wrap — counterparty leak"
        except pyhpke.exceptions.OpenError:
            pass


def test_alloc_interop_body_matches_rust_struct():
    """WIRE interop: every AllocationSealedRequest field (allocation.rs:90-111) present
    with the right JSON type, digests recover the right signers, body is serializable.
    Covers both modes."""
    import json
    signers, ex, inc, rem = _alloc_parties()
    item = dict(ALLOC); item["incoming"] = inc.address
    enc, _ = _fresh_enc_keys()
    body, _ = A.build_allocation_sealed(43113, DOM, item, signers, enc,
                                        ex.address, rem.address, include_witness=True)
    # top-level required fields + types
    assert isinstance(body["chainId"], int)
    assert set(body) == {"chainId", "public", "exitingSeat", "remainingSeat",
                         "commitment", "wrapsHash", "wraps", "sigs", "witness"}
    for k in ("exitingSeat", "remainingSeat", "commitment", "wrapsHash"):
        assert isinstance(body[k], str) and body[k].startswith("0x")
    assert isinstance(body["wraps"], list) and all(isinstance(w, str) for w in body["wraps"])
    assert isinstance(body["sigs"], list) and len(body["sigs"]) == 3
    # public subset: WireAllocationPublic — nonce/openNonce STRING, deadline int
    p = body["public"]
    assert set(p) == {"oldId", "exitingSide", "remainingSide", "incoming",
                      "incomingSide", "nonce", "openNonce", "deadline"}
    assert isinstance(p["nonce"], str) and isinstance(p["openNonce"], str)
    assert isinstance(p["deadline"], int)
    for k in ("oldId", "exitingSide", "remainingSide", "incoming", "incomingSide"):
        assert isinstance(p[k], str) and p[k].startswith("0x")
    # witness item: WireAllocationItem — wide fields STRING, small ints int
    wi = body["witness"]["item"]
    assert set(wi) == {"oldId", "exitingSide", "remainingSide", "incoming", "incomingSide",
                       "closeRate", "openRate", "cImBps", "bImBps", "cIm", "spread",
                       "premiumBps", "openNonce", "nonce", "deadline", "pairId",
                       "instrumentId", "side", "notional", "expiry", "settlement"}
    for k in ("closeRate", "openRate", "cIm", "spread", "openNonce", "nonce", "notional"):
        assert isinstance(wi[k], str), f"{k} must be a String for the Rust deserializer"
    for k in ("cImBps", "bImBps", "premiumBps", "deadline", "instrumentId", "side",
              "expiry", "settlement"):
        assert isinstance(wi[k], int), f"{k} must be an int"
    assert isinstance(body["witness"]["salt"], str)
    json.dumps(body)  # must serialize to JSON without error
    # digests recover the three declared signers under the same domain
    c, wh = body["commitment"], body["wrapsHash"]
    consent = A.allocation_consent_digest(DOM, item, c, wh)
    acceptance = A.allocation_acceptance_digest(DOM, item, c, wh)
    voluntary = A.voluntary_open_consent_digest(DOM, c, item["openNonce"], item["deadline"], wh)
    assert Account._recover_hash(consent, signature=body["sigs"][0]) == ex.address
    assert Account._recover_hash(acceptance, signature=body["sigs"][1]) == inc.address
    assert Account._recover_hash(voluntary, signature=body["sigs"][2]) == rem.address


# ── CLOSEOUT builder ──────────────────────────────────────────────────────────
def test_closeout_builder_csprng_salt_present_and_32b():
    acct = Account.create()
    item = dict(CLOSE); item["incoming"] = acct.address
    enc, _ = _fresh_enc_keys()
    sign = lambda d: Account.unsafe_sign_hash(d, acct.key).signature.to_0x_hex()
    b1, _ = A.build_closeout_sealed(43113, b"\xD0" * 32, item, sign, enc, include_witness=True)
    b2, _ = A.build_closeout_sealed(43113, b"\xD0" * 32, item, sign, enc, include_witness=True)
    s1 = bytes.fromhex(b1["witness"]["salt"][2:])
    assert len(s1) == 32
    assert not A.salt_is_weak(s1)
    assert b1["witness"]["salt"] != b2["witness"]["salt"]


def test_closeout_builder_weak_salt_raises():
    """POSITIVE CONTROL: the closeout builder REFUSES a weak salt; without the guard
    it would pass."""
    acct = Account.create()
    item = dict(CLOSE); item["incoming"] = acct.address
    enc, _ = _fresh_enc_keys()
    sign = lambda d: Account.unsafe_sign_hash(d, acct.key).signature.to_0x_hex()
    ok, _ = A.build_closeout_sealed(43113, b"\xD0" * 32, item, sign, enc, salt=A.random_salt())
    assert ok["commitment"].startswith("0x")
    import pytest
    with pytest.raises(ValueError):
        A.build_closeout_sealed(43113, b"\xD0" * 32, item, sign, enc, salt=b"\x5c" * 32)


def test_closeout_builder_commitment_and_wrapshash_selfconsistent():
    acct = Account.create()
    item = dict(CLOSE); item["incoming"] = acct.address
    enc, _ = _fresh_enc_keys()
    sign = lambda d: Account.unsafe_sign_hash(d, acct.key).signature.to_0x_hex()
    salt = A.random_salt()
    body, digest = A.build_closeout_sealed(43113, b"\xD0" * 32, item, sign, enc,
                                           salt=salt, include_witness=True)
    assert set(body) >= {"chainId", "public", "commitment", "wrapsHash", "wraps", "sig", "witness"}
    assert set(body["public"]) == {"oldId", "closedOutSide", "remainingSide", "incoming",
                                    "incomingSide", "nonce", "openNonce", "deadline"}
    assert len(body["wraps"]) == 3
    assert body["commitment"] == "0x" + A.commit_closeout(item, salt).hex()
    wraps = [bytes.fromhex(w[2:]) for w in body["wraps"]]
    assert body["wrapsHash"] == "0x" + A.wraps_hash(wraps).hex()
    assert Account._recover_hash(digest, signature=body["sig"]) == acct.address
    assert "0x" + A.commit_closeout(item, body["witness"]["salt"]).hex() == body["commitment"]


def test_closeout_builder_fixture_pinned_values():
    at = FIXTURE["armTime"]
    wh = A.wraps_hash(FIXTURE_WRAPS)
    c = A.commit_closeout(CLOSE, CLOSE_SALT)
    assert _hex(c) == FIXTURE["closeout"]["commitment"]
    assert _hex(A.closeout_item_hash(at, CLOSE, c, wh)) == FIXTURE["closeout"]["itemHash"]
    assert _hex(A.closeout_item_id(CLOSE, c)) == FIXTURE["closeout"]["itemId"]


def test_closeout_builder_hpke_self_house_only_no_counterparty_leak():
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    import pyhpke
    acct = Account.create()
    item = dict(CLOSE); item["incoming"] = acct.address
    enc, sks = _fresh_enc_keys()
    taker_sk = X25519PrivateKey.generate().private_bytes_raw()
    sign = lambda d: Account.unsafe_sign_hash(d, acct.key).signature.to_0x_hex()
    salt = A.random_salt()
    body, _ = A.build_closeout_sealed(43113, b"\xD0" * 32, item, sign, enc,
                                      salt=salt, include_witness=True)
    wraps = [bytes.fromhex(w[2:]) for w in body["wraps"]]
    want = A.encode_item_plaintext(A.CLOSE_FULL_FIELDS, A.CLOSE_FULL_TYPES, item, salt)
    for i in range(2):
        assert A.open_item(sks[i], i + 1, wraps) == want
    for idx in (1, 2):
        try:
            A.open_item(taker_sk, idx, wraps)
            assert False, "taker opened a closeout wrap — counterparty leak"
        except pyhpke.exceptions.OpenError:
            pass


def test_closeout_interop_body_matches_rust_struct():
    """WIRE interop: every LiqRfqSealedRequest field (liq_rfq.rs:71-88) present with the
    right JSON type — SINGULAR `sig`, and witness.closeTime a STRING (the Break B fix:
    WireCloseoutItem.close_time is String, parse_u64 liq_rfq.rs:122). Serializable."""
    import json
    acct = Account.create()
    item = dict(CLOSE); item["incoming"] = acct.address
    enc, _ = _fresh_enc_keys()
    sign = _acct_signer(acct)
    body, digest = A.build_closeout_sealed(43113, DOM, item, sign, enc, include_witness=True)
    assert isinstance(body["chainId"], int)
    assert set(body) == {"chainId", "public", "commitment", "wrapsHash", "wraps", "sig", "witness"}
    assert "sigs" not in body  # closeout carries a SINGULAR `sig`
    assert isinstance(body["sig"], str) and body["sig"].startswith("0x")
    for k in ("commitment", "wrapsHash"):
        assert isinstance(body[k], str) and body[k].startswith("0x")
    p = body["public"]
    assert set(p) == {"oldId", "closedOutSide", "remainingSide", "incoming",
                      "incomingSide", "nonce", "openNonce", "deadline"}
    assert isinstance(p["nonce"], str) and isinstance(p["openNonce"], str)
    assert isinstance(p["deadline"], int)
    wi = body["witness"]["item"]
    assert set(wi) == {"oldId", "closedOutSide", "remainingSide", "incoming", "incomingSide",
                       "feedId", "closeTime", "cIm", "spread", "nonce", "deadline",
                       "cImBps", "openNonce", "premiumBps", "subsidyMaxUsd"}
    # every String-typed field on WireCloseoutItem — closeTime the load-bearing one
    for k in ("closeTime", "cIm", "spread", "nonce", "openNonce", "subsidyMaxUsd"):
        assert isinstance(wi[k], str), f"{k} must be a String for the Rust deserializer"
    assert isinstance(wi["closeTime"], str) and wi["closeTime"] == str(item["closeTime"])
    for k in ("deadline", "cImBps", "premiumBps"):
        assert isinstance(wi[k], int), f"{k} must be an int"
    json.dumps(body)  # serializable
    # the singular sig recovers the incoming maker over the failover consent digest
    assert Account._recover_hash(digest, signature=body["sig"]) == acct.address


# ── The sealed submit WITNESS is MANDATORY ─────────────────────────────────────
# The submitter refuses a witness-less sealed submit (400). So every client builder
# DEFAULTS include_witness=True — a caller may pass False explicitly.
def test_default_sealed_body_includes_witness_all_three():
    """With NO include_witness argument, each builder attaches a witness carrying
    the plaintext terms + salt, and the salt re-derives C."""
    # OPEN_SIDE — witness rides the terms under `leg`
    acct = Account.create()
    leg = dict(LEG); leg["seat"] = acct.address
    enc, _ = _fresh_enc_keys()
    body, _ = A.build_open_side_sealed(43113, DOM, leg, _acct_signer(acct), enc)  # default
    assert "witness" in body, "default open-side build MUST carry a witness"
    assert set(body["witness"]) == {"leg", "salt"}
    assert "0x" + A.commit_leg(leg, body["witness"]["salt"]).hex() == body["commitment"]

    # ALLOCATION — witness rides the terms under `item`
    signers, ex, inc, rem = _alloc_parties()
    item = dict(ALLOC); item["incoming"] = inc.address
    enc, _ = _fresh_enc_keys()
    body, _ = A.build_allocation_sealed(43113, DOM, item, signers, enc,
                                        ex.address, rem.address)  # default
    assert "witness" in body, "default allocation build MUST carry a witness"
    assert set(body["witness"]) == {"item", "salt"}
    assert "0x" + A.commit_alloc(item, body["witness"]["salt"]).hex() == body["commitment"]

    # CLOSEOUT — witness rides the terms under `item`
    acct = Account.create()
    ci = dict(CLOSE); ci["incoming"] = acct.address
    enc, _ = _fresh_enc_keys()
    body, _ = A.build_closeout_sealed(43113, DOM, ci, _acct_signer(acct), enc)  # default
    assert "witness" in body, "default closeout build MUST carry a witness"
    assert set(body["witness"]) == {"item", "salt"}
    assert "0x" + A.commit_closeout(ci, body["witness"]["salt"]).hex() == body["commitment"]


def test_caller_can_still_opt_out_of_witness():
    """A caller MAY pass include_witness=False (e.g. a pure blind relay / test)."""
    acct = Account.create()
    leg = dict(LEG); leg["seat"] = acct.address
    enc, _ = _fresh_enc_keys()
    body, _ = A.build_open_side_sealed(43113, DOM, leg, _acct_signer(acct), enc,
                                       include_witness=False)
    assert "witness" not in body


def test_witness_tls_guard():
    """The witness is PLAINTEXT terms over the wire. The send-path guard refuses a
    witness-bearing body over plain http:// to a REMOTE host, but allows https and
    allows http to localhost/127.0.0.1 (dev). A witness-less body is never blocked."""
    import pytest
    os.environ.setdefault("CRX_SIGNER_PK", "0x" + "11" * 32)
    os.environ.setdefault("CRX_CUSTODY", "0x" + "ab" * 20)
    import crx_maker as cm

    w = {"witness": {"item": {}, "salt": "0x" + "5a" * 32}, "chainId": 43113}

    # http → remote host: REFUSED
    with pytest.raises(cm.CrxError) as e:
        cm._guard_witness_tls("http://api.crxfx.com/submit/open-side-sealed", w)
    assert e.value.code == "witness_plaintext_over_http"

    # https → remote host: allowed
    cm._guard_witness_tls("https://api.crxfx.com/submit/open-side-sealed", w)
    # http → localhost / 127.0.0.1 dev: allowed
    cm._guard_witness_tls("http://localhost:8080/submit/open-side-sealed", w)
    cm._guard_witness_tls("http://127.0.0.1:8080/submit/open-side-sealed", w)
    # witness-LESS body over remote http: never blocked (guard fires only on a witness)
    cm._guard_witness_tls("http://api.crxfx.com/submit/open-side-sealed", {"chainId": 43113})


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
