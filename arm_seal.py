"""arm-encrypt P5 — the CLIENT side of the sealed arm.

The maker (seat) no longer sends plaintext trade terms on chain. Each confidential
item is SEALED:

    C         = keccak256(abi.encode(<full item struct>, salt32))   # commitment
    wraps     = [ciphertext, wrap_self, wrap_house]                  # HPKE envelope
    wrapsHash = keccak256(abi.encode(bytes[] wraps))
    sig       = seat sig over the sealed EIP-712 digest {publicFields, C, wrapsHash}

COUNTERPARTY PRIVACY — each side wraps ONLY to {itself, house}. When the maker
arms its half it seals to {maker(self), house}; the taker arms its own half to
{taker(self), house}. Neither side ever needs the other's encKey, so arming a
half leaks nothing about the counterparty. The arming seat recovers its half from
its own wrap; CRX (house) gets every half for its audit record; the counterparty
already holds the trade economics from signing its own half.

This module is a BYTE-EXACT mirror of the contract + guest at
/private/tmp/crx-arm-encrypt @ 7d0d6ee3 (Wire.sol / ArmLib.sol / ArmItems) and of
the Rust submitter at /private/tmp/crx-mono-p5 crx-api/src/sealed.rs. Its C /
wrapsHash / itemHash / itemId reproduce test/fixtures/arm-commit-parity.json.

SALT DISCIPLINE — the [[salt brute-force]] fix: the salt is a per-item CSPRNG draw
(`secrets.token_bytes(32)`). A low-entropy salt hashes to a grindable C; only a
client-side CSPRNG guarantees entropy. Never deterministic, never on chain.

ENCRYPTION — HPKE base mode (RFC 9180): DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
ChaCha20Poly1305. The bulk item is encrypted once under a fresh content_key
(ChaCha20Poly1305); the content_key is HPKE-sealed to each recipient's on-chain
`encKey` (a raw X25519 public key). Wrap layout:

    wraps[0] = nonce(12) || ChaCha20Poly1305(content_key, nonce, abi.encode(item)||salt)
    wraps[1] = enc(32) || HPKE-Seal(self.encKey, content_key)   # the arming seat
    wraps[2] = enc(32) || HPKE-Seal(house.encKey, content_key)  # CRX audit record

The chain binds only `wrapsHash`; the layout is a client/guest convention.
"""

import secrets

from eth_abi import encode as abi_encode
from eth_utils import keccak
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey

# ── arm kinds (Wire.sol) ──────────────────────────────────────────────────────
ARM_KIND_OPEN_SIDE = 7
ARM_KIND_ALLOCATION = 1
ARM_KIND_LIQ_RFQ = 8

# ── full-item struct field types (Wire.sol; the commitment preimage) ──────────
LEG_FULL_TYPES = ["address", "bytes32", "bytes32", "bytes32", "uint8", "int8",
                  "uint256", "uint64", "uint16", "int16", "uint40", "uint64", "uint64"]
LEG_FULL_FIELDS = ["seat", "legId", "joinRef", "pair", "instrumentId", "side",
                   "notional", "rate", "imBps", "premiumBps", "expiry", "nonce", "quoteExpiry"]

ALLOC_FULL_TYPES = ["bytes32", "bytes32", "bytes32", "address", "bytes32", "uint128",
                    "uint64", "uint16", "uint16", "uint128", "uint128", "int16", "uint64",
                    "uint64", "uint64", "bytes32", "uint8", "int8", "uint256", "uint40", "uint40"]
ALLOC_FULL_FIELDS = ["oldId", "exitingSide", "remainingSide", "incoming", "incomingSide",
                     "closeRate", "openRate", "cImBps", "bImBps", "cIm", "spread", "premiumBps",
                     "openNonce", "nonce", "deadline", "pairId", "instrumentId", "side",
                     "notional", "expiry", "settlement"]

CLOSE_FULL_TYPES = ["bytes32", "bytes32", "bytes32", "address", "bytes32", "bytes32",
                    "uint64", "uint128", "uint128", "uint64", "uint64", "uint16", "uint64",
                    "int16", "uint128"]
CLOSE_FULL_FIELDS = ["oldId", "closedOutSide", "remainingSide", "incoming", "incomingSide",
                     "feedId", "closeTime", "cIm", "spread", "nonce", "deadline", "cImBps",
                     "openNonce", "premiumBps", "subsidyMaxUsd"]

# ── public-subset struct field types (the only fields on chain) ───────────────
LEG_PUBLIC_TYPES = ["address", "bytes32", "uint64", "uint64"]
LEG_PUBLIC_FIELDS = ["seat", "legId", "nonce", "quoteExpiry"]

ALLOC_PUBLIC_TYPES = ["bytes32", "bytes32", "bytes32", "address", "bytes32", "uint64", "uint64", "uint64"]
ALLOC_PUBLIC_FIELDS = ["oldId", "exitingSide", "remainingSide", "incoming", "incomingSide",
                       "nonce", "openNonce", "deadline"]

CLOSE_PUBLIC_TYPES = ["bytes32", "bytes32", "bytes32", "address", "bytes32", "uint64", "uint64", "uint64"]
CLOSE_PUBLIC_FIELDS = ["oldId", "closedOutSide", "remainingSide", "incoming", "incomingSide",
                       "nonce", "openNonce", "deadline"]

# ── the 5 sealed EIP-712 type strings (Wire.sol EIP712Lib) ────────────────────
LEG_TYPE_STRING = ("Leg(address seat,bytes32 legId,uint64 nonce,uint64 quoteExpiry,"
                   "bytes32 commitment,bytes32 wrapsHash)")
ALLOCATION_CONSENT_TYPE_STRING = ("AllocationConsent(bytes32 oldId,bytes32 exitingSide,"
    "bytes32 remainingSide,address incoming,bytes32 incomingSide,uint64 nonce,uint64 deadline,"
    "bytes32 commitment,bytes32 wrapsHash)")
ALLOCATION_ACCEPTANCE_TYPE_STRING = ("AllocationAcceptance(bytes32 oldId,address taker,"
    "bytes32 incomingSide,uint64 nonce,uint64 deadline,bytes32 commitment,bytes32 wrapsHash)")
VOLUNTARY_ALLOCATION_OPEN_CONSENT_TYPE_STRING = ("VoluntaryAllocationOpenConsent(bytes32 commitment,"
    "uint64 nonce,uint64 deadline,bytes32 wrapsHash)")
FAILOVER_CONSENT_TYPE_STRING = ("FailoverConsent(bytes32 oldId,bytes32 closedOutSide,"
    "bytes32 remainingSide,address taker,bytes32 incomingSide,uint64 nonce,uint64 openNonce,"
    "uint64 deadline,bytes32 commitment,bytes32 wrapsHash)")


# ── small encoding helpers ────────────────────────────────────────────────────
def _b32(x):
    """Coerce a 0x-hex string or bytes to 32 raw bytes."""
    if isinstance(x, bytes):
        b = x
    else:
        b = bytes.fromhex(x[2:] if x.startswith("0x") else x)
    if len(b) != 32:
        raise ValueError(f"expected 32 bytes, got {len(b)}")
    return b


def _addr(x):
    return x if isinstance(x, str) else "0x" + x.hex()


def _tuple(fields, types, item):
    """Ordered value list for eth_abi, coercing bytes32 hex to raw bytes."""
    out = []
    for name, typ in zip(fields, types):
        v = item[name]
        if typ == "bytes32":
            v = _b32(v)
        out.append(v)
    return out


# ── commitment: C = keccak256(abi.encode(<full item struct>, salt)) ───────────
def commit(fields, types, item, salt):
    """C for any full item. abi.encode(item, salt): all-static struct inlines to
    bare field words, salt a raw 32-byte trailer — identical to the contract."""
    values = _tuple(fields, types, item) + [_b32(salt)]
    return keccak(abi_encode(types + ["bytes32"], values))


def commit_leg(leg, salt):
    return commit(LEG_FULL_FIELDS, LEG_FULL_TYPES, leg, salt)


def commit_alloc(item, salt):
    return commit(ALLOC_FULL_FIELDS, ALLOC_FULL_TYPES, item, salt)


def commit_closeout(item, salt):
    return commit(CLOSE_FULL_FIELDS, CLOSE_FULL_TYPES, item, salt)


# ── wrapsHash = keccak256(abi.encode(bytes[] wraps)) ──────────────────────────
def wraps_hash(wraps):
    """The bind ArmLib._sealedEnvelope runs: a stripped or swapped wrap fails it.
    ABI-encode of bytes[] (leading 0x20 offset), NOT packed."""
    return keccak(abi_encode(["bytes[]"], [list(wraps)]))


# ── public-field abi.encode (the on-chain publicFields bytes) ─────────────────
def encode_public(fields, types, item):
    return abi_encode([f"({','.join(types)})"], [_tuple(fields, types, item)])


# ── itemHash / itemId (ArmItems — abi.encodePacked of static words) ───────────
def _word_u(v):
    return int(v).to_bytes(32, "big")


def _packed(*chunks):
    return keccak(b"".join(chunks))


def _public_abi(fields, types, item):
    # abi.encode(publicStruct) with the struct inlined (all-static) — the bare words.
    return abi_encode([f"({','.join(types)})"], [_tuple(fields, types, item)])


def leg_item_hash(arm_time, leg, commitment, wh):
    tail = abi_encode(
        [f"({','.join(LEG_PUBLIC_TYPES)})", "bytes32", "bytes32"],
        [_tuple(LEG_PUBLIC_FIELDS, LEG_PUBLIC_TYPES, leg), _b32(commitment), _b32(wh)])
    return _packed(_word_u(ARM_KIND_OPEN_SIDE), _word_u(arm_time), tail)


def leg_item_id(leg):
    return _b32(leg["legId"])


def alloc_item_hash(arm_time, item, commitment, wh):
    tail = abi_encode(
        [f"({','.join(ALLOC_PUBLIC_TYPES)})", "bytes32", "bytes32"],
        [_tuple(ALLOC_PUBLIC_FIELDS, ALLOC_PUBLIC_TYPES, item), _b32(commitment), _b32(wh)])
    return _packed(_word_u(ARM_KIND_ALLOCATION), _word_u(arm_time), tail)


def alloc_item_id(item, commitment):
    tail = abi_encode(
        [f"({','.join(ALLOC_PUBLIC_TYPES)})", "bytes32"],
        [_tuple(ALLOC_PUBLIC_FIELDS, ALLOC_PUBLIC_TYPES, item), _b32(commitment)])
    return _packed(_word_u(ARM_KIND_ALLOCATION), tail)


def closeout_item_hash(arm_time, item, commitment, wh):
    tail = abi_encode(
        [f"({','.join(CLOSE_PUBLIC_TYPES)})", "bytes32", "bytes32"],
        [_tuple(CLOSE_PUBLIC_FIELDS, CLOSE_PUBLIC_TYPES, item), _b32(commitment), _b32(wh)])
    return _packed(_word_u(ARM_KIND_LIQ_RFQ), _word_u(arm_time), tail)


def closeout_item_id(item, commitment):
    tail = abi_encode(
        [f"({','.join(CLOSE_PUBLIC_TYPES)})", "bytes32"],
        [_tuple(CLOSE_PUBLIC_FIELDS, CLOSE_PUBLIC_TYPES, item), _b32(commitment)])
    return _packed(_word_u(ARM_KIND_LIQ_RFQ), tail)


# ── sealed EIP-712 digests (EIP712Lib) ────────────────────────────────────────
def _struct_hash(words):
    return keccak(b"".join(words))


def _digest(domain, struct_hash):
    return keccak(b"\x19\x01" + _b32(domain) + struct_hash)


def side_arm_digest(domain, leg, commitment, wh):
    sh = _struct_hash([
        keccak(text=LEG_TYPE_STRING),
        bytes(12) + bytes.fromhex(_addr(leg["seat"])[2:]),
        _b32(leg["legId"]),
        _word_u(leg["nonce"]),
        _word_u(leg["quoteExpiry"]),
        _b32(commitment),
        _b32(wh),
    ])
    return _digest(domain, sh)


def allocation_consent_digest(domain, item, commitment, wh):
    sh = _struct_hash([
        keccak(text=ALLOCATION_CONSENT_TYPE_STRING),
        _b32(item["oldId"]), _b32(item["exitingSide"]), _b32(item["remainingSide"]),
        bytes(12) + bytes.fromhex(_addr(item["incoming"])[2:]), _b32(item["incomingSide"]),
        _word_u(item["nonce"]), _word_u(item["deadline"]), _b32(commitment), _b32(wh),
    ])
    return _digest(domain, sh)


def allocation_acceptance_digest(domain, item, commitment, wh):
    sh = _struct_hash([
        keccak(text=ALLOCATION_ACCEPTANCE_TYPE_STRING),
        _b32(item["oldId"]), bytes(12) + bytes.fromhex(_addr(item["incoming"])[2:]),
        _b32(item["incomingSide"]), _word_u(item["nonce"]), _word_u(item["deadline"]),
        _b32(commitment), _b32(wh),
    ])
    return _digest(domain, sh)


def voluntary_open_consent_digest(domain, commitment, nonce, deadline, wh):
    sh = _struct_hash([
        keccak(text=VOLUNTARY_ALLOCATION_OPEN_CONSENT_TYPE_STRING),
        _b32(commitment), _word_u(nonce), _word_u(deadline), _b32(wh),
    ])
    return _digest(domain, sh)


def failover_consent_digest(domain, item, commitment, wh):
    sh = _struct_hash([
        keccak(text=FAILOVER_CONSENT_TYPE_STRING),
        _b32(item["oldId"]), _b32(item["closedOutSide"]), _b32(item["remainingSide"]),
        bytes(12) + bytes.fromhex(_addr(item["incoming"])[2:]), _b32(item["incomingSide"]),
        _word_u(item["nonce"]), _word_u(item["openNonce"]), _word_u(item["deadline"]),
        _b32(commitment), _b32(wh),
    ])
    return _digest(domain, sh)


# ── salt discipline ───────────────────────────────────────────────────────────
def random_salt():
    """A fresh 32-byte salt from the OS CSPRNG — the [[salt brute-force]] fix.
    NEVER deterministic, NEVER on chain."""
    return secrets.token_bytes(32)


def salt_is_weak(salt):
    """The submitter's backstop: reject an all-equal-bytes salt. A high-entropy
    salt this cheap check cannot vet still passes — the CSPRNG draw is the guarantee."""
    b = _b32(salt)
    return all(x == b[0] for x in b)


# ── HPKE base mode: DHKEM(X25519,HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305 ─
_HPKE_SUITE = lambda: CipherSuite.new(
    KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.CHACHA20_POLY1305)


def _pk_from_enckey(enc_key):
    """On-chain `encKey` bytes32 -> X25519 public key (raw 32-byte encoding)."""
    return KEMKey.from_pyca_cryptography_key(X25519PublicKey.from_public_bytes(_b32(enc_key)))


def _sk_from_bytes(sk):
    return KEMKey.from_pyca_cryptography_key(X25519PrivateKey.from_private_bytes(_b32(sk)))


def hpke_seal(enc_key, content_key):
    """wrap_i = enc(32) || HPKE-Seal(recipient.encKey, content_key)."""
    suite = _HPKE_SUITE()
    enc, sender = suite.create_sender_context(_pk_from_enckey(enc_key))
    ct = sender.seal(content_key)
    return enc + ct


def hpke_open(sk, wrap):
    """A recipient opens its wrap -> content_key."""
    enc, ct = wrap[:32], wrap[32:]
    suite = _HPKE_SUITE()
    recipient = suite.create_recipient_context(enc, _sk_from_bytes(sk))
    return recipient.open(ct)


def seal_item(plaintext, recipient_enc_keys):
    """Encrypt one item's `abi.encode(item)||salt` under a fresh content_key, then
    HPKE-seal that key to each recipient. Returns the `wraps` list:
        wraps[0]   = nonce(12) || ChaCha20Poly1305(content_key, nonce, plaintext)
        wraps[1:]  = enc || HPKE-Seal(encKey_i, content_key)  per recipient, in order
    `recipient_enc_keys` is [self.encKey, house.encKey] — the arming seat and CRX.
    The counterparty is NEVER a recipient, so a half-arm leaks nothing about it."""
    content_key = ChaCha20Poly1305.generate_key()  # 32 bytes
    nonce = secrets.token_bytes(12)
    ct = ChaCha20Poly1305(content_key).encrypt(nonce, plaintext, None)
    wraps = [nonce + ct]
    for ek in recipient_enc_keys:
        wraps.append(hpke_seal(ek, content_key))
    return wraps, content_key


def open_item(sk, wrap_index, wraps):
    """A recipient at `wrap_index` (1=self/arming seat, 2=house) opens its wrap and
    decrypts wraps[0] -> the item plaintext (`abi.encode(item)||salt`)."""
    content_key = hpke_open(sk, wraps[wrap_index])
    nonce, ct = wraps[0][:12], wraps[0][12:]
    return ChaCha20Poly1305(content_key).decrypt(nonce, ct, None)


def encode_item_plaintext(fields, types, item, salt):
    """The sealed plaintext: abi.encode(item, salt) — the same bytes hashed into C.
    A recipient decrypts to this, then re-derives C to prove the opening."""
    values = _tuple(fields, types, item) + [_b32(salt)]
    return abi_encode(types + ["bytes32"], values)


# ── the OPEN_SIDE client build: everything the seat produces for one half-arm ──
def build_open_side_sealed(chain_id, domain, leg, sign_hash, recipient_enc_keys,
                           salt=None, include_witness=False):
    """Produce the `/submit/open-side-sealed` request body for one seat's half-arm.

    - draws a CSPRNG salt (unless one is supplied — supply only for a fixture pin);
    - builds C over the FULL leg;
    - HPKE-seals the plaintext to [self, house] — never the counterparty;
    - signs the sealed Leg digest under `domain`;
    - returns the JSON body the Rust submitter (`open_side_sealed`) verifies.

    `sign_hash(digest_bytes) -> 0x-hex signature` is the seat's signer (e.g.
    `lambda d: Account.unsafe_sign_hash(d, SIGNER.key).signature.to_0x_hex()`).
    `include_witness=True` attaches the plaintext+salt so CRX (a house recipient)
    can re-derive C — defence in depth; omit it for a pure blind relay."""
    if salt is None:
        salt = random_salt()
    if salt_is_weak(salt):
        raise ValueError("refusing a weak salt — draw from secrets.token_bytes(32)")

    commitment = commit_leg(leg, salt)
    plaintext = encode_item_plaintext(LEG_FULL_FIELDS, LEG_FULL_TYPES, leg, salt)
    wraps, _ = seal_item(plaintext, recipient_enc_keys)
    wh = wraps_hash(wraps)
    digest = side_arm_digest(domain, leg, commitment, wh)
    sig = sign_hash(digest)

    body = {
        "chainId": chain_id,
        "public": {
            "seat": _addr(leg["seat"]),
            "legId": "0x" + _b32(leg["legId"]).hex(),
            "nonce": str(leg["nonce"]),
            "quoteExpiry": leg["quoteExpiry"],
        },
        "commitment": "0x" + commitment.hex(),
        "wrapsHash": "0x" + wh.hex(),
        "wraps": ["0x" + w.hex() for w in wraps],
        "sig": sig,
    }
    if include_witness:
        # WireLeg shape the submitter's `to_leg` expects: wide fields (notional,
        # rate, nonce) ride as STRINGS; bytes32 as 0x-hex; expiry seconds as int.
        body["witness"] = {
            "leg": {
                "seat": _addr(leg["seat"]),
                "legId": "0x" + _b32(leg["legId"]).hex(),
                "joinRef": "0x" + _b32(leg["joinRef"]).hex(),
                "pair": "0x" + _b32(leg["pair"]).hex(),
                "instrumentId": leg["instrumentId"],
                "side": leg["side"],
                "notional": str(leg["notional"]),
                "rate": str(leg["rate"]),
                "imBps": leg["imBps"],
                "premiumBps": leg["premiumBps"],
                "expiry": leg["expiry"],
                "nonce": str(leg["nonce"]),
                "quoteExpiry": leg["quoteExpiry"],
            },
            "salt": "0x" + _b32(salt).hex(),
        }
    return body, digest
