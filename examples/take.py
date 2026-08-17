import asyncio, json, os, sys, time, uuid
from decimal import Decimal

import requests, websockets
from eth_abi import encode
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak

BASE = os.environ.get("CRX_BASE", "https://api.crxfx.com").rstrip("/")
SIGNER = Account.from_key(os.environ["CRX_TAKER_SIGNER_PK"])
CUSTODY = os.environ["CRX_TAKER_CUSTODY"].lower()
CHAIN, PAIR, SIDE, NOTIONAL = "base", "USDJPY", "buy", "25000.00"
EXPIRY_MS = (int(time.time()) + 7 * 86400) * 1000

LEG_TYPEHASH = keccak(text="Leg(address seat,bytes32 legId,bytes32 joinRef,bytes32 pair,"
                           "uint8 instrumentId,int8 side,uint256 notional,uint64 rate,"
                           "uint16 imBps,int16 premiumBps,uint40 expiry,uint64 nonce,"
                           "uint64 quoteExpiry)")
DOMAIN_TYPEHASH = keccak(text="EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
NDF = 1  # instrumentId for the non-deliverable forward
FLAT_IM_BPS = 100


def _ws(base):
    return base.replace("https://", "wss://").replace("http://", "ws://")


def _body(r):
    try:
        b = r.json()
    except ValueError:
        raise RuntimeError(f"non-JSON from {r.url}: {r.text[:120]!r}") from None
    if r.status_code >= 400:
        raise RuntimeError(f"{r.status_code} {b}")
    return b


_chains = _body(requests.get(f"{BASE}/health", timeout=10))["chains"]
_c = next(x for x in _chains if x["key"] == CHAIN)
CHAIN_ID = _chains[0]["chain_id"]
SEP = keccak(encode(["bytes32", "bytes32", "bytes32", "uint256", "address"],
                    [DOMAIN_TYPEHASH, keccak(text="CRX"), keccak(text="rulebook-1.0"),
                     _c["chain_id"], _c["core"]]))
assert "0x" + SEP.hex() == _c["domain"], "domain mismatch, refuse to sign"


def hello(nonce):
    return "\n".join(["CRX-WS-LOGIN", "Audience: crx-gateway", f"Chain: {CHAIN_ID}",
                      f"Custody: {CUSTODY}", f"Signer: {SIGNER.address.lower()}", f"Nonce: {nonce}"])


async def ws_logon(ws):
    challenge = json.loads(await ws.recv())
    assert challenge.get("type") == "challenge", f"expected challenge, got {challenge.get('type')}"
    sig = Account.sign_message(encode_defunct(text=hello(challenge["nonce"])), SIGNER.key).signature.to_0x_hex()
    await ws.send(json.dumps({"type": "logon", "signer": SIGNER.address.lower(), "custody": CUSTODY, "sig": sig}))
    async for raw in ws:
        frame = json.loads(raw)
        if frame["type"] == "logon_ack":
            return frame["data"]
        if frame["type"] == "error":
            data = frame.get("data") or {}
            print("logon refused:", data.get("code"), data.get("message"))
            sys.exit(1)


def taker_leg(q, leg_id, quote_expiry, rfq_id):
    nonce = int.from_bytes(keccak(bytes.fromhex(CUSTODY[2:]) + rfq_id.encode())[-8:], "big")
    return {"seat": CUSTODY, "leg_id": leg_id, "join_ref": q["join_ref"],
            "pair_id": q["pair_id"], "instrument_id": NDF, "side": q["side"],
            "notional": q["notional"], "rate": q["rate"], "im_bps": FLAT_IM_BPS,
            "premium_bps": q["premium_bps"], "expiry": q["expiry"],
            "nonce": str(nonce), "quote_expiry": quote_expiry}


def leg_digest(leg):
    struct_hash = keccak(encode(
        ["bytes32", "address", "bytes32", "bytes32", "bytes32", "uint8", "int8",
         "uint256", "uint64", "uint16", "int16", "uint40", "uint64", "uint64"],
        [LEG_TYPEHASH, leg["seat"], bytes.fromhex(leg["leg_id"][2:]),
         bytes.fromhex(leg["join_ref"][2:]), bytes.fromhex(leg["pair_id"][2:]),
         leg["instrument_id"], leg["side"], int(Decimal(leg["notional"]).scaleb(6)),
         int(Decimal(leg["rate"]).scaleb(6)), leg["im_bps"], leg["premium_bps"],
         leg["expiry"] // 1000, int(leg["nonce"]), leg["quote_expiry"] // 1000]))
    return keccak(b"\x19\x01" + SEP + struct_hash)


HDR = {"content-type": "application/json"}


def sign_rest(method, path, custody, signer_acct, nonce=None):
    ts = int(time.time() * 1000)
    nonce = nonce or uuid.uuid4().hex
    custody = custody.lower()
    signer = signer_acct.address.lower()
    msg = "\n".join(["CRX-REST-LOGIN", "Audience: crx-gateway", f"Method: {method.upper()}",
                     f"Path: {path}", f"Custody: {custody}", f"Signer: {signer}",
                     f"Timestamp: {ts}", f"Nonce: {nonce}"])
    sig = Account.sign_message(encode_defunct(text=msg), signer_acct.key).signature.to_0x_hex()
    return {"x-crx-address": custody, "x-crx-signer": signer, "x-crx-ts": str(ts),
            "x-crx-nonce": nonce, "x-crx-sig": sig}


async def main():
    async with websockets.connect(_ws(BASE) + "/ws",
                                  ping_interval=20, ping_timeout=20) as ws:
        await ws_logon(ws)
        oheaders = {**HDR, **sign_rest("POST", "/rfqs", CUSTODY, SIGNER)}
        ack = _body(requests.post(f"{BASE}/rfqs", headers=oheaders, timeout=10, json={
            "chain": CHAIN, "pair": PAIR, "side": SIDE, "expiry": EXPIRY_MS,
            "notional": NOTIONAL, "client_rfq_id": f"take-{uuid.uuid4().hex[:12]}"}))
        rfq_id, my_leg_id, quote_expiry = ack["rfq_id"], ack["leg_id"], ack["quote_expiry"]
        print("rfq", rfq_id)
        accepted = False
        async for raw in ws:
            frame = json.loads(raw)
            data = frame.get("data") or {}
            if data.get("rfq_id") != rfq_id:
                continue
            if frame["type"] == "rfq.quoted" and not accepted:
                leg = taker_leg(data, my_leg_id, quote_expiry, rfq_id)
                digest = leg_digest(leg)
                sig = Account.unsafe_sign_hash(digest, SIGNER.key).signature.to_0x_hex()
                apath = f"/rfqs/{rfq_id}/accept"
                aheaders = {**HDR, **sign_rest("POST", apath, CUSTODY, SIGNER)}
                body = _body(requests.post(f"{BASE}{apath}", headers=aheaders, timeout=10,
                                           json={"quote_id": data["quote_id"], "leg": leg, "sig": sig}))
                assert body["leg_hash"] == "0x" + digest.hex(), "gateway rebuilt a different Leg"
                accepted = True
                print("accepted", data["quote_id"])
            if frame["type"] == "trade.opened":
                arm = (data.get("arms") or [{}])[0]
                print("opened", data["trade_id"], arm.get("result"), arm.get("tx"))
                return

asyncio.run(main())
