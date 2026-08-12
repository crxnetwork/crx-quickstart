import asyncio, json, os, time, uuid
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
SETTLEMENT_MS = (int(time.time()) + 7 * 86400) * 1000

TERMS_TYPEHASH = keccak(text="Terms(address taker,address maker,uint256 notional,uint16 imBpsTaker,"
                             "uint16 imBpsMaker,uint16 premiumBps,uint40 expiry,uint64 nonce,bytes instrument)")
DOMAIN_TYPEHASH = keccak(text="EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")


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


def taker_digest(rfq, q):
    blob = (b"\x01" + bytes.fromhex(rfq["pair_id"][2:])
            + ((1 if rfq["side"] == "buy" else -1) & 0xFF).to_bytes(1, "big")
            + (rfq["settlement"] // 1000).to_bytes(5, "big")
            + int(Decimal(q["rate"]).scaleb(6)).to_bytes(8, "big"))
    struct_hash = keccak(encode(
        ["bytes32", "address", "address", "uint256", "uint16", "uint16",
         "uint16", "uint40", "uint64", "bytes32"],
        [TERMS_TYPEHASH, rfq["taker"], q["maker"], int(Decimal(rfq["notional"]).scaleb(6)),
         q["im_bps_taker"], q["im_bps_maker"], rfq["premium_bps"],
         q["expires_at"] // 1000, int(q["terms"]["nonce"]), keccak(blob)]))
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
            "chain": CHAIN, "pair": PAIR, "side": SIDE, "settlement": SETTLEMENT_MS,
            "notional": NOTIONAL, "client_rfq_id": f"take-{uuid.uuid4().hex[:12]}"}))
        rfq_id, rfq = ack["rfq_id"], None
        print("rfq", rfq_id)
        async for raw in ws:
            frame = json.loads(raw)
            data = frame.get("data") or {}
            if frame["type"] == "rfq.opened" and data["rfq"]["rfq_id"] == rfq_id:
                rfq = data["rfq"]
            if rfq and frame["type"] == "rfq.quoted" and data["quote"]["rfq_id"] == rfq_id:
                q = data["quote"]
                digest = taker_digest(rfq, q)
                assert q["terms_hash"] == "0x" + digest.hex(), "gateway rebuilt different Terms"
                sig = Account.unsafe_sign_hash(digest, SIGNER.key).signature.to_0x_hex()
                apath = f"/rfqs/{rfq_id}/accept"
                aheaders = {**HDR, **sign_rest("POST", apath, CUSTODY, SIGNER)}
                _body(requests.post(f"{BASE}{apath}", headers=aheaders,
                                    timeout=10, json={"quote_id": q["quote_id"], "sig_taker": sig}))
                print("accepted", q["quote_id"])
            if frame["type"] == "trade.opened" and data["rfq_id"] == rfq_id:
                print("opened", data["trade_id"], data["tx"])
                return

asyncio.run(main())
