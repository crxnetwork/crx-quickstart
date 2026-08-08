# verify.py: one process proving the round trip, connectivity only without taker creds
import asyncio, json, os, sys, time, uuid
from decimal import Decimal

import requests, websockets
from eth_abi import encode
from eth_account import Account
from eth_utils import keccak

import crx_maker
from crx_maker import ACCT, BASE, TERMS_TYPEHASH, _body, _separator, quote

CHAIN, PAIR, SIDE, NOTIONAL = "base", "USDJPY", "buy", "25000.00"
SETTLEMENT_MS = (int(time.time()) + 7 * 86400) * 1000
WS = BASE.replace("https://", "wss://") + "/ws"
stage = "health"


async def logon(ws, key):
    await ws.send(json.dumps({"type": "logon", "api_key": key}))
    async for raw in ws:
        frame = json.loads(raw)
        if frame["type"] == "logon_ack":
            return frame["data"]
        if frame["type"] == "error":
            print(f"FAIL at {stage}:", frame.get("data"))
            sys.exit(1)


def taker_digest(rfq, q):
    """Rebuild the digest the maker signed, so the gateway's terms_hash is checked."""
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
    return keccak(b"\x19\x01" + _separator(rfq["chain"]) + struct_hash)


async def maker_leg(ws, rfq_id):
    global stage
    async for raw in ws:
        frame = json.loads(raw)
        if frame["type"] == "rfq.opened" and frame["data"]["rfq"]["rfq_id"] == rfq_id:
            stage = "maker quote"
            q = quote(frame["data"]["rfq"], rate="146.250000", im_bps=292, firm_for=60)
            print("quoted", q["quote_id"])
            return


async def run():
    global stage
    health = _body(requests.get(f"{BASE}/health", timeout=10))
    _separator("base")
    print("health ok, api", health["api_version"], "chains",
          ",".join(sorted(crx_maker.CHAINS)), "- domain checked")
    stage = "maker logon"
    async with websockets.connect(WS, ping_interval=20, ping_timeout=20) as maker_ws:
        ack = await logon(maker_ws, os.environ["CRX_API_KEY"])
        print("maker logged on as", ack["account"], "role", ack["role"])
        taker_key, taker_pk = os.environ.get("CRX_TAKER_KEY"), os.environ.get("CRX_TAKER_PK")
        if not (taker_key and taker_pk):
            print("connectivity check passed. the full round trip needs CRX_TAKER_KEY and CRX_TAKER_PK")
            return
        stage = "taker logon"
        taker = Account.from_key(taker_pk)
        hdr = {"x-api-key": taker_key, "content-type": "application/json"}

        async def taker_leg(ws, rfq_id):
            global stage
            rfq = None
            async for raw in ws:
                frame = json.loads(raw)
                data = frame.get("data") or {}
                # every fact the Terms digest needs arrives on rfq.opened
                if frame["type"] == "rfq.opened" and data["rfq"]["rfq_id"] == rfq_id:
                    rfq = data["rfq"]
                if rfq and frame["type"] == "rfq.quoted" and data["quote"]["rfq_id"] == rfq_id:
                    q = data["quote"]
                    # the live solver may also quote, so only this maker's quote is accepted
                    if q["maker"].lower() != ACCT.address.lower():
                        continue
                    stage = "taker accept"
                    digest = taker_digest(rfq, q)
                    assert q["terms_hash"] == "0x" + digest.hex(), "gateway rebuilt different Terms"
                    sig = Account.unsafe_sign_hash(digest, taker.key).signature.to_0x_hex()
                    _body(requests.post(f"{BASE}/rfqs/{rfq_id}/accept", headers=hdr, timeout=10,
                                        json={"quote_id": q["quote_id"], "sig_taker": sig}))
                    stage = "trade open"
                if frame["type"] == "trade.opened" and data.get("rfq_id") == rfq_id:
                    print("PASS", data["trade_id"], data["tx"])
                    return

        async with websockets.connect(WS, ping_interval=20, ping_timeout=20) as taker_ws:
            await logon(taker_ws, taker_key)
            stage = "rfq open"
            ack = _body(requests.post(f"{BASE}/rfqs", headers=hdr, timeout=10, json={
                "chain": CHAIN, "pair": PAIR, "side": SIDE, "settlement": SETTLEMENT_MS,
                "notional": NOTIONAL, "client_rfq_id": f"verify-{uuid.uuid4().hex[:12]}"}))
            print("rfq", ack["rfq_id"])
            await asyncio.gather(maker_leg(maker_ws, ack["rfq_id"]),
                                 taker_leg(taker_ws, ack["rfq_id"]))


try:
    asyncio.run(asyncio.wait_for(run(), 90))
except asyncio.TimeoutError:
    print("FAIL: timed out at stage", stage)
    sys.exit(1)
