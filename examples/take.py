# take.py: the taker leg, needing a taker key in CRX_API_KEY and its bound private key in CRX_MAKER_PK
import asyncio, json, os, sys, pathlib, time, uuid
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from decimal import Decimal

import requests, websockets
from eth_abi import encode
from eth_account import Account
from eth_utils import keccak
from crx_maker import ACCT, BASE, HDR, TERMS_TYPEHASH, _body, _separator

CHAIN, PAIR, SIDE, NOTIONAL = "base", "USDJPY", "buy", "25000.00"   # notional is a string, never a float
SETTLEMENT_MS = (int(time.time()) + 7 * 86400) * 1000               # the wire carries unix ms

def taker_digest(rfq, q):
    """Rebuild the digest the maker signed, so the gateway's terms_hash is checked and never trusted."""
    blob = (b"\x01" + bytes.fromhex(rfq["pair_id"][2:])
            + ((1 if rfq["side"] == "buy" else -1) & 0xFF).to_bytes(1, "big")
            + (rfq["settlement"] // 1000).to_bytes(5, "big")   # the u40 header packs seconds
            + int(Decimal(q["rate"]).scaleb(6)).to_bytes(8, "big"))
    struct_hash = keccak(encode(
        ["bytes32", "address", "address", "uint256", "uint16", "uint16",
         "uint16", "uint40", "uint64", "bytes32"],
        [TERMS_TYPEHASH, rfq["taker"], q["maker"], int(Decimal(rfq["notional"]).scaleb(6)),
         q["im_bps_taker"], q["im_bps_maker"], rfq["premium_bps"],
         q["expires_at"] // 1000, int(q["terms"]["nonce"]), keccak(blob)]))
    return keccak(b"\x19\x01" + _separator(rfq["chain"]) + struct_hash)

# nothing here completes without a maker quoting the same pair on the other side
async def main():
    async with websockets.connect(BASE.replace("https://", "wss://") + "/ws",
                                  ping_interval=20, ping_timeout=20) as ws:
        await ws.send(json.dumps({"type": "logon", "api_key": os.environ["CRX_API_KEY"]}))
        ack = _body(requests.post(f"{BASE}/rfqs", headers=HDR, timeout=10, json={
            "chain": CHAIN, "pair": PAIR, "side": SIDE, "settlement": SETTLEMENT_MS,
            "notional": NOTIONAL, "client_rfq_id": f"take-{uuid.uuid4().hex[:12]}"}))
        rfq_id, rfq = ack["rfq_id"], None
        print("rfq", rfq_id)
        async for raw in ws:
            frame = json.loads(raw)
            data = frame.get("data") or {}
            # every fact the Terms digest needs arrives on rfq.opened, not on the POST ack
            if frame["type"] == "rfq.opened" and data["rfq"]["rfq_id"] == rfq_id:
                rfq = data["rfq"]
            if rfq and frame["type"] == "rfq.quoted" and data["quote"]["rfq_id"] == rfq_id:
                q = data["quote"]
                digest = taker_digest(rfq, q)
                assert q["terms_hash"] == "0x" + digest.hex(), "gateway rebuilt different Terms"
                sig = Account.unsafe_sign_hash(digest, ACCT.key).signature.to_0x_hex()
                _body(requests.post(f"{BASE}/rfqs/{rfq_id}/accept", headers=HDR,
                                    timeout=10, json={"quote_id": q["quote_id"], "sig_taker": sig}))
                print("accepted", q["quote_id"])
            if frame["type"] == "trade.opened" and data["rfq_id"] == rfq_id:
                print("opened", data["trade_id"], data["tx"])
                return

asyncio.run(main())
