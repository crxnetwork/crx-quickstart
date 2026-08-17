import asyncio, json, os, sys, uuid
from datetime import datetime, timedelta, timezone

import requests, websockets
from eth_account import Account

import crx_maker
from crx_maker import (BASE, FLAT_IM_BPS, NDF, _body, _nonce, _separator, _ws,
                       leg_digest, login_frame, quote, sign_rest)

CHAIN, PAIR, SIDE, NOTIONAL = "base", "USDJPY", "buy", "25000.00"
EXPIRY = datetime.now(timezone.utc) + timedelta(days=7)
while EXPIRY.weekday() >= 5:
    EXPIRY += timedelta(days=1)
EXPIRY_MS = int(EXPIRY.timestamp() * 1000)
WS = _ws(BASE) + "/ws"
stage = "health"


async def logon(ws, signer_acct, custody):
    challenge = json.loads(await ws.recv())
    if challenge.get("type") != "challenge":
        print(f"FAIL at {stage}: expected challenge, got", challenge)
        sys.exit(1)
    await ws.send(json.dumps(login_frame(challenge["nonce"], signer_acct, custody, crx_maker.PRIMARY_CHAIN_ID)))
    async for raw in ws:
        frame = json.loads(raw)
        if frame["type"] == "logon_ack":
            return frame["data"]
        if frame["type"] == "error":
            print(f"FAIL at {stage}:", frame.get("data"))
            sys.exit(1)


def taker_leg_of(q, custody, leg_id, quote_expiry, rfq_id):
    return {"seat": custody, "leg_id": leg_id, "join_ref": q["join_ref"],
            "pair_id": q["pair_id"], "instrument_id": NDF, "side": q["side"],
            "notional": q["notional"], "rate": q["rate"], "im_bps": FLAT_IM_BPS,
            "premium_bps": q["premium_bps"], "expiry": q["expiry"],
            "nonce": str(_nonce(custody, rfq_id)), "quote_expiry": quote_expiry}


async def maker_leg(ws, rfq_id):
    global stage
    async for raw in ws:
        frame = json.loads(raw)
        if frame["type"] == "rfq.opened" and frame["data"]["rfq_id"] == rfq_id:
            stage = "maker quote"
            q = quote(frame["data"], rate="146.250000", firm_for=60)
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
        ack = await logon(maker_ws, crx_maker.SIGNER, crx_maker.CUSTODY)
        print("maker logged on as", ack["account"], "role", ack["role"])
        taker_pk = os.environ.get("CRX_TAKER_SIGNER_PK")
        if not taker_pk:
            print("connectivity check passed. the full round trip needs CRX_TAKER_SIGNER_PK and CRX_TAKER_CUSTODY")
            return
        stage = "taker logon"
        taker = Account.from_key(taker_pk)
        taker_custody = os.environ["CRX_TAKER_CUSTODY"].lower()

        async def taker_leg(ws, rfq_id, leg_id, quote_expiry):
            global stage
            async for raw in ws:
                frame = json.loads(raw)
                data = frame.get("data") or {}
                if data.get("rfq_id") != rfq_id:
                    continue
                if frame["type"] == "rfq.quoted":
                    stage = "taker accept"
                    leg = taker_leg_of(data, taker_custody, leg_id, quote_expiry, rfq_id)
                    digest = leg_digest(CHAIN, leg)
                    sig = Account.unsafe_sign_hash(digest, taker.key).signature.to_0x_hex()
                    apath = f"/rfqs/{rfq_id}/accept"
                    aheaders = {**crx_maker.HDR, **sign_rest("POST", apath, taker_custody, taker)}
                    body = _body(requests.post(f"{BASE}{apath}", headers=aheaders, timeout=10,
                                               json={"quote_id": data["quote_id"], "leg": leg, "sig": sig}))
                    assert body["leg_hash"] == "0x" + digest.hex(), "gateway rebuilt a different Leg"
                    stage = "trade open"
                if frame["type"] == "trade.opened":
                    arm = (data.get("arms") or [{}])[0]
                    print("PASS", data["trade_id"], arm.get("result"), arm.get("tx"))
                    return

        async with websockets.connect(WS, ping_interval=20, ping_timeout=20) as taker_ws:
            await logon(taker_ws, taker, taker_custody)
            stage = "rfq open"
            oheaders = {**crx_maker.HDR, **sign_rest("POST", "/rfqs", taker_custody, taker)}
            ack = _body(requests.post(f"{BASE}/rfqs", headers=oheaders, timeout=10, json={
                "chain": CHAIN, "pair": PAIR, "side": SIDE, "expiry": EXPIRY_MS,
                "notional": NOTIONAL, "client_rfq_id": f"verify-{uuid.uuid4().hex[:12]}"}))
            print("rfq", ack["rfq_id"])
            await asyncio.gather(maker_leg(maker_ws, ack["rfq_id"]),
                                 taker_leg(taker_ws, ack["rfq_id"], ack["leg_id"], ack["quote_expiry"]))


try:
    asyncio.run(asyncio.wait_for(run(), 90))
except asyncio.TimeoutError:
    print("FAIL: timed out at stage", stage)
    sys.exit(1)
except Exception as err:
    print(f"FAIL at {stage}: {type(err).__name__}: {err}")
    sys.exit(1)
