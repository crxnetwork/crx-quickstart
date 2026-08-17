import asyncio, json, os, sys, uuid
from datetime import datetime, timedelta, timezone

import requests, websockets
from eth_account import Account

CHAIN = os.environ.get("CRX_CHAIN", "base")
PAIR, SIDE, NOTIONAL = "USDJPY", "buy", "25000.00"
EXPIRY = datetime.now(timezone.utc) + timedelta(days=7)
while EXPIRY.weekday() >= 5:
    EXPIRY += timedelta(days=1)
EXPIRY_MS = int(EXPIRY.timestamp() * 1000)
stage = "config"


class Refusal(Exception):
    """A named failure. The wrapper prints it as FAIL at <stage>, no traceback."""


def config():
    # crx_maker reads the env and fetches /health at import, so the import sits
    # here, inside the guarded path, not at the top of the file.
    global crx_maker, BASE, WS, HEALTH
    for name in ("CRX_SIGNER_PK", "CRX_CUSTODY"):
        if not os.environ.get(name):
            raise Refusal(f"{name} not set")
    import crx_maker
    BASE = crx_maker.BASE
    WS = crx_maker._ws(BASE) + "/ws"
    HEALTH = crx_maker._health  # the one /health fetch, made at import
    if CHAIN not in crx_maker.CHAINS:
        raise Refusal(f"CRX_CHAIN={CHAIN} is not served by {BASE}; "
                      f"/health lists {', '.join(crx_maker.CHAINS)}")


async def logon(ws, signer_acct, custody):
    challenge = json.loads(await ws.recv())
    if challenge.get("type") != "challenge":
        raise Refusal(f"expected challenge, got {challenge}")
    await ws.send(json.dumps(crx_maker.login_frame(
        challenge["nonce"], signer_acct, custody, crx_maker.PRIMARY_CHAIN_ID)))
    async for raw in ws:
        frame = json.loads(raw)
        if frame["type"] == "logon_ack":
            return frame["data"]
        if frame["type"] == "error":
            raise Refusal(f"{frame.get('data')}")


def taker_leg_of(q, custody, leg_id, quote_expiry, rfq_id):
    return {"seat": custody, "leg_id": leg_id, "join_ref": q["join_ref"],
            "pair_id": q["pair_id"], "instrument_id": crx_maker.NDF, "side": q["side"],
            "notional": q["notional"], "rate": q["rate"], "im_bps": crx_maker.FLAT_IM_BPS,
            "premium_bps": q["premium_bps"], "expiry": q["expiry"],
            "nonce": str(crx_maker._nonce(custody, rfq_id)), "quote_expiry": quote_expiry}


async def maker_leg(ws, rfq_id):
    global stage
    async for raw in ws:
        frame = json.loads(raw)
        if frame["type"] == "rfq.opened" and frame["data"]["rfq_id"] == rfq_id:
            stage = "maker quote"
            q = crx_maker.quote(frame["data"], rate="146.250000", firm_for=60)
            print("quoted", q["quote_id"])
            return


async def run():
    global stage
    config()
    stage = "health"
    crx_maker._separator(CHAIN)
    print("health ok, api", HEALTH["api_version"], "chains",
          ",".join(crx_maker.CHAINS), "- domain checked")
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
        taker_custody = os.environ.get("CRX_TAKER_CUSTODY")
        if not taker_custody:
            raise Refusal("CRX_TAKER_CUSTODY not set")
        taker_custody = taker_custody.lower()

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
                    digest = crx_maker.leg_digest(CHAIN, leg)
                    sig = Account.unsafe_sign_hash(digest, taker.key).signature.to_0x_hex()
                    apath = f"/rfqs/{rfq_id}/accept"
                    aheaders = {**crx_maker.HDR, **crx_maker.sign_rest("POST", apath, taker_custody, taker)}
                    body = crx_maker._body(requests.post(f"{BASE}{apath}", headers=aheaders, timeout=10,
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
            oheaders = {**crx_maker.HDR, **crx_maker.sign_rest("POST", "/rfqs", taker_custody, taker)}
            ack = crx_maker._body(requests.post(f"{BASE}/rfqs", headers=oheaders, timeout=10, json={
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
except Refusal as err:
    print(f"FAIL at {stage}: {err}")
    sys.exit(1)
except Exception as err:
    print(f"FAIL at {stage}: {type(err).__name__}: {err}")
    sys.exit(1)
