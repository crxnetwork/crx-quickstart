# catch.py: hold the socket until the first RFQ arrives
import asyncio, json, os
import websockets

WS = os.environ["CRX_BASE"].replace("https://", "wss://") + "/ws"

async def main():
    async with websockets.connect(WS) as ws:
        await ws.send(json.dumps({"type": "logon", "api_key": os.environ["CRX_API_KEY"]}))
        while True:
            frame = json.loads(await ws.recv())
            # without logon_ack a quiet socket and a refused one look the same
            if frame["type"] == "logon_ack":
                d = frame["data"]
                print("logged on as", d["account"], "role", d["role"], "- waiting for an RFQ")
            if frame["type"] == "error":
                print("logon refused:", frame.get("data"))
                return
            if frame["type"] == "rfq.opened":
                r = frame["data"]["rfq"]
                print("rfq_id:", r["rfq_id"])
                # settlement on the wire is unix milliseconds
                print(r["pair"], r["side"], "notional", r["notional"], "settlement", r["settlement"])
                return

asyncio.run(main())
