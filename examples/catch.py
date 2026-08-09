# catch.py: hold the socket until the first RFQ arrives. Needs CRX_MAKER_PK; it logs itself in.
import asyncio, json, os
import requests, websockets
from eth_account import Account
from eth_account.messages import encode_defunct

BASE = os.environ.get("CRX_BASE", "https://api.crxfx.com").rstrip("/")
ACCT = Account.from_key(os.environ["CRX_MAKER_PK"])


def _ws(base):
    return base.replace("https://", "wss://").replace("http://", "ws://")


def login():
    """Sign the gateway challenge for ACCT and return the session token."""
    message = requests.get(f"{BASE}/auth/nonce", timeout=10,
                           params={"address": ACCT.address.lower(), "chain": "base"}).json()["message"]
    sig = Account.sign_message(encode_defunct(text=message), ACCT.key).signature.to_0x_hex()
    return requests.post(f"{BASE}/auth/login", timeout=10,
                         json={"address": ACCT.address.lower(), "sig": sig}).json()["token"]


async def main():
    token = login()
    async with websockets.connect(_ws(BASE) + "/ws") as ws:
        await ws.send(json.dumps({"type": "logon", "token": token}))
        while True:
            frame = json.loads(await ws.recv())
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
