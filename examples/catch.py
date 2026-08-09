# catch.py: hold the socket until the first RFQ arrives. Needs CRX_SIGNER_PK + CRX_CUSTODY.
import asyncio, json, os
import requests, websockets
from eth_account import Account
from eth_account.messages import encode_defunct

BASE = os.environ.get("CRX_BASE", "https://api.crxfx.com").rstrip("/")
SIGNER = Account.from_key(os.environ["CRX_SIGNER_PK"])   # the hot key, signs the hello
CUSTODY = os.environ["CRX_CUSTODY"].lower()              # the cold party the signer logs on for
CHAIN_ID = requests.get(f"{BASE}/health", timeout=10).json()["chains"][0]["chain_id"]


def _ws(base):
    return base.replace("https://", "wss://").replace("http://", "ws://")


def hello(nonce):
    """The exact six line hello the gateway recovers the signer from, newline joined, no trailing newline."""
    return "\n".join(["CRX-WS-LOGIN", "Audience: crx-gateway", f"Chain: {CHAIN_ID}",
                      f"Custody: {CUSTODY}", f"Signer: {SIGNER.address.lower()}", f"Nonce: {nonce}"])


async def ws_logon(ws, nonce):
    """Sign the hello with SIGNER on CUSTODY's behalf and send the logon frame."""
    sig = Account.sign_message(encode_defunct(text=hello(nonce)), SIGNER.key).signature.to_0x_hex()
    await ws.send(json.dumps({"type": "logon", "signer": SIGNER.address.lower(), "custody": CUSTODY, "sig": sig}))


async def main():
    async with websockets.connect(_ws(BASE) + "/ws") as ws:
        while True:
            frame = json.loads(await ws.recv())
            if frame["type"] == "challenge":
                await ws_logon(ws, frame["nonce"])
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
