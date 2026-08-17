__version__ = "2.0.0"

import asyncio, json, os, time, uuid
from decimal import Decimal

import requests, websockets
from eth_abi import encode
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak
from web3 import Web3


class CrxError(Exception):

    def __init__(self, status, body):
        body = body if isinstance(body, dict) else {}
        self.status = status
        self.code = body.get("code") or "unknown"
        self.message = body.get("error") or body.get("message") or ""
        super().__init__(f"{status} {self.code}" + (f": {self.message}" if self.message else ""))


def _body(response):
    try:
        body = response.json()
    except ValueError:
        raise CrxError(response.status_code, {"code": "non_json_body",
                                              "error": f"{response.url} answered with a non-JSON body: "
                                                       f"{response.text[:120]!r}"}) from None
    if response.status_code >= 400:
        raise CrxError(response.status_code, body)
    return body


BASE = os.environ.get("CRX_BASE", "https://api.crxfx.com").rstrip("/")
ROOT = BASE
SIGNER = Account.from_key(os.environ["CRX_SIGNER_PK"])
CUSTODY = os.environ["CRX_CUSTODY"].lower()
HDR = {"content-type": "application/json"}


def _ws(base):
    return base.replace("https://", "wss://").replace("http://", "ws://")


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


_health = _body(requests.get(f"{ROOT}/health", timeout=10))
CHAINS = {c["key"]: c for c in _health["chains"]}
PRIMARY_CHAIN_ID = _health["chains"][0]["chain_id"]


def hello(nonce, custody, signer, chain_id):
    return "\n".join(["CRX-WS-LOGIN", "Audience: crx-gateway", f"Chain: {chain_id}",
                      f"Custody: {custody}", f"Signer: {signer}", f"Nonce: {nonce}"])


def login_frame(nonce, signer_acct, custody, chain_id):
    sig = Account.sign_message(
        encode_defunct(text=hello(nonce, custody, signer_acct.address.lower(), chain_id)),
        signer_acct.key).signature.to_0x_hex()
    return {"type": "logon", "signer": signer_acct.address.lower(), "custody": custody, "sig": sig}


async def ws_logon(ws, nonce):
    frame = login_frame(nonce, SIGNER, CUSTODY, PRIMARY_CHAIN_ID)
    await ws.send(json.dumps(frame))
    return frame


LEG_TYPE = ("Leg(address seat,bytes32 legId,bytes32 joinRef,bytes32 pair,"
            "uint8 instrumentId,int8 side,uint256 notional,uint64 rate,"
            "uint16 imBps,int16 premiumBps,uint40 expiry,uint64 nonce,"
            "uint64 quoteExpiry)")
LEG_TYPEHASH = keccak(text=LEG_TYPE)
DOMAIN_TYPEHASH = keccak(text="EIP712Domain(string name,string version,"
                              "uint256 chainId,address verifyingContract)")

# ABI head types for the Leg struct hash, aligned to LEG_TYPE.
LEG_ABI_TYPES = ["bytes32", "address", "bytes32", "bytes32", "bytes32", "uint8", "int8",
                 "uint256", "uint64", "uint16", "int16", "uint40", "uint64", "uint64"]
NDF = 1  # instrumentId for the non-deliverable forward
FLAT_IM_BPS = 100  # the flat protocol IM, both seats


def _separator(chain_key):
    c = CHAINS[chain_key]
    sep = keccak(encode(["bytes32", "bytes32", "bytes32", "uint256", "address"],
                        [DOMAIN_TYPEHASH, keccak(text="CRX"), keccak(text="rulebook-1.0"),
                         c["chain_id"], c["core"]]))
    assert "0x" + sep.hex() == c["domain"], f"domain does not match {chain_key}, refuse to sign"
    return sep


def _nonce(seat, client_quote_id):
    return int.from_bytes(
        keccak(bytes.fromhex(seat[2:]) + client_quote_id.encode())[-8:], "big")


def _leg(rfq, rate, nonce):
    return {"seat": CUSTODY, "leg_id": rfq["leg_id"], "join_ref": rfq["join_ref"],
            "pair_id": rfq["pair_id"], "instrument_id": NDF, "side": rfq["side"],
            "notional": rfq["notional"], "rate": rate, "im_bps": FLAT_IM_BPS,
            "premium_bps": rfq["premium_bps"], "expiry": rfq["expiry"],
            "nonce": str(nonce), "quote_expiry": rfq["quote_expiry"]}


def leg_digest(chain, leg):
    struct_hash = keccak(encode(
        LEG_ABI_TYPES,
        [LEG_TYPEHASH, leg["seat"], bytes.fromhex(leg["leg_id"][2:]),
         bytes.fromhex(leg["join_ref"][2:]), bytes.fromhex(leg["pair_id"][2:]),
         leg["instrument_id"], leg["side"], int(Decimal(leg["notional"]).scaleb(6)),
         int(Decimal(leg["rate"]).scaleb(6)), leg["im_bps"], leg["premium_bps"],
         leg["expiry"] // 1000, int(leg["nonce"]), leg["quote_expiry"] // 1000]))
    return keccak(b"\x19\x01" + _separator(chain) + struct_hash)


def quote(rfq, *, rate, firm_for=60, client_quote_id=None):
    cqid = client_quote_id or f"{rfq['pair']}.{rfq['rfq_id'][2:14]}"
    leg = _leg(rfq, rate, _nonce(CUSTODY, cqid))
    digest = leg_digest(rfq["chain"], leg)
    sig = Account.unsafe_sign_hash(digest, SIGNER.key).signature.to_0x_hex()
    assert Account._recover_hash(digest, signature=sig) == SIGNER.address
    path = f"/rfqs/{rfq['rfq_id']}/quotes"
    headers = {**HDR, **sign_rest("POST", path, CUSTODY, SIGNER)}
    body = _body(requests.post(f"{BASE}{path}", headers=headers, timeout=10,
                               json={"maker": CUSTODY, "rate": rate,
                                     "expires_at": (int(time.time()) + firm_for) * 1000,
                                     "sig": sig, "client_quote_id": cqid}))
    assert body["leg_hash"] == "0x" + digest.hex(), "gateway rebuilt a different Leg"
    return body


def on_rfq(handler, *pairs):
    url = _ws(ROOT) + "/ws"

    async def run():
        backoff = 1
        while True:
            try:
                async with websockets.connect(url, ping_interval=20, ping_timeout=20) as ws:
                    challenge = json.loads(await ws.recv())
                    if challenge.get("type") != "challenge":
                        print("expected a challenge, got", challenge.get("type"))
                        return
                    await ws_logon(ws, challenge["nonce"])
                    backoff = 1
                    async for raw in ws:
                        frame = json.loads(raw)
                        if frame["type"] == "error":
                            print("logon refused:", frame.get("data"))
                            return
                        if frame["type"] == "logon_ack":
                            d = frame["data"]
                            print("logged on as", d["account"], "role", d["role"])
                            continue
                        if frame["type"] != "rfq.opened":
                            continue
                        rfq = frame["data"]
                        if pairs and rfq["pair"] not in pairs:
                            continue
                        try:
                            handler(rfq)
                        except Exception as err:
                            print("skipped", rfq["rfq_id"][:12], err)
            except Exception as err:
                print("dropped:", type(err).__name__, err)
            else:
                print("dropped: the gateway closed the socket")
            print(f"reconnecting in {backoff}s")
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30)

    asyncio.run(run())


def _w3():
    return Web3(Web3.HTTPProvider(os.environ["CRX_RPC_URL"]))


def _submit_gateway_tx(w3, tx):
    txn = {"from": SIGNER.address, "to": tx["to"], "data": tx["data"], "value": int(tx["value"]),
           "chainId": tx["chain_id"], "nonce": w3.eth.get_transaction_count(SIGNER.address),
           "gasPrice": w3.eth.gas_price}
    txn["gas"] = w3.eth.estimate_gas(txn)
    sent = w3.eth.send_raw_transaction(SIGNER.sign_transaction(txn).raw_transaction)
    w3.eth.wait_for_transaction_receipt(sent)
    return sent.hex()


def _gateway_flow(endpoint, payload):
    path = f"/{endpoint}"
    headers = {**HDR, **sign_rest("POST", path, CUSTODY, SIGNER)}
    body = _body(requests.post(f"{ROOT}{path}", headers=headers, timeout=10, json=payload))
    w3 = _w3()
    return [_submit_gateway_tx(w3, tx) for tx in body["transactions"]]


def deposit(chain, symbol, amount):
    return _gateway_flow("deposit", {"chain": chain, "symbol": symbol, "amount": amount})


def withdraw(chain, symbol, amount, recipient):
    return _gateway_flow("withdraw",
                          {"chain": chain, "symbol": symbol, "amount": amount, "recipient": recipient})
