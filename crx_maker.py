"""Copy this maker plumbing once."""
__version__ = "1.0.0"

import asyncio, json, os, time
from decimal import Decimal

import requests, websockets
from eth_abi import encode
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak
from web3 import Web3


class CrxError(Exception):
    """A gateway refusal carrying a stable `code` slug and a `message` that is prose and moves."""

    def __init__(self, status, body):
        body = body if isinstance(body, dict) else {}
        self.status = status
        self.code = body.get("code") or "unknown"
        # REST bodies use the error key where stream error frames use message
        self.message = body.get("error") or body.get("message") or ""
        super().__init__(f"{status} {self.code}" + (f": {self.message}" if self.message else ""))


def _body(response):
    """Return the parsed body, or raise CrxError naming the host behind a non-JSON reply."""
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
ROOT = BASE                                        # every path hangs off the host root
ACCT = Account.from_key(os.environ["CRX_MAKER_PK"])
HDR = {"content-type": "application/json"}          # login() fills in the Bearer header in place
token = None                                        # the session JWT, set by login()


def _ws(base):
    """Map the REST scheme to the socket scheme, so loopback http becomes ws not wss."""
    return base.replace("https://", "wss://").replace("http://", "ws://")


def login():
    """Prove ACCT's address by signing the gateway challenge, store the session token, and set HDR in place.

    Mutates the module-level HDR dict — never rebinds it — so `from crx_maker import HDR` in another
    module sees the Bearer header after login runs.
    """
    global token
    message = _body(requests.get(f"{ROOT}/auth/nonce", timeout=10,
                                 params={"address": ACCT.address.lower(), "chain": "base"}))["message"]
    sig = Account.sign_message(encode_defunct(text=message), ACCT.key).signature.to_0x_hex()
    body = _body(requests.post(f"{ROOT}/auth/login", timeout=10,
                               json={"address": ACCT.address.lower(), "sig": sig}))
    token = body["token"]
    HDR.clear()
    HDR.update({"Authorization": f"Bearer {token}", "content-type": "application/json"})
    return token


login()

TERMS_TYPE = ("Terms(address taker,address maker,uint256 notional,"
              "uint16 imBpsTaker,uint16 imBpsMaker,uint16 premiumBps,"
              "uint40 expiry,uint64 nonce,bytes instrument)")
TERMS_TYPEHASH = keccak(text=TERMS_TYPE)
DOMAIN_TYPEHASH = keccak(text="EIP712Domain(string name,string version,"
                              "uint256 chainId,address verifyingContract)")
CHAINS = {c["key"]: c for c in _body(requests.get(f"{ROOT}/health", timeout=10))["chains"]}

CANCEL_ABI = [{"type": "function", "name": "cancelQuote", "stateMutability": "nonpayable", "outputs": [],
               "inputs": [{"name": "t", "type": "tuple", "components": [
                   {"name": "taker", "type": "address"}, {"name": "maker", "type": "address"},
                   {"name": "notional", "type": "uint256"},
                   {"name": "imBpsTaker", "type": "uint16"}, {"name": "imBpsMaker", "type": "uint16"},
                   {"name": "premiumBps", "type": "uint16"},
                   {"name": "expiry", "type": "uint40"}, {"name": "nonce", "type": "uint64"},
                   {"name": "instrument", "type": "bytes"}]}]}]


def _separator(chain_key):
    c = CHAINS[chain_key]
    sep = keccak(encode(["bytes32", "bytes32", "bytes32", "uint256", "address"],
                        [DOMAIN_TYPEHASH, keccak(text="CRX"), keccak(text="rulebook-1.0"),
                         c["chain_id"], c["core"]]))
    # the assert stops a signature being made against a rotated core under a stale domain
    assert "0x" + sep.hex() == c["domain"], f"domain does not match {chain_key}, refuse to sign"
    return sep


def _digest(rfq, rate, im_bps, expiry, cqid):
    side = 1 if rfq["side"] == "buy" else -1
    # the wire carries settlement and expiry in unix ms while the signed u40 fields pack seconds
    blob = (b"\x01"
            + bytes.fromhex(rfq["pair_id"][2:])
            + (side & 0xFF).to_bytes(1, "big")
            + (rfq["settlement"] // 1000).to_bytes(5, "big")
            + int(Decimal(rate).scaleb(6)).to_bytes(8, "big"))
    nonce = int.from_bytes(
        keccak(bytes.fromhex(ACCT.address[2:]) + cqid.encode())[-8:], "big")
    struct_hash = keccak(encode(
        ["bytes32", "address", "address", "uint256", "uint16", "uint16",
         "uint16", "uint40", "uint64", "bytes32"],
        [TERMS_TYPEHASH, rfq["taker"], ACCT.address,
         int(Decimal(rfq["notional"]).scaleb(6)),
         im_bps, im_bps, rfq["premium_bps"], expiry, nonce, keccak(blob)]))
    return keccak(b"\x19\x01" + _separator(rfq["chain"]) + struct_hash)


def quote(rfq, *, rate, im_bps, firm_for=60, client_quote_id=None):
    """Sign and submit one firm quote and return the gateway's quote object."""
    cqid = client_quote_id or f"{rfq['pair']}.{rfq['rfq_id'][2:14]}"
    expiry = int(time.time()) + firm_for
    digest = _digest(rfq, rate, im_bps, expiry, cqid)
    sig = Account.unsafe_sign_hash(digest, ACCT.key).signature.to_0x_hex()
    assert Account._recover_hash(digest, signature=sig) == ACCT.address
    body = _body(requests.post(f"{BASE}/rfqs/{rfq['rfq_id']}/quotes", headers=HDR, timeout=10,
                               json={"rate": rate, "im_bps_taker": im_bps, "im_bps_maker": im_bps,
                                     "expires_at": expiry * 1000, "sig": sig,
                                     "client_quote_id": cqid}))
    assert body["terms_hash"] == "0x" + digest.hex(), "gateway rebuilt different Terms"
    return body


def on_rfq(handler, *pairs):
    """Block forever calling handler(rfq) per RFQ on the named pairs, resuming from the last seq after a drop."""
    url = _ws(ROOT) + "/ws"

    async def run():
        seq, backoff = None, 1
        while True:
            try:
                # pings keep a dead but open socket from looking alive forever
                async with websockets.connect(url, ping_interval=20, ping_timeout=20) as ws:
                    logon = {"type": "logon", "token": token}
                    if seq is not None:
                        logon["since"] = seq
                    await ws.send(json.dumps(logon))
                    print("logged on,", f"replaying after seq {seq}" if seq else "at the head")
                    backoff = 1
                    async for raw in ws:
                        frame = json.loads(raw)
                        if frame["type"] == "error":
                            print("logon refused:", frame.get("data"))
                            return
                        if frame.get("seq"):
                            seq = frame["seq"]
                        if frame["type"] != "rfq.opened":
                            continue
                        rfq = frame["data"]["rfq"]
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


def cancel_quote(terms):
    """Cancel a firm quote before it opens, taking the signed nine field Terms as a dict or tuple in field order."""
    w3 = _w3()
    core = w3.eth.contract(address=os.environ["CRX_CORE"], abi=CANCEL_ABI)
    values = tuple(terms.values()) if isinstance(terms, dict) else tuple(terms)
    tx = core.functions.cancelQuote(values).build_transaction(
        {"from": ACCT.address, "nonce": w3.eth.get_transaction_count(ACCT.address)})
    sent = w3.eth.send_raw_transaction(ACCT.sign_transaction(tx).raw_transaction)
    return sent.hex()


def _submit_gateway_tx(w3, tx):
    """Fill nonce and gas against CRX_RPC_URL, sign with ACCT, and wait for the receipt."""
    txn = {"from": ACCT.address, "to": tx["to"], "data": tx["data"], "value": int(tx["value"]),
           "chainId": tx["chain_id"], "nonce": w3.eth.get_transaction_count(ACCT.address),
           "gasPrice": w3.eth.gas_price}
    txn["gas"] = w3.eth.estimate_gas(txn)
    sent = w3.eth.send_raw_transaction(ACCT.sign_transaction(txn).raw_transaction)
    w3.eth.wait_for_transaction_receipt(sent)
    return sent.hex()


def _gateway_flow(endpoint, payload):
    """POST to the gateway root, then sign and submit each returned tx in order."""
    body = _body(requests.post(f"{ROOT}/{endpoint}", headers=HDR, timeout=10, json=payload))
    w3 = _w3()
    return [_submit_gateway_tx(w3, tx) for tx in body["transactions"]]


def deposit(chain, symbol, amount):
    """Submit the unsigned txs POST /deposit returns, an approve first when allowance falls short."""
    return _gateway_flow("deposit", {"chain": chain, "symbol": symbol, "amount": amount})


def withdraw(chain, symbol, amount, recipient):
    """Submit the unsigned tx POST /withdraw returns, which passes only if required IM stays covered after."""
    return _gateway_flow("withdraw",
                          {"chain": chain, "symbol": symbol, "amount": amount, "recipient": recipient})
