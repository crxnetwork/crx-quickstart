# CRX quickstart

## Run it

Python 3.9 or newer.

```bash
pip3 install -r requirements.txt

cp .env.example .env        # fill in CRX_SIGNER_PK and CRX_CUSTODY
set -a; . ./.env; set +a    # a missing name fails at import as KeyError: 'CRX_SIGNER_PK'

python3 quote.py
```

`CRX_BASE` is optional and defaults to `https://api.crxfx.com`.

## quote.py

```python
from crx_maker import on_rfq, quote

PAIR = "USDJPY"           # the pair to price
RATE = "146.250000"       # the price for it
FIRM_FOR_SECS = 60        # how long the quote stays firm

def price(rfq):
    q = quote(rfq, rate=RATE, firm_for=FIRM_FOR_SECS)
    print(q["status"], q["leg_hash"])

on_rfq(price, PAIR)
```

**Two wallets.**

- `CRX_SIGNER_PK` is the **hot signer**. It signs every quote, accept, and WS logon.
- `CRX_CUSTODY` is the **cold custody** address. It is the `seat` the signer acts for — an address, never a key.
- The Leg binds `seat = CUSTODY`; the signature comes from `SIGNER`. The gateway recovers the signer and checks the `(custody, signer)` pair is whitelisted.

**One trade, two Legs.**

- Each side signs only its **own** 13-field `Leg`. There is no joint digest.
- The counterparty appears in the signed bytes only as `join_ref` — a blinded handle, never an address.
- `rfq.opened` carries your own `leg_id`, `join_ref`, and `side` (your direction as a signed integer, `+1` long base, `-1` short — never the taker's).
- Initial margin is the flat protocol constant, **100 bps for both seats**. It is signed as `im_bps` but never sent in a request body.
- `quote_expiry` is RFQ-sourced: the RFQ fixes one value and both halves sign it, equal.
- A quote posts `{maker, rate, expires_at, sig, client_quote_id}`. `client_quote_id` is required — the signed nonce derives from it as `uint64(keccak256(seat ‖ client_quote_id))`.
- An accept posts `{quote_id, leg, sig}` — the taker's own Leg and the signature over its own digest. Never sign a digest read off a quote; a quote row carries the counterparty's half.
- `GET /rfqs/{id}` serves the RFQ view with quotes ranked best-first, for takers that poll instead of stream.

`crx_maker.py` does the rest:

- Logs on over the socket: the gateway sends a `challenge` nonce, the signer signs the six-line hello, the client replies with the logon frame. No minted key, no session header.
- Quotes carry no auth header — the signature is the credential.
- Checks the EIP-712 domain and refuses to sign on a mismatch.
- Builds the Leg digest, derives the nonce, and recovers its own signature before sending.
- Asserts the returned `leg_hash` matches the signed one.

**Drops and refusals.**

- `on_rfq` reconnects with a backoff doubling from 1s to 30s.
- Each reconnect answers a fresh challenge and streams forward from the head.
- A refused logon prints the reason and stops.
- Refusals raise `crx_maker.CrxError`, carrying `.status`, `.code`, and `.message`.
- Branch on `.code`.

**Units.**

- Every numeric wire timestamp is unix **milliseconds**.
- Covers `expiry` and `quote_expiry` on `rfq.opened`, `expires_at` on quotes, and `expiry` on a posted RFQ.
- The signed Leg time fields stay in seconds.
- `crx_maker.py` divides the wire `expiry` and `quote_expiry` by 1000 before packing them.
- The gateway refuses the wrong scale: `400 bad_request: expiry … looks like unix seconds; wire timestamps are unix milliseconds`.

**Testnet.** The signature is the credential — a whitelisted `(custody, signer)` pair, no minted key. Full API reference at https://portal.crxfx.com/docs.

## Two sides, two processes

- An RFQ needs a taker to open it and a maker to price it.
- `quote.py` waits for an RFQ on its pair, so an idle book prints nothing.
- `examples/take.py` opens an RFQ and waits for a firm quote, stalling with no maker listening.
- Run the maker first and let it log on, then the taker in a second shell.
- A fresh logon streams forward, so a maker connecting after the RFQ opened never sees it.
- Each side needs its own hot signer and cold custody pair.
- `quote.py` signs as the maker on `CRX_SIGNER_PK` / `CRX_CUSTODY`; `examples/take.py` as the taker on `CRX_TAKER_SIGNER_PK` / `CRX_TAKER_CUSTODY`.
- The gateway derives the maker/taker seat from the custody's on-chain status at logon, so a custody without the taker seat is refused.

```bash
# shell one — the maker
set -a; . ./.env; set +a
python3 quote.py

# shell two — the taker
export CRX_TAKER_SIGNER_PK=0x…   # the taker hot key
export CRX_TAKER_CUSTODY=0x…     # the taker cold custody address
python3 examples/take.py
```

## Verify

```bash
python3 verify.py
```

- Run it from the repo root — it imports `crx_maker`.
- With only `CRX_SIGNER_PK` and `CRX_CUSTODY` set, it checks `/health`, the domain, and the socket logon, then exits 0.
- With `CRX_TAKER_SIGNER_PK` and `CRX_TAKER_CUSTODY` also set, it runs the full round trip in one process: open, quote, accept, `trade.opened`.
- It prints PASS with the trade id and the arm result, or FAIL naming the stage it reached.

## Examples

Run them from the repo root, `python3 examples/catch.py`.

- `examples/verify_signing.py`: run first, recomputing the Leg typehash, nonce, pair, domain separator, struct hash, leg_hash, and signature against a fixed fixture. No network, no env.
- `examples/catch.py`: hold the socket, print the logon ack, then the first RFQ. Needs `CRX_SIGNER_PK`, `CRX_CUSTODY`.
- `examples/take.py`: open an RFQ, build and sign its own taker Leg off `rfq.quoted`, accept, and hold for the fill. Self-contained taker. Needs `CRX_TAKER_SIGNER_PK`, `CRX_TAKER_CUSTODY`.
- `examples/sign.py`: build and sign the Leg digest for a sample RFQ through `crx_maker` internals, with no `quote()` call. Needs `CRX_SIGNER_PK`, `CRX_CUSTODY`, because importing `crx_maker` pulls the live domain off `/health`.
- `examples/deposit.py`: the gateway builds the txs, with an approve first when allowance falls short. Sign and submit them, through `crx_maker.deposit`. Needs `CRX_RPC_URL`, `CRX_SIGNER_PK`, `CRX_CUSTODY`.
- `examples/withdraw.py`: the gateway preflights coverage and builds the tx, through `crx_maker.withdraw`. Needs `CRX_RPC_URL`, `CRX_SIGNER_PK`, `CRX_CUSTODY`, `CRX_RECIPIENT`.
