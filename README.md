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
MARGIN_BPS = 292          # initial margin, basis points, taker and maker
FIRM_FOR_SECS = 60        # how long the quote stays firm

def price(rfq):
    q = quote(rfq, rate=RATE, im_bps=MARGIN_BPS, firm_for=FIRM_FOR_SECS)
    print(q["status"], q["terms_hash"])

on_rfq(price, PAIR)
```

**Two wallets.**

- `CRX_SIGNER_PK` is the **hot signer**. It signs every quote, accept, and WS logon.
- `CRX_CUSTODY` is the **cold custody** address. It is the `maker` the signer acts for — an address, never a key.
- The Terms bind `maker = CUSTODY`; the signature comes from `SIGNER`. The gateway recovers the signer and checks the `(custody, signer)` pair is whitelisted.

`crx_maker.py` does the rest:

- Logs on over the socket: the gateway sends a `challenge` nonce, the signer signs the six-line hello, the client replies with the logon frame. No minted key, no session header.
- Quotes carry no auth header — the signature is the credential.
- Checks the EIP-712 domain and refuses to sign on a mismatch.
- Builds the Terms digest, derives the nonce, and recovers its own signature before sending.
- Asserts the returned `terms_hash` matches the signed one.

**Drops and refusals.**

- `on_rfq` reconnects with a backoff doubling from 1s to 30s.
- Each reconnect answers a fresh challenge and streams forward from the head.
- A refused logon prints the reason and stops.
- Refusals raise `crx_maker.CrxError`, carrying `.status`, `.code`, and `.message`.
- Branch on `.code`.

**Units.**

- Every numeric wire timestamp is unix **milliseconds**.
- Covers `settlement` on `rfq.opened`, `expires_at` on quotes, and `settlement` on a posted RFQ.
- The signed Terms header stays in seconds.
- `crx_maker.py` divides the wire `settlement` by 1000 before packing the u40.
- It multiplies the seconds `expiry` by 1000 for the wire `expires_at`.
- The gateway refuses the wrong scale: `400 bad_request: settlement … looks like unix seconds; wire timestamps are unix milliseconds`.

**Testnet.** The signature is the credential — a whitelisted `(custody, signer)` pair, no minted key. Full API reference at https://portal.crxfx.com/docs.

## Two sides, two processes

- An RFQ needs a taker to open it and a maker to price it.
- `quote.py` waits for an RFQ on its pair, so a quiet book prints nothing.
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

- With only `CRX_SIGNER_PK` and `CRX_CUSTODY` set, it checks `/health`, the domain, and the socket logon, then exits 0.
- With `CRX_TAKER_SIGNER_PK` and `CRX_TAKER_CUSTODY` also set, it runs the full round trip in one process: open, quote, accept, `trade.opened`.
- It prints PASS with the trade id and tx, or FAIL naming the stage it reached.

## Examples

Run them from the repo root, `python3 examples/catch.py`.

- `examples/verify_signing.py`: run first, recomputing the nonce, instrument, domain separator, struct hash, terms_hash, and signature against the fixed fixture on [the signing page](https://portal.crxfx.com/docs/api/signing). No network, no env.
- `examples/catch.py`: hold the socket, print the logon ack, then the first RFQ. Needs `CRX_SIGNER_PK`, `CRX_CUSTODY`.
- `examples/take.py`: open an RFQ, rebuild and sign the maker's Terms off `rfq.opened`, accept, and hold for the fill. Self-contained taker. Needs `CRX_TAKER_SIGNER_PK`, `CRX_TAKER_CUSTODY`.
- `examples/sign.py`: build and sign the Terms digest for a sample RFQ through `crx_maker` internals, with no `quote()` call. Needs `CRX_SIGNER_PK`, `CRX_CUSTODY`, because importing `crx_maker` pulls the live domain off `/health`.
- `examples/cancel.py`: pull a firm quote before it opens, through `crx_maker.cancel_quote`. Needs `CRX_RPC_URL`, `CRX_CORE`, `CRX_SIGNER_PK`, `CRX_CUSTODY`.
- `examples/deposit.py`: the gateway builds the txs, with an approve first when allowance falls short. Sign and submit them, through `crx_maker.deposit`. Needs `CRX_RPC_URL`, `CRX_SIGNER_PK`, `CRX_CUSTODY`.
- `examples/withdraw.py`: the gateway preflights coverage and builds the tx, through `crx_maker.withdraw`. Needs `CRX_RPC_URL`, `CRX_SIGNER_PK`, `CRX_CUSTODY`, `CRX_RECIPIENT`.
