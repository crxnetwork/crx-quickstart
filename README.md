# CRX quickstart

## Run it

Python 3.9 or newer.

```bash
pip install -r requirements.txt

cp .env.example .env        # fill in CRX_API_KEY, CRX_MAKER_PK
set -a; . ./.env; set +a    # a missing name fails at import as KeyError: 'CRX_API_KEY'

python quote.py
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

`crx_maker.py` does the rest:

- Checks the EIP-712 domain and refuses to sign on a mismatch.
- Builds the Terms digest, derives the nonce, and recovers its own signature before sending.
- Asserts the returned `terms_hash` matches the signed one.

**Drops and refusals.**

- `on_rfq` reconnects with a backoff doubling from 1s to 30s.
- The logon carries `since=<last seq>`, so the gateway replays the missed RFQs.
- Each drop and each resume prints one line.
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

**Testnet.** The CRX maker portal mints the keys. Full API reference at https://portal.crxfx.com/docs.

## Two sides, two processes

- An RFQ needs a taker to open it and a maker to price it.
- `quote.py` waits for an RFQ on its pair, so a quiet book prints nothing.
- `examples/take.py` opens an RFQ and waits for a firm quote, stalling with no maker listening.
- Run the maker first and let it log on, then the taker in a second shell.
- A fresh logon streams forward, so a maker connecting after the RFQ opened never sees it.
- Each side needs its own key, bound to its own EOA.
- `quote.py` takes a maker key and `examples/take.py` takes a taker key.
- A mismatch reads `401 unauthorized: this endpoint requires a taker key`.

```bash
cp .env.example .env.taker   # the taker key and its bound EOA

# shell one
set -a; . ./.env; set +a
python quote.py

# shell two
set -a; . ./.env.taker; set +a
python examples/take.py
```

## Verify

```bash
python verify.py
```

- With only the maker key set, it checks `/health`, the domain, and the socket logon, then exits 0.
- With `CRX_TAKER_KEY` and `CRX_TAKER_PK` set, it runs the full round trip in one process: open, quote, accept, `trade.opened`.
- It prints PASS with the trade id and tx, or FAIL naming the stage it reached.

## Examples

Run them from the repo root, `python examples/catch.py`.

- `examples/verify_signing.py`: run first, recomputing the nonce, instrument, domain separator, struct hash, terms_hash, and signature against the fixed fixture on [the signing page](https://portal.crxfx.com/docs/api/signing). No network, no env.
- `examples/catch.py`: hold the socket, print the logon ack, then the first RFQ. Needs `CRX_API_KEY`.
- `examples/take.py`: open an RFQ, rebuild and sign the maker's Terms off `rfq.opened`, accept, and hold for the fill. Needs a taker key in `CRX_API_KEY`, plus the bound taker private key in `CRX_MAKER_PK`.
- `examples/sign.py`: build and sign the Terms digest for a sample RFQ through `crx_maker` internals, with no `quote()` call. Needs `CRX_API_KEY` and `CRX_MAKER_PK`, because importing `crx_maker` reads both and pulls the live domain off `/health`.
- `examples/cancel.py`: pull a firm quote before it opens, through `crx_maker.cancel_quote`. Needs `CRX_RPC_URL`, `CRX_CORE`, `CRX_MAKER_PK`, and the `CRX_API_KEY` that `crx_maker` reads at import.
- `examples/deposit.py`: the gateway builds the txs, with an approve first when allowance falls short. Sign and submit them, through `crx_maker.deposit`. Needs `CRX_RPC_URL`, `CRX_MAKER_PK`, `CRX_API_KEY`.
- `examples/withdraw.py`: the gateway preflights coverage and builds the tx, through `crx_maker.withdraw`. Needs `CRX_RPC_URL`, `CRX_MAKER_PK`, `CRX_API_KEY`, `CRX_RECIPIENT`.
