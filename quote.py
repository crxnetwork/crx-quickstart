# quote.py: the maker leg. No API key — the signer logs on with a signed hello, the whitelisted custody address is the credential
from crx_maker import on_rfq, quote

PAIR = "USDJPY"
RATE = "146.250000"       # a decimal string
MARGIN_BPS = 292          # initial margin in basis points, taker and maker alike
FIRM_FOR_SECS = 60

def price(rfq):
    q = quote(rfq, rate=RATE, im_bps=MARGIN_BPS, firm_for=FIRM_FOR_SECS)
    print(q["status"], q["terms_hash"])

on_rfq(price, PAIR)
