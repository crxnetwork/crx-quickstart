from crx_maker import on_rfq, quote

PAIR = "USDJPY"
RATE = "146.250000"
MARGIN_BPS = 292
FIRM_FOR_SECS = 60

def price(rfq):
    q = quote(rfq, rate=RATE, im_bps=MARGIN_BPS, firm_for=FIRM_FOR_SECS)
    print(q["status"], q["terms_hash"])

on_rfq(price, PAIR)
