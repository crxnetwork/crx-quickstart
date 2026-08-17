from crx_maker import on_rfq, quote

PAIR = "USDJPY"
RATE = "146.250000"
FIRM_FOR_SECS = 60

def price(rfq):
    q = quote(rfq, rate=RATE, firm_for=FIRM_FOR_SECS)
    print(q["status"], q["leg_hash"])

on_rfq(price, PAIR)
