import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from crx_maker import cancel_quote

terms = {"taker": "0x7A3f5cE4d9B2a6F8C1e0d4b7A2F5c8E1D4b7a0F3",
          "maker": "0x4c9e2d7B5a8f3C6E1D0B4a7F2c5E8d1b6A9F0C3d",
          "notional": 1500000000000, "imBpsTaker": 292, "imBpsMaker": 292,
          "premiumBps": 0, "expiry": 1784247420, "nonce": 12216268158445721542,
          "instrumentId": 1,
          "pair": bytes.fromhex("35b8bafff3570683af968b8d36b91b1a19465141d9712425e9f76c68ff8cb152"),
          "side": 1, "settlement": 1788896256, "rate": 146250000}

print("cancelled in", cancel_quote(terms))
