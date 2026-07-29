# cancel.py: pull a firm quote before it opens
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from crx_maker import cancel_quote

# terms: the same nine field dict built and signed for quote()
terms = {"taker": "0x7A3f5cE4d9B2a6F8C1e0d4b7A2F5c8E1D4b7a0F3",
          "maker": "0x4c9e2d7B5a8f3C6E1D0B4a7F2c5E8d1b6A9F0C3d",
          "notional": 1500000000000, "imBpsTaker": 292, "imBpsMaker": 292,
          "premiumBps": 0, "expiry": 1784247420, "nonce": 12216268158445721542,
          "instrument": bytes.fromhex(
              "0135b8bafff3570683af968b8d36b91b1a19465141d9712425e9f76c68ff8cb15201006aa9dc000000000008b79910")}

print("cancelled in", cancel_quote(terms))
