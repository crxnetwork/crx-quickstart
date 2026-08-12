import os, sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from crx_maker import withdraw

CHAIN = "base"
SYMBOL = "USDC"
AMOUNT = "2500.50"
RECIPIENT = os.environ["CRX_RECIPIENT"]

print("withdrawn in", withdraw(CHAIN, SYMBOL, AMOUNT, RECIPIENT))
