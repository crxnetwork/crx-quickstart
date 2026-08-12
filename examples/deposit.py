import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from crx_maker import deposit

CHAIN = "base"
SYMBOL = "USDC"
AMOUNT = "2500.50"

print("deposited in", deposit(CHAIN, SYMBOL, AMOUNT))
