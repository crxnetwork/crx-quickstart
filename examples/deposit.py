# deposit.py: sign and submit the txs the gateway builds, which also cures a margin call
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from crx_maker import deposit

CHAIN = "base"
SYMBOL = "USDC"
AMOUNT = "2500.50"   # a decimal string in the token's own decimals

print("deposited in", deposit(CHAIN, SYMBOL, AMOUNT))
