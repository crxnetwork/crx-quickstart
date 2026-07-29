# withdraw.py: free collateral only, gated by IM coverage after the transfer
import os, sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from crx_maker import withdraw

CHAIN = "base"
SYMBOL = "USDC"
AMOUNT = "2500.50"                         # 6 decimal ledger units
RECIPIENT = os.environ["CRX_RECIPIENT"]    # must be on the onchain route whitelist

print("withdrawn in", withdraw(CHAIN, SYMBOL, AMOUNT, RECIPIENT))
