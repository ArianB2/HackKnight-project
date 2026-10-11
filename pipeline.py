"""
Run the whole LedgerSentinel pipeline from data/ledger_clean.csv:

    python pipeline.py

1. lock the baseline (hash chain)
2. plant attacks and benign noise (injector)
3. score every row (integrity + rules + Isolation Forest)
4. evaluate detectors against ground truth
"""
from detect import score
from eval import evaluate
from integrity import hash_chain, injector

if __name__ == "__main__":
    for title, step in [("1. Lock baseline", lambda: hash_chain.main()),
                        ("2. Inject attacks", injector.main),
                        ("3. Score ledger", score.main),
                        ("4. Evaluate", evaluate.main)]:
        print(f"\n=== {title} ===")
        step()
