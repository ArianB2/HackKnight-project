"""
Score each detector against the injector's ground truth.

    python -m eval.evaluate

Uses the pristine injected ledger (not live demo edits) so numbers are stable.
Writes eval/results/summary.csv, by_attack_type.csv, and results.md for slides.
"""
import pandas as pd

from common import (EDIT_LOG_PRISTINE, LABELS, PRISTINE, RESULTS_DIR, load_edit_log,
                    load_ledger)
from detect.score import run_detection
from integrity.hash_chain import load_baseline

DETECTORS = {
    "Hash chain": "flag_chain",
    "Rules only": "flag_rules",
    "Isolation Forest (top 1%)": "flag_if",
    "Combined risk score": "flag_combined",
}


def to_markdown(df: pd.DataFrame) -> str:
    head = "| " + " | ".join(map(str, df.columns)) + " |"
    rule = "|" + "|".join("---" for _ in df.columns) + "|"
    body = ["| " + " | ".join(map(str, row)) + " |" for row in df.itertuples(index=False)]
    return "\n".join([head, rule] + body)


def evaluate(scores: pd.DataFrame, labels: pd.DataFrame):
    attacks = labels[labels["is_attack"] == 1].set_index("txn_id")
    y = scores["txn_id"].isin(attacks.index)
    rows = []
    for name, col in DETECTORS.items():
        flagged = scores[col].fillna(False).astype(bool)
        tp = int((flagged & y).sum())
        rows.append({
            "Detector": name,
            "Flagged": int(flagged.sum()),
            "True attacks caught": tp,
            "Precision": round(tp / flagged.sum(), 3) if flagged.sum() else 0.0,
            "Recall": round(tp / y.sum(), 3) if y.sum() else 0.0,
        })
    summary = pd.DataFrame(rows)

    merged = scores.merge(attacks[["attack_type"]], left_on="txn_id", right_index=True)
    by_type = merged.groupby("attack_type").agg(
        Planted=("txn_id", "size"),
        **{name: (col, lambda s: int(s.fillna(False).astype(bool).sum())) for name, col in DETECTORS.items()},
    )
    return summary, by_type.reset_index().rename(columns={"attack_type": "Attack type"})


def main() -> None:
    snapshot, manifest, head = load_baseline()
    scores, _ = run_detection(load_ledger(PRISTINE), snapshot, manifest,
                              load_edit_log(EDIT_LOG_PRISTINE), expected_head=head)
    labels = pd.read_csv(LABELS, dtype=str)
    labels["is_attack"] = labels["is_attack"].astype(int)
    summary, by_type = evaluate(scores, labels)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    summary.to_csv(RESULTS_DIR / "summary.csv", index=False)
    by_type.to_csv(RESULTS_DIR / "by_attack_type.csv", index=False)
    md = ["# LedgerSentinel evaluation", "",
          f"{int(labels['is_attack'].sum())} planted attacks among {len(scores):,} records.", "",
          to_markdown(summary), "", "## Catches per attack type", "",
          to_markdown(by_type), ""]
    (RESULTS_DIR / "results.md").write_text("\n".join(md))
    print(summary.to_string(index=False))
    print()
    print(by_type.to_string(index=False))


if __name__ == "__main__":
    main()
