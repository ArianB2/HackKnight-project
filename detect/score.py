"""
Combine the three layers into one risk score per transaction.

    python -m detect.score

    integrity (hash chain)  -> was an approved record changed or deleted?
    rules                   -> known fraud patterns
    Isolation Forest        -> statistically unusual rows
    edit log context        -> who changed it, when, and was it logged at all

Writes data/scores.csv (every row) and data/alerts.csv (risk >= threshold).
"""
import pandas as pd

from common import (ALERT_THRESHOLD, ALERTS, CURRENT, EDIT_LOG, FIELDS, SCORES,
                    load_edit_log, load_ledger)
from detect.features import build_features, edit_context
from detect.model import anomaly_scores
from detect.rules import apply_rules
from integrity.hash_chain import load_baseline, verify


def _level(risk: float) -> str:
    return "High" if risk >= 70 else "Medium" if risk >= ALERT_THRESHOLD else "Low"


def run_detection(current, snapshot, manifest, edit_log, expected_head=None, threshold=ALERT_THRESHOLD):
    integrity = verify(current, snapshot, manifest, expected_head)
    findings = integrity["findings"].set_index("txn_id")
    locked = set(manifest["txn_id"])

    feats = build_features(current, snapshot)
    s = pd.concat([feats, apply_rules(feats), anomaly_scores(feats)], axis=1)
    s = s.join(edit_context(edit_log), on="txn_id")

    status = s["txn_id"].map(findings["status"]).astype(object)
    s["integrity_status"] = status.where(status.notna(), s["txn_id"].isin(locked).map({True: "ok", False: "new"}))
    s["fields_changed"] = s["txn_id"].map(findings["fields_changed"]).fillna("")
    s["changes"] = s["txn_id"].map(findings["changes"]).fillna("[]")
    sensitive = s["txn_id"].map(findings["sensitive"]).fillna(False).astype(bool)

    risks, reasons = [], []
    for i, r in s.iterrows():
        pts, why = 0.0, []
        if r["integrity_status"] == "modified":
            pts += 35 if sensitive[i] else 10
            why.append(f"Approved record was changed after approval ({r['fields_changed']})")
            if pd.isna(r["n_edits"]):
                pts += 15
                why.append("No matching entry in the edit log: changed outside the application")
            else:
                if r["edited_by_clerk"] == 1:
                    pts += 10
                    why.append(f"Edited by {r['editors']}, who is not an approver")
                if r["edit_off_hours"] == 1:
                    pts += 10
                    why.append("Edited between 10pm and 6am")
        pts += r["rule_points"]
        why += r["rule_reasons"]
        if r["if_points"] > 0:
            pts += r["if_points"]
            top = max(0.1, (1 - r["if_pct"]) * 100)
            detail = f"Unusual compared with other payments (Isolation Forest, top {top:.1f}%)"
            if r["vendor_seen"] == 1 and r["amount_ratio"] >= 3:
                detail += f"; amount is {r['amount_ratio']:.1f}x this vendor's typical payment"
            why.append(detail)
        risks.append(min(100.0, pts))
        reasons.append(why)
    s["risk_score"] = [round(x, 1) for x in risks]
    s["reasons"] = [" | ".join(w) for w in reasons]

    # Deleted records are not in the live ledger, so add them back from the baseline
    deleted_ids = findings.index[findings["status"] == "deleted"]
    if len(deleted_ids):
        d = snapshot[snapshot["txn_id"].isin(deleted_ids)].copy()
        d["integrity_status"] = "deleted"
        d["fields_changed"] = "entire record"
        d["changes"] = "[]"
        d["risk_score"] = 60.0
        d["reasons"] = "Approved record was deleted from the ledger"
        d["rule_hits"] = ""
        s = pd.concat([s, d], ignore_index=True)

    s["level"] = s["risk_score"].map(_level)
    s["flag_chain"] = s["integrity_status"].isin(["modified", "deleted"])
    s["flag_rules"] = s["rule_hits"].fillna("") != ""
    s["flag_if"] = s["if_pct"].fillna(0) >= 0.99
    s["flag_combined"] = s["risk_score"] >= threshold

    keep = FIELDS + ["integrity_status", "fields_changed", "changes", "risk_score", "level",
                     "reasons", "rule_hits", "if_score", "if_pct", "amount_ratio", "editors",
                     "n_edits", "flag_chain", "flag_rules", "flag_if", "flag_combined"]
    s = s[keep].sort_values("risk_score", ascending=False).reset_index(drop=True)
    return s, integrity


def main() -> None:
    snapshot, manifest, head = load_baseline()
    scores, integrity = run_detection(load_ledger(CURRENT), snapshot, manifest,
                                      load_edit_log(EDIT_LOG), expected_head=head)
    scores.to_csv(SCORES, index=False)
    alerts = scores[scores["flag_combined"]]
    alerts.to_csv(ALERTS, index=False)
    print(f"Scored {len(scores):,} rows | alerts: {len(alerts)} "
          f"(High {int((alerts['level'] == 'High').sum())}, Medium {int((alerts['level'] == 'Medium').sum())})")
    print(alerts[["txn_id", "vendor", "amount", "risk_score", "reasons"]].head(10).to_string(max_colwidth=70))


if __name__ == "__main__":
    main()
