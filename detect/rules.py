"""Security rules, written like SIEM detection signatures.

Each rule: (id, points toward the risk score, plain English reason, test).
"""
import pandas as pd

RULES = [
    ("account_shared", 30, "Bank account is shared with a different vendor",
     lambda f: f["account_shared"] == 1),
    ("injection_text", 30, "Record text contains instructions aimed at an AI reviewer",
     lambda f: f["injection_text"] == 1),
    ("account_mismatch", 20, "Bank account differs from this vendor's known account",
     lambda f: f["account_mismatch"] == 1),
    ("duplicate", 30, "Same vendor and amount paid within 7 days (not a recurring bill)",
     lambda f: f["dup_unusual"] == 1),
    ("exceeds_vendor_max", 40, "At least 2x the largest payment this vendor has ever received",
     lambda f: (f["vendor_n"] >= 5) & (f["amount_vs_max"] >= 2)),
    ("new_vendor_large", 10, "New vendor receiving $10,000 or more",
     lambda f: (f["vendor_seen"] == 0) & (f["amount_f"] >= 10_000)),
    ("round_no_contract", 10, "Round amount with no contract on file",
     lambda f: (f["round_amount"] == 1) & (f["no_contract"] == 1)),
    ("off_hours", 10, "Approved between 10pm and 6am",
     lambda f: f["off_hours"] == 1),
]


def apply_rules(features: pd.DataFrame) -> pd.DataFrame:
    """Adds rule_points, rule_hits (ids) and rule_reasons (text) columns."""
    hits = pd.DataFrame({rid: test(features).values for rid, _, _, test in RULES}, index=features.index)
    points = {rid: pts for rid, pts, _, _ in RULES}
    reasons = {rid: text for rid, _, text, _ in RULES}
    out = pd.DataFrame(index=features.index)
    out["rule_points"] = sum(hits[r].astype(int) * points[r] for r in hits.columns)
    out["rule_hits"] = hits.apply(lambda row: ",".join(r for r in hits.columns if row[r]), axis=1)
    out["rule_reasons"] = hits.apply(lambda row: [reasons[r] for r in hits.columns if row[r]], axis=1)
    return out
