"""Turn each ledger row into numbers the rules and the model can use.

History is the locked baseline snapshot: what "normal" looked like for each
vendor before anyone could tamper with it.
"""
import numpy as np
import pandas as pd

from integrity.sanitize import detect_injection

MODEL_FEATURES = [
    "log_amount",       # size of the payment (log scale)
    "amount_z",         # how unusual the amount is for this vendor
    "log_vendor_n",     # how often we have paid this vendor before
    "vendor_seen",      # vendor exists in trusted history
    "approve_hour",     # hour of approval
    "days_to_pay",      # days between approval and payment
    "no_contract",      # no contract number on file
    "round_amount",     # exact multiple of $500, at least $1,000
    "log_vs_max",       # amount compared with the largest past payment to this vendor
    "dup_unusual",      # repeat of a recent payment for a vendor not normally billed repeats
]


def _log(x):
    return np.log10(np.clip(x, 1, None))


def build_features(current: pd.DataFrame, history: pd.DataFrame) -> pd.DataFrame:
    f = current.copy()
    f["amount_f"] = pd.to_numeric(f["amount"], errors="coerce").fillna(0.0)
    f["log_amount"] = _log(f["amount_f"])

    h = history.copy()
    h["log_amount"] = _log(pd.to_numeric(h["amount"], errors="coerce").fillna(0.0))
    vendor = h.groupby("vendor")["log_amount"].agg(vendor_n="size", vendor_med="median", vendor_std="std")
    known_account = h.groupby("vendor")["vendor_account"].agg(lambda s: s.mode().iat[0])
    category_med = h.groupby("category")["log_amount"].median()
    h["amount_f"] = pd.to_numeric(h["amount"], errors="coerce").fillna(0.0)
    vendor_max = h.groupby("vendor")["amount_f"].max()
    repeats = h.groupby(["vendor", "amount_f"]).size()

    f = f.join(vendor, on="vendor")
    f["vendor_seen"] = f["vendor_n"].notna().astype(int)
    f["vendor_n"] = f["vendor_n"].fillna(0)
    f["log_vendor_n"] = np.log1p(f["vendor_n"])

    reference = f["vendor_med"].fillna(f["category"].map(category_med)).fillna(h["log_amount"].median())
    spread = f["vendor_std"].where(f["vendor_n"] >= 3).fillna(0.5).clip(lower=0.25)
    f["amount_z"] = (f["log_amount"] - reference) / spread
    f["amount_ratio"] = 10 ** (f["log_amount"] - reference)   # x times the typical payment
    f["amount_vs_max"] = (f["amount_f"] / f["vendor"].map(vendor_max)).fillna(1.0)
    f["log_vs_max"] = np.log10(f["amount_vs_max"].clip(lower=0.01))

    expected_account = f["vendor"].map(known_account)
    f["account_mismatch"] = (expected_account.notna() & (f["vendor_account"] != expected_account)).astype(int)
    vendors_per_account = f.groupby("vendor_account")["vendor"].nunique()
    f["account_shared"] = (f["vendor_account"].map(vendors_per_account) > 1).astype(int)

    approved = pd.to_datetime(f["approved_at"], errors="coerce")
    paid = pd.to_datetime(f["date"], errors="coerce")
    f["approve_hour"] = approved.dt.hour.fillna(12).astype(int)
    f["off_hours"] = ((f["approve_hour"] < 6) | (f["approve_hour"] >= 22)).astype(int)
    f["days_to_pay"] = (paid - approved.dt.normalize()).dt.days.fillna(0)

    # "DV" (direct voucher) is how Chicago marks payments made without a contract
    f["no_contract"] = f["contract_number"].str.strip().isin(["", "DV"]).astype(int)
    f["round_amount"] = ((f["amount_f"] >= 1000) & (f["amount_f"] % 500 == 0)).astype(int)
    f["injection_text"] = f["vendor"].map(detect_injection).astype(int)

    f["dup_count"] = 0
    f["_paid"] = paid
    key = ["vendor", "amount_f"]
    repeated = f[f.duplicated(key, keep=False)]
    for _, idx in repeated.groupby(key).groups.items():
        d = f.loc[idx, "_paid"].to_numpy(dtype="datetime64[ns]")
        v = f.loc[idx, "voucher_number"].to_numpy(dtype=object)
        close = np.abs(d[:, None] - d[None, :]) <= np.timedelta64(7, "D")
        # Identical lines on the SAME voucher are one payment split into parts, not a duplicate
        other_voucher = v[:, None] != v[None, :]
        f.loc[idx, "dup_count"] = (close & other_voucher).sum(axis=1)
    # Recurring bills (rent, leases) repeat the same amount legitimately. A repeat is only
    # suspicious when the vendor's trusted history does not show that amount recurring.
    pairs = pd.MultiIndex.from_frame(f[["vendor", "amount_f"]])
    f["amount_hist_repeats"] = repeats.reindex(pairs).fillna(0).values
    f["dup_unusual"] = ((f["dup_count"] > 0) & (f["amount_hist_repeats"] <= 1)).astype(int)
    return f.drop(columns=["_paid"])


def edit_context(edit_log: pd.DataFrame) -> pd.DataFrame:
    """Per transaction summary of the application edit log."""
    if edit_log.empty:
        return pd.DataFrame(columns=["n_edits", "edited_by_clerk", "edit_off_hours", "editors", "last_edit"],
                            index=pd.Index([], name="txn_id", dtype=object))
    log = edit_log.copy()
    hour = pd.to_datetime(log["timestamp"], errors="coerce").dt.hour
    log["off"] = ((hour < 6) | (hour >= 22)).astype(int)
    log["clerk"] = log["user"].str.startswith("clerk").astype(int)
    return log.groupby("txn_id").agg(
        n_edits=("event_id", "size"),
        edited_by_clerk=("clerk", "max"),
        edit_off_hours=("off", "max"),
        editors=("user", lambda s: ", ".join(sorted(set(s)))),
        last_edit=("timestamp", "max"),
    )
