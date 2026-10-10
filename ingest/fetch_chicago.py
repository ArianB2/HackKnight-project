"""
LedgerSentinel: pull City of Chicago vendor payments and build the clean baseline ledger.

Run from the repo root:
    python ingest/fetch_chicago.py                      # pulls from the Chicago API
    python ingest/fetch_chicago.py path/to/Payments.csv # uses a CSV you exported manually

Outputs:
    data/raw/chicago_raw.csv    untouched source pull (gitignored, for provenance)
    data/ledger_clean.csv       clean baseline ledger, about 10k rows (commit this)
    data/sample.csv             first 500 rows for quick tests

The city updates this data daily, so ONE person runs this and commits
data/ledger_clean.csv. That way both teammates work on identical rows.
"""
import hashlib
import os
import sys

import numpy as np
import pandas as pd

SEED = 42
N_ROWS = 10_000
API = "https://data.cityofchicago.org/resource/s4vu-giwb.csv"
API_FILTERED = API + "?$where=voucher_number%20IS%20NOT%20NULL&$limit=200000"
API_PLAIN = API + "?$limit=200000"

CLERKS = ["clerk_ana", "clerk_ben", "clerk_cho", "clerk_dev", "clerk_eli", "clerk_fay"]
APPROVERS = ["mgr_gina", "mgr_hal", "mgr_ivy"]


def vendor_account(name: str) -> str:
    """Stable fake 10 digit bank account per vendor."""
    return str(int(hashlib.sha256(name.encode()).hexdigest(), 16) % 10**10).zfill(10)


def load_source() -> pd.DataFrame:
    """Read a local CSV if one is passed, otherwise pull from the API."""
    if len(sys.argv) > 1:
        print(f"Reading local file {sys.argv[1]}")
        df = pd.read_csv(sys.argv[1], dtype=str)
    else:
        try:
            df = pd.read_csv(API_FILTERED, dtype=str)
        except Exception as err:  # filter syntax rejected, retry without it
            print(f"Filtered query failed ({err}), retrying without filter")
            df = pd.read_csv(API_PLAIN, dtype=str)

    # Manual exports use "Check Date", the API uses "check_date". Normalize both.
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]
    return df


def main() -> None:
    rng = np.random.default_rng(SEED)

    df = load_source()
    print(f"Loaded {len(df):,} rows")
    os.makedirs("data/raw", exist_ok=True)
    df.to_csv("data/raw/chicago_raw.csv", index=False)

    # Older payments are rolled up with a year only date like "2024". Keep real payments.
    df = df[df["check_date"].fillna("").str.len() > 4].copy()
    df["date"] = pd.to_datetime(df["check_date"], errors="coerce")
    df["amount"] = pd.to_numeric(df["amount"].str.replace(r"[$,]", "", regex=True), errors="coerce")
    df = df.dropna(subset=["date", "amount", "vendor_name"])
    df = df[df["amount"] > 0]

    if df.empty:
        sys.exit("No individual payments found. Check the source file or API response.")

    # Most recent payments, oldest first
    df = df.sort_values("date", kind="stable").tail(N_ROWS).reset_index(drop=True)

    out = pd.DataFrame({
        "txn_id": [f"TXN{i:06d}" for i in range(len(df))],
        "voucher_number": df.get("voucher_number", pd.Series([""] * len(df))).fillna(""),
        "date": df["date"].dt.strftime("%Y-%m-%d"),
        "vendor": df["vendor_name"].str.strip(),
        "amount": df["amount"].round(2),
        "category": df["department_name"].fillna("UNKNOWN"),
        "contract_number": df["contract_number"].fillna(""),
    })

    # Synthetic columns (public data has no users or bank accounts)
    out["vendor_account"] = out["vendor"].map(vendor_account)
    out["created_by"] = rng.choice(CLERKS, size=len(out))
    out["approved_by"] = rng.choice(APPROVERS, size=len(out))

    # Approved 1 to 7 days before payment, during business hours (9am to 5pm)
    days_before = rng.integers(1, 8, size=len(out))
    hour = rng.integers(9, 17, size=len(out))
    minute = rng.integers(0, 60, size=len(out))
    approved = (
        pd.to_datetime(out["date"])
        - pd.to_timedelta(days_before, unit="D")
        + pd.to_timedelta(hour, unit="h")
        + pd.to_timedelta(minute, unit="m")
    )
    out["approved_at"] = approved.dt.strftime("%Y-%m-%dT%H:%M:00")

    out.to_csv("data/ledger_clean.csv", index=False)
    out.head(500).to_csv("data/sample.csv", index=False)

    print(f"Saved {len(out):,} rows to data/ledger_clean.csv")
    print(f"Date range: {out['date'].min()} to {out['date'].max()}")
    print(f"Vendors: {out['vendor'].nunique():,}")
    print(out.head())


if __name__ == "__main__":
    main()
