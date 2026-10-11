"""Shared paths, schema, and ledger I/O for LedgerSentinel."""
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"

CLEAN = DATA / "ledger_clean.csv"              # output of ingest/fetch_chicago.py
CURRENT = DATA / "ledger_current.csv"          # live ledger (tampered by injector / demo)
PRISTINE = DATA / "ledger_current_pristine.csv"  # copy used for evaluation and demo reset
EDIT_LOG = DATA / "edit_log.csv"
EDIT_LOG_PRISTINE = DATA / "edit_log_pristine.csv"
LABELS = DATA / "labels.csv"                   # ground truth from the injector

BASELINE_DIR = DATA / "baseline"
SNAPSHOT = BASELINE_DIR / "snapshot.csv"       # trusted copy of approved records
MANIFEST = BASELINE_DIR / "manifest.csv"       # row hashes + chain hashes
HEAD = BASELINE_DIR / "head.txt"               # final chain hash (anchored in S3)

SCORES = DATA / "scores.csv"                   # every row with its risk score
ALERTS = DATA / "alerts.csv"                   # rows at or above the alert threshold
RESULTS_DIR = ROOT / "eval" / "results"

FIELDS = [
    "txn_id", "voucher_number", "date", "vendor", "amount", "category",
    "contract_number", "vendor_account", "created_by", "approved_by", "approved_at",
]
SENSITIVE_FIELDS = {"vendor", "vendor_account", "amount"}
BASELINE_FRACTION = 0.8   # oldest 80% of rows are approved and locked
ALERT_THRESHOLD = 40
EDIT_LOG_COLUMNS = ["event_id", "txn_id", "user", "timestamp", "field", "old_value", "new_value"]


def load_ledger(path) -> pd.DataFrame:
    """Read every column as text so hashes are byte-for-byte stable."""
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    return df[FIELDS] if set(FIELDS).issubset(df.columns) else df


def save_ledger(df: pd.DataFrame, path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    df[FIELDS].to_csv(path, index=False)


def load_edit_log(path) -> pd.DataFrame:
    if not Path(path).exists():
        return pd.DataFrame(columns=EDIT_LOG_COLUMNS)
    return pd.read_csv(path, dtype=str, keep_default_na=False)
