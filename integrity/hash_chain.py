"""
Hash chain over the trusted baseline ledger.

    python -m integrity.hash_chain build    # lock the oldest 80% of data/ledger_clean.csv
    python -m integrity.hash_chain verify   # check data/ledger_current.csv against it

Each approved row gets a SHA-256 hash of its fields. Each chain hash covers the
previous chain hash plus the row hash, so changing any row, or the manifest
itself, changes the final head hash. The head hash is what we anchor in S3
Object Lock, where an insider cannot overwrite it.
"""
import hashlib
import json
import sys

import pandas as pd

from common import (BASELINE_DIR, BASELINE_FRACTION, CLEAN, CURRENT, FIELDS, HEAD,
                    MANIFEST, SENSITIVE_FIELDS, SNAPSHOT, load_ledger, save_ledger)

GENESIS = "0" * 64
SEP = "\x1f"  # unit separator, cannot appear in normal CSV text


def row_hash(record: dict) -> str:
    payload = SEP.join(str(record[f]) for f in FIELDS)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def chain(row_hashes) -> list:
    out, prev = [], GENESIS
    for h in row_hashes:
        prev = hashlib.sha256((prev + h).encode("utf-8")).hexdigest()
        out.append(prev)
    return out


def build_manifest(snapshot: pd.DataFrame) -> pd.DataFrame:
    hashes = [row_hash(r) for r in snapshot[FIELDS].to_dict("records")]
    return pd.DataFrame({
        "position": range(len(snapshot)),
        "txn_id": snapshot["txn_id"].values,
        "row_hash": hashes,
        "chain_hash": chain(hashes),
    })


def build_baseline(clean: pd.DataFrame):
    n = int(len(clean) * BASELINE_FRACTION)
    snapshot = clean.iloc[:n].reset_index(drop=True)
    manifest = build_manifest(snapshot)
    head = manifest["chain_hash"].iloc[-1]
    return snapshot, manifest, head


def verify(current: pd.DataFrame, snapshot: pd.DataFrame, manifest: pd.DataFrame,
           expected_head: str | None = None) -> dict:
    """Compare the live ledger with the locked baseline.

    Returns a dict with:
      manifest_ok   recomputed chain matches the stored chain hashes
      snapshot_ok   the baseline snapshot itself still matches its hashes
      anchor_ok     head hash matches the externally anchored head (None if not given)
      head          recomputed head hash
      findings      one row per modified or deleted record, with field level changes
      first_break   chain position of the earliest broken record (None if intact)
    """
    recomputed_chain = chain(manifest["row_hash"].tolist())
    manifest_ok = recomputed_chain == manifest["chain_hash"].tolist()
    head = recomputed_chain[-1] if recomputed_chain else GENESIS

    snap_hashes = [row_hash(r) for r in snapshot[FIELDS].to_dict("records")]
    snapshot_ok = snap_hashes == manifest["row_hash"].tolist()

    cur = current.set_index("txn_id", drop=False)
    snap = snapshot.set_index("txn_id", drop=False)

    findings = []
    for pos, txn_id, expected in manifest[["position", "txn_id", "row_hash"]].itertuples(index=False):
        if txn_id not in cur.index:
            findings.append({"position": pos, "txn_id": txn_id, "status": "deleted",
                             "fields_changed": "", "sensitive": True, "changes": "[]"})
            continue
        record = cur.loc[txn_id]
        if isinstance(record, pd.DataFrame):  # duplicated txn_id is itself tampering
            record = record.iloc[0]
        if row_hash(record) == expected:
            continue
        original = snap.loc[txn_id]
        changes = [{"field": f, "old": str(original[f]), "new": str(record[f])}
                   for f in FIELDS if str(original[f]) != str(record[f])]
        changed = [c["field"] for c in changes]
        findings.append({
            "position": pos, "txn_id": txn_id, "status": "modified",
            "fields_changed": ",".join(changed),
            "sensitive": bool(SENSITIVE_FIELDS.intersection(changed)),
            "changes": json.dumps(changes),
        })

    findings = pd.DataFrame(findings, columns=["position", "txn_id", "status",
                                               "fields_changed", "sensitive", "changes"])
    return {
        "manifest_ok": manifest_ok,
        "snapshot_ok": snapshot_ok,
        "anchor_ok": None if expected_head is None else (expected_head.strip() == head),
        "head": head,
        "checked": len(manifest),
        "findings": findings,
        "first_break": None if findings.empty else int(findings["position"].min()),
    }


def load_baseline(directory=BASELINE_DIR):
    snapshot = load_ledger(directory / "snapshot.csv")
    manifest = pd.read_csv(directory / "manifest.csv", dtype={"row_hash": str, "chain_hash": str})
    head = (directory / "head.txt").read_text().strip()
    return snapshot, manifest, head


def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "build"
    if cmd == "build":
        snapshot, manifest, head = build_baseline(load_ledger(CLEAN))
        BASELINE_DIR.mkdir(parents=True, exist_ok=True)
        save_ledger(snapshot, SNAPSHOT)
        manifest.to_csv(MANIFEST, index=False)
        HEAD.write_text(head + "\n")
        print(f"Locked {len(snapshot):,} approved records")
        print(f"Head hash: {head}")
    elif cmd == "verify":
        snapshot, manifest, head = load_baseline()
        result = verify(load_ledger(CURRENT), snapshot, manifest, expected_head=head)
        f = result["findings"]
        print(f"Manifest chain intact: {result['manifest_ok']}")
        print(f"Snapshot intact:       {result['snapshot_ok']}")
        print(f"Head matches anchor:   {result['anchor_ok']}")
        print(f"Records checked:       {result['checked']:,}")
        print(f"Modified:              {(f['status'] == 'modified').sum()}")
        print(f"Deleted:               {(f['status'] == 'deleted').sum()}")
        if result["first_break"] is not None:
            print(f"Chain first breaks at position {result['first_break']}")
    else:
        sys.exit("Usage: python -m integrity.hash_chain [build|verify]")


if __name__ == "__main__":
    main()
