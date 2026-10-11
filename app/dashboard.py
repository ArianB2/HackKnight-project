"""
LedgerSentinel AI dashboard.

    streamlit run app/dashboard.py

Optional environment variables:
    LS_BUCKET         S3 bucket holding the Object Lock baseline (verify against S3, not local disk)
    LS_BEDROCK_MODEL  Bedrock model or inference profile ID for explanations
"""
import json
import os
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from common import (ALERT_THRESHOLD, CLEAN, EDIT_LOG, EDIT_LOG_COLUMNS, EDIT_LOG_PRISTINE,  # noqa: E402
                    LABELS, PRISTINE, CURRENT, load_edit_log, load_ledger, save_ledger)
from detect.explain import DEFAULT_MODEL, case_report, explain  # noqa: E402
from detect.score import run_detection  # noqa: E402
from eval.evaluate import evaluate as score_detectors  # noqa: E402
from integrity.hash_chain import load_baseline  # noqa: E402

st.set_page_config(page_title="LedgerSentinel AI", layout="wide")


# ---------------------------------------------------------------- data loading
@st.cache_data(show_spinner="Loading trusted baseline...")
def get_baseline(bucket: str):
    note = ""
    if bucket:
        try:
            from cloud.anchor import download
            snapshot, manifest, head = load_baseline(download(bucket))
            return snapshot, manifest, head, f"S3 Object Lock (s3://{bucket}/baseline/)", note
        except Exception as err:
            note = f"S3 unavailable ({type(err).__name__}), fell back to the local baseline."
    snapshot, manifest, head = load_baseline()
    return snapshot, manifest, head, "Local disk (demo mode, not tamper-proof)", note


@st.cache_data(show_spinner="Scoring every transaction...")
def get_scores(file_key, bucket: str, threshold: int):
    snapshot, manifest, head, source, note = get_baseline(bucket)
    scores, integrity = run_detection(load_ledger(CURRENT), snapshot, manifest,
                                      load_edit_log(EDIT_LOG), head, threshold)
    return scores, integrity, source, note


@st.cache_data(show_spinner="Evaluating detectors against planted attacks...")
def get_evaluation(threshold: int):
    snapshot, manifest, head = load_baseline()
    scores, _ = run_detection(load_ledger(PRISTINE), snapshot, manifest,
                              load_edit_log(EDIT_LOG_PRISTINE), head, threshold)
    labels = pd.read_csv(LABELS, dtype=str)
    labels["is_attack"] = labels["is_attack"].astype(int)
    return score_detectors(scores, labels)


def money(x) -> str:
    try:
        return f"${float(x):,.2f}"
    except (TypeError, ValueError):
        return str(x)


# ---------------------------------------------------------------- sidebar
with st.sidebar:
    st.header("Settings")
    bucket = st.text_input("S3 baseline bucket", os.environ.get("LS_BUCKET", ""),
                           help="Bucket with Object Lock. Leave blank to use the local baseline.")
    model_id = st.text_input("Bedrock model ID", DEFAULT_MODEL)
    use_llm = st.toggle("AI explanations (Bedrock)", value=True)
    threshold = st.slider("Alert threshold", 20, 90, ALERT_THRESHOLD, 5)
    st.divider()
    st.subheader("Demo scenario")
    if st.button("Clean ledger (chain intact)", width="stretch",
                 help="Start here for the live demo: no tampering, chain is green"):
        save_ledger(load_ledger(CLEAN), CURRENT)
        pd.DataFrame(columns=EDIT_LOG_COLUMNS).to_csv(EDIT_LOG, index=False)
        st.session_state.clear()
        st.rerun()
    if st.button("Planted attacks (full alert queue)", width="stretch",
                 help="Ledger with the injector's 56 attacks and benign noise"):
        shutil.copy(PRISTINE, CURRENT)
        shutil.copy(EDIT_LOG_PRISTINE, EDIT_LOG)
        st.session_state.clear()
        st.rerun()

file_key = (CURRENT.stat().st_mtime_ns, EDIT_LOG.stat().st_mtime_ns)
scores, integrity, source, note = get_scores(file_key, bucket, threshold)
alerts = scores[scores["risk_score"] >= threshold]
findings = integrity["findings"]

# ---------------------------------------------------------------- header
st.title("LedgerSentinel AI")
st.subheader("Financial Integrity & Cybersecurity Monitoring")
st.caption("Every transaction tells a story. LedgerSentinel finds the ones that don't add up.")
if note:
    st.warning(note)

k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("Transactions checked", f"{(scores['integrity_status'] != 'deleted').sum():,}")
k2.metric("Approved records verified", f"{integrity['checked']:,}")
k3.metric("Integrity breaks", len(findings))
k4.metric("Alerts", len(alerts))
k5.metric("High risk", int((alerts["level"] == "High").sum()))

if findings.empty:
    st.success("Hash chain intact: every approved record matches the locked baseline.")
else:
    n_mod = int((findings["status"] == "modified").sum())
    n_del = int((findings["status"] == "deleted").sum())
    st.error(f"Hash chain broken at position {integrity['first_break']:,}: "
             f"{n_mod} approved records modified, {n_del} deleted since approval.")
st.caption(f"Trusted baseline: {source}  ·  head hash `{integrity['head'][:20]}...`  ·  "
           f"anchor match: {integrity['anchor_ok']}")

tab_alerts, tab_integrity, tab_demo, tab_eval = st.tabs(
    ["Alerts", "Integrity", "Live tamper demo", "Evaluation"])

# ---------------------------------------------------------------- alerts
with tab_alerts:
    table = alerts[["risk_score", "level", "txn_id", "date", "vendor", "amount",
                    "integrity_status", "reasons"]].copy()
    table["amount"] = table["amount"].map(money)
    st.dataframe(table, hide_index=True, height=330,
                 column_config={"risk_score": st.column_config.ProgressColumn(
                     "Risk", min_value=0, max_value=100, format="%.0f")})

    if alerts.empty:
        st.info("No alerts at this threshold.")
    else:
        by_id = alerts.set_index("txn_id", drop=False)
        sel = st.selectbox("Investigate a transaction", by_id.index.tolist(),
                           format_func=lambda t: f"{t} · {str(by_id.at[t, 'vendor'])[:45]} · "
                                                 f"{money(by_id.at[t, 'amount'])} · risk {by_id.at[t, 'risk_score']:.0f}")
        alert = by_id.loc[sel].to_dict()
        left, right = st.columns([1, 1])
        with left:
            st.markdown(f"#### {alert['vendor']}")
            st.markdown(f"**{money(alert['amount'])}** paid {alert['date']} to account "
                        f"`{alert['vendor_account']}`  \nCreated by `{alert['created_by']}`, approved by "
                        f"`{alert['approved_by']}` at {alert['approved_at']}")
            st.markdown("**Why it was flagged**")
            for reason in str(alert["reasons"]).split(" | "):
                st.markdown(f"- {reason}")
            changes = json.loads(alert.get("changes") or "[]")
            if changes:
                st.markdown("**Changed since approval**")
                st.table(pd.DataFrame(changes).rename(columns={"field": "Field", "old": "Approved value",
                                                               "new": "Current value"}))
        with right:
            key = f"exp_{sel}"
            if st.button("Explain with AI", type="primary"):
                with st.spinner("Writing explanation..."):
                    st.session_state[key] = explain(alert, model_id, use_llm)
            if key in st.session_state:
                text, how = st.session_state[key]
                st.markdown("**AI summary**" if how == "bedrock" else "**Summary (template)**")
                st.info(text)
                st.download_button("Download case report", case_report(alert, text, integrity, source),
                                   file_name=f"case_{sel}.md", mime="text/markdown")

# ---------------------------------------------------------------- integrity
with tab_integrity:
    st.markdown(
        "Each approved record is hashed with SHA-256. Each chain link hashes the previous link plus "
        "the record, so one silent edit changes every link after it. The final head hash is stored in "
        "S3 with Object Lock, so an insider who can edit the ledger still cannot rewrite the proof.")
    a, b, c = st.columns(3)
    a.metric("Manifest chain valid", "Yes" if integrity["manifest_ok"] else "No")
    b.metric("Baseline snapshot valid", "Yes" if integrity["snapshot_ok"] else "No")
    c.metric("Matches anchored head", {True: "Yes", False: "No", None: "Not checked"}[integrity["anchor_ok"]])
    if findings.empty:
        st.success("No modified or deleted records.")
    else:
        rows = []
        for f in findings.itertuples(index=False):
            ch = json.loads(f.changes)
            rows.append({"Position": f.position, "Transaction": f.txn_id, "Status": f.status,
                         "Changes": "; ".join(f"{x['field']}: {x['old']} → {x['new']}" for x in ch)
                         or "record removed"})
        st.dataframe(pd.DataFrame(rows), hide_index=True)

# ---------------------------------------------------------------- live demo
with tab_demo:
    st.markdown("Play the insider. Change an approved payment and watch the chain break.")
    current = load_ledger(CURRENT)
    snapshot = get_baseline(bucket)[0]
    untouched = set(snapshot["txn_id"]) - set(findings["txn_id"])
    pool = current[current["txn_id"].isin(untouched)].copy()
    business = pool["vendor"].str.contains(r"\b(?:LLC|INC|CORP|CO|COMPANY|LTD|SERVICES)\b", regex=True)
    pool = pool[business] if business.any() else pool   # demo on companies, not individuals
    pool["gap"] = (pd.to_numeric(pool["amount"], errors="coerce") - 500).abs()
    pool = pool.sort_values("gap").head(200)
    txn = st.selectbox("Approved transaction", pool["txn_id"].tolist(),
                       format_func=lambda t: f"{t} · {pool.set_index('txn_id').at[t, 'vendor'][:45]} · "
                                             f"{money(pool.set_index('txn_id').at[t, 'amount'])}")
    row = current[current["txn_id"] == txn].iloc[0]
    st.write(f"Currently pays **{money(row['amount'])}** to **{row['vendor']}**, account `{row['vendor_account']}`")
    with st.form("tamper"):
        c1, c2 = st.columns(2)
        new_account = c1.text_input("New bank account", "7700999001")
        new_amount = c2.text_input("Amount", row["amount"])
        c3, c4 = st.columns(2)
        user = c3.selectbox("Edited by", ["clerk_dev", "clerk_ana", "mgr_gina"])
        logged = c4.checkbox("Record the edit in the application log", value=False,
                             help="Unchecked = changed directly in the database, leaving no log entry")
        if st.form_submit_button("Apply edit", type="primary"):
            idx = current.index[current["txn_id"] == txn][0]
            log = load_edit_log(EDIT_LOG)
            stamp = pd.Timestamp.now().strftime("%Y-%m-%dT%H:%M:00")
            for field, value in (("vendor_account", new_account), ("amount", new_amount)):
                if str(value) != str(current.at[idx, field]):
                    if logged:
                        log.loc[len(log)] = [f"EV9{len(log):04d}", txn, user, stamp, field,
                                             current.at[idx, field], value]
                    current.at[idx, field] = value
            save_ledger(current, CURRENT)
            log[EDIT_LOG_COLUMNS].to_csv(EDIT_LOG, index=False)
            st.session_state["last_tamper"] = txn
            st.rerun()
    if "last_tamper" in st.session_state:
        t = st.session_state["last_tamper"]
        hit = scores[scores["txn_id"] == t]
        if not hit.empty:
            st.error(f"Detected: {t} now scores {hit['risk_score'].iat[0]:.0f}/100. Open the Alerts tab to investigate.")

# ---------------------------------------------------------------- evaluation
with tab_eval:
    st.markdown("Detectors scored against attacks planted by the injector (ground truth). "
                "Run on the pristine injected ledger, so live demo edits do not affect these numbers.")
    summary, by_type = get_evaluation(threshold)
    st.dataframe(summary, hide_index=True)
    st.markdown("**Catches per attack type**")
    st.dataframe(by_type, hide_index=True)
    st.caption("The hash chain catches every change to approved records, including legitimate ones. "
               "The combined score separates benign corrections from attacks and adds rules and ML "
               "for new transactions the chain cannot see.")
