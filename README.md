# LedgerSentinel AI

**Every transaction tells a story. LedgerSentinel finds the ones that don't add up.**

LedgerSentinel is a financial integrity monitor for small and mid-sized businesses. It flags suspicious payments, and it also checks whether someone quietly changed the financial records after they were approved.

Built for Hack Knight 2026, AI for Finance track.

## The problem

A clerk with access to the accounting system changes the bank account on an approved $500 supplier payment to an account they control. The report still looks normal, and nobody notices until an audit. Small businesses rarely have a security team watching for this, and traditional anomaly detection looks at amounts, not at the history of the record itself.

## How it works

| Layer | What it catches | How |
|---|---|---|
| **Hash chain** | Any edit or deletion of an approved record | SHA-256 hash per record, chained so one change breaks every link after it |
| **S3 Object Lock** | An insider rewriting the proof itself | The baseline and its head hash are stored write-once in S3 (governance mode, KMS encrypted) |
| **Rules** | Known fraud patterns in new transactions | Shared bank accounts, duplicate payments, payments far above a vendor's history, round amounts with no contract, off-hours approvals |
| **Isolation Forest** | Unusual transactions nobody wrote a rule for | Unsupervised scikit-learn model over amount, vendor history, timing and contract features |
| **Risk score** | Ranking what a human should look at first | Combines all of the above plus edit log context (who edited, when, and whether the edit was logged at all) |
| **Claude on Bedrock** | Turning findings into plain English | Writes the alert summary and case report. It explains; it never decides |

The hash chain proves *that* an approved record changed. The rules and the model handle brand new fake transactions, which were never in the baseline. The risk score separates routine corrections from attacks.

```
Chicago payments ──> ledger_clean.csv ──> hash chain ──> baseline + head hash ──> S3 Object Lock
                                                                                       │
live ledger + edit log ──> verify against locked baseline ─┐                           │
                       └─> features ──> rules + Isolation Forest ──> risk score ──> alerts ──> Claude (Bedrock) ──> case report
```

## Repository layout

| Path | What it does |
|---|---|
| `ingest/fetch_chicago.py` | Downloads City of Chicago vendor payments and builds `data/ledger_clean.csv` with synthetic users, bank accounts and approval times |
| `common.py` | Shared schema, file paths and ledger I/O |
| `integrity/hash_chain.py` | Builds the locked baseline (row hashes, chain hashes, head) and verifies the live ledger against it |
| `integrity/injector.py` | Plays the insider attacker: plants 56 labeled attacks plus benign noise to create ground truth |
| `integrity/sanitize.py` | Prompt injection detection and sanitizing for ledger text before it reaches the LLM |
| `detect/features.py` | Per transaction features compared with trusted vendor history |
| `detect/rules.py` | Detection rules with point weights, written like SIEM signatures |
| `detect/model.py` | Isolation Forest anomaly scoring |
| `detect/score.py` | Combines integrity, rules, model and edit log context into one risk score |
| `detect/explain.py` | Bedrock (Claude) explanations with a template fallback, plus case report generation |
| `eval/evaluate.py` | Precision and recall of each detector against planted attacks |
| `cloud/anchor.py` | Uploads the baseline to S3 Object Lock, checks the anchored head, demos that deletion is refused |
| `cloud/iam_policy_app.json` | Least privilege policy for the app role |
| `app/dashboard.py` | Streamlit dashboard: alerts, integrity status, live tamper demo, evaluation |
| `pipeline.py` | Runs baseline, injection, scoring and evaluation in one command |

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python ingest/fetch_chicago.py      # once, by one teammate; commit data/ledger_clean.csv
python pipeline.py                  # baseline, attacks, scoring, evaluation
streamlit run app/dashboard.py
```

## AWS setup

```bash
# Bucket with Object Lock (must be enabled at creation)
aws s3api create-bucket --bucket <bucket> --object-lock-enabled-for-bucket --region us-east-1

# Lock the baseline for 1 day, then prove it cannot be deleted
python -m cloud.anchor upload --bucket <bucket>
python -m cloud.anchor check --bucket <bucket>
python -m cloud.anchor try-delete --bucket <bucket>

# Dashboard verifies against the S3 copy and uses Claude for explanations
export LS_BUCKET=<bucket>
export LS_BEDROCK_MODEL=<inference profile id, e.g. us.anthropic.claude-haiku-4-5-...>
streamlit run app/dashboard.py
```

Credentials come from `aws login` (short-lived, auto-rotated). The project has no long-lived access keys.

## Evaluation

The injector plants six attack types into the ledger:

| Attack | Kind | Example |
|---|---|---|
| Payee account change | Edit | Approved payment redirected to a mule account |
| Amount inflation | Edit | Approved amount raised 1.5x to 4x |
| Record deleted | Edit | Approved record removed |
| Duplicate payment | New row | Same invoice paid again days later |
| Fake vendor | New row | Shell company paid a round amount into a mule account, two with prompt injection in the name |
| Inflated invoice | New row | Real vendor, real account, 4x to 10x its normal amount |

It also adds benign noise the detectors must not over-react to: manager reclassifications, small amount corrections, legitimate bank changes and late evening approvals. 30% of edit attacks bypass the application log entirely.

Run `python -m eval.evaluate`. Results are written to `eval/results/results.md`.

Results on 10,024 real City of Chicago payments with 56 planted attacks:

| Detector | Flagged | Attacks caught | Precision | Recall |
|---|---|---|---|---|
| Hash chain | 69 | 28 | 0.41 | 0.50 |
| Rules only | 500 | 36 | 0.07 | 0.64 |
| Isolation Forest (top 1%) | 101 | 7 | 0.07 | 0.13 |
| **Combined risk score** | **148** | **45** | **0.30** | **0.80** |

| Attack type | Planted | Hash chain | Rules | Isolation Forest | Combined |
|---|---|---|---|---|---|
| Payee account change | 12 | 12 | 12 | 0 | 12 |
| Amount inflation | 12 | 12 | 2 | 0 | 12 |
| Record deleted | 4 | 4 | 0 | 0 | 4 |
| Fake vendor | 8 | 0 | 8 | 6 | 8 |
| Duplicate payment | 10 | 0 | 9 | 1 | 4 |
| Inflated invoice | 10 | 0 | 5 | 0 | 5 |

**What this shows**

- The hash chain catches **every** change to an approved record (28 of 28), including the 30% made outside the application log. Its "false positives" are the 41 legitimate corrections, which it is right to surface.
- The combined score keeps all 28 tampering cases and all 8 fake vendors while dropping the routine manager corrections, and flags 1.5% of transactions for review to catch 80% of planted fraud.
- No single layer is enough: rules alone flag 500 rows, and Isolation Forest alone catches 13%. Together they reach 80% recall at 6x the precision of rules alone.
- Weak spots, honestly: duplicate payments and inflated invoices. City payments legitimately repeat amounts and vary widely in size, so these attacks blend in. Per-vendor invoice numbers would fix duplicates in a real deployment.

## Security design

- **Threat model:** an insider clerk with write access to the ledger who can edit, delete or add records, and may bypass the application log.
- **Tamper evidence:** the hash chain detects any change to approved records. The proof lives in S3 Object Lock, outside the insider's reach.
- **Prompt injection:** ledger text is untrusted. It is scanned for instructions aimed at the AI (which raises the risk score), stripped of markup, length limited and fenced in `<record>` tags that the model is told never to obey.
- **Least privilege:** the app role can read and append the baseline and invoke one Claude model. An explicit deny blocks bypassing or weakening Object Lock.
- **No static keys:** humans use IAM users with MFA and `aws login`; root is locked away.

## Data

[City of Chicago Payments](https://data.cityofchicago.org/d/s4vu-giwb), the city's public vendor payment records. We use the 10,000 most recent individual payments. The public data has no users, bank accounts or approval times, so those columns are synthetic and generated with a fixed seed.

## Limitations and next steps

- Synthetic users and accounts mean the evaluation measures the method, not real world fraud rates.
- Next: Lambda for scheduled verification, DynamoDB for alerts, QuickBooks and Xero connectors, per-user behavior baselines, and alert feedback to tune weights.
- Anomalies are leads for human review, not proof of fraud.
