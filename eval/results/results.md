# LedgerSentinel evaluation

56 planted attacks among 10,028 records.

| Detector | Flagged | True attacks caught | Precision | Recall |
|---|---|---|---|---|
| Hash chain | 69 | 28 | 0.406 | 0.5 |
| Rules only | 500 | 36 | 0.072 | 0.643 |
| Isolation Forest (top 1%) | 101 | 7 | 0.069 | 0.125 |
| Combined risk score | 148 | 45 | 0.304 | 0.804 |

## Catches per attack type

| Attack type | Planted | Hash chain | Rules only | Isolation Forest (top 1%) | Combined risk score |
|---|---|---|---|---|---|
| amount_inflation | 12 | 12 | 2 | 0 | 12 |
| duplicate_payment | 10 | 0 | 9 | 1 | 4 |
| fake_vendor | 8 | 0 | 8 | 6 | 8 |
| inflated_invoice | 10 | 0 | 5 | 0 | 5 |
| payee_account_change | 12 | 12 | 12 | 0 | 12 |
| record_deleted | 4 | 4 | 0 | 0 | 4 |
