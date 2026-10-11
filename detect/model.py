"""Isolation Forest anomaly scoring.

No fraud labels are needed. The forest keeps splitting the data at random;
unusual rows get isolated in fewer splits and receive a higher score. A high
score means "look at this", never "this is fraud".
"""
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from detect.features import MODEL_FEATURES


def anomaly_scores(features: pd.DataFrame, seed: int = 42) -> pd.DataFrame:
    X = StandardScaler().fit_transform(features[MODEL_FEATURES].astype(float))
    model = IsolationForest(n_estimators=300, contamination="auto", random_state=seed)
    model.fit(X)
    raw = -model.score_samples(X)               # higher = more unusual
    out = pd.DataFrame(index=features.index)
    out["if_score"] = raw
    out["if_pct"] = pd.Series(raw, index=features.index).rank(pct=True)
    # Only the most unusual 5% earn points, scaled 0 to 30
    out["if_points"] = ((out["if_pct"] - 0.95) / 0.05).clip(0, 1) * 30
    return out
