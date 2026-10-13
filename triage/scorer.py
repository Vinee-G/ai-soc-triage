"""Two scorers: transparent rules + a small ML model. Final score blends both."""
import os
import joblib
import numpy as np
from .config import BANDS
from .features import FEATURE_COLUMNS

MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "model", "model.joblib")
CLASS_SCORES = np.array([10, 40, 70, 95])  # Low, Medium, High, Critical -> 0-100


def rule_score(row):
    """Returns (score 0-100, list of human-readable reasons)."""
    s, why = row["rule_level"] * 4, []
    if row["rule_level"] >= 10:
        why.append(f"high SIEM rule level ({row['rule_level']})")
    if row["ip_fail_then_success"]:
        s += 35
        why.append(f"successful login after {int(row['ip_fail_count'])} failed attempts from the same IP")
    elif row["ip_fail_count"] >= 5:
        s += min(row["ip_fail_count"], 20)
        why.append(f"{int(row['ip_fail_count'])} failed logins from one IP (brute force)")
    if row["sensitive_file"]:
        s += 20
        why.append("a sensitive system file was changed")
    if row["is_malware"]:
        s += 20
        why.append("malware/rootkit indicator")
    if row["is_new_user"]:
        s += 10
        why.append("new user account created")
    if row["is_web_attack"]:
        s += 10
        why.append("web attack pattern")
    if row["off_hours"]:
        s += 5
        why.append("happened outside working hours")
    if row["external_ip"]:
        s += 5
        why.append("source is an external (public) IP")
    if row["privileged_user"]:
        s += 5
        why.append("privileged account involved")
    if row["criticality"] >= 2:
        s += row["criticality"] * 3
        why.append(f"important asset ({row['agent']})")
    return min(s, 100), why


def load_model():
    return joblib.load(MODEL_PATH) if os.path.exists(MODEL_PATH) else None


def band(score):
    for limit, name in BANDS:
        if score < limit:
            return name
    return "Critical"


def score_alerts(df, model=None):
    """Adds rule_score, ml_score, final_score, severity, reasons to the DataFrame."""
    out = df.copy()
    rs = out.apply(rule_score, axis=1)
    out["rule_score"] = [r[0] for r in rs]
    out["reasons"] = [r[1] for r in rs]
    if model is not None:
        proba = model.predict_proba(out[FEATURE_COLUMNS])
        full = np.zeros((len(out), 4))
        full[:, model.classes_.astype(int)] = proba
        out["ml_score"] = (full * CLASS_SCORES).sum(axis=1).round(1)
        out["final_score"] = (0.5 * out["rule_score"] + 0.5 * out["ml_score"]).round(1)
    else:  # still works before you train a model
        out["ml_score"] = np.nan
        out["final_score"] = out["rule_score"].astype(float)
    out["severity"] = out["final_score"].apply(band)
    return out.sort_values("final_score", ascending=False).reset_index(drop=True)
