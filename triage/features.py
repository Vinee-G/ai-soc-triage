"""Turn raw Wazuh alerts (JSON) into numbers a model can understand."""
import ipaddress
import json
import pandas as pd
from .config import CRITICALITY, DEFAULT_CRITICALITY, SENSITIVE_FILES, PRIVILEGED_USERS

FEATURE_COLUMNS = [
    "rule_level", "firedtimes", "is_auth_fail", "is_auth_success", "is_sudo_priv",
    "is_fim", "is_web_attack", "is_malware", "is_new_user", "has_mitre",
    "external_ip", "off_hours", "privileged_user", "criticality",
    "ip_total", "ip_fail_count", "ip_fail_then_success", "sensitive_file",
]


def load_alerts(lines):
    """Read Wazuh alerts.json lines (one JSON object per line). Bad lines are skipped."""
    rows = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def _is_external(ip):
    try:
        return not ipaddress.ip_address(ip).is_private
    except (ValueError, TypeError):
        return False


def _parse_alert(a):
    rule = a.get("rule", {}) or {}
    groups = [str(g).lower() for g in rule.get("groups", [])]
    desc = str(rule.get("description", "")).lower()
    data = a.get("data", {}) or {}
    agent = (a.get("agent", {}) or {}).get("name", "unknown")
    srcip = data.get("srcip", "") or ""
    user = str(data.get("srcuser") or data.get("dstuser") or "").lower()
    path = str((a.get("syscheck", {}) or {}).get("path", "")).lower()
    gtxt = " ".join(groups)
    ts = pd.to_datetime(a.get("timestamp"), errors="coerce", utc=True)
    hour = ts.hour if pd.notna(ts) else 12
    mitre = rule.get("mitre", {}) or {}
    tactics = mitre.get("tactic", []) if isinstance(mitre.get("tactic", []), list) else []
    ids = mitre.get("id", []) if isinstance(mitre.get("id", []), list) else []

    return {
        "timestamp": ts,
        "agent": agent,
        "srcip": srcip,
        "user": user,
        "rule_id": str(rule.get("id", "")),
        "description": rule.get("description", ""),
        "mitre_tactic": ", ".join(tactics),
        "mitre_id": ", ".join(ids),
        "rule_level": int(rule.get("level", 0)),
        "firedtimes": int(rule.get("firedtimes", 1)),
        "is_auth_fail": int("authentication_fail" in gtxt or "brute force" in desc or "login failed" in desc),
        "is_auth_success": int("authentication_success" in gtxt or "authentication success" in desc),
        "is_sudo_priv": int("sudo" in gtxt or "sudo" in desc or "privilege" in desc),
        "is_fim": int("syscheck" in gtxt),
        "is_web_attack": int(any(k in gtxt or k in desc for k in ("web_attack", "sql_injection", "sql injection", "xss", "attack"))
                             and "brute" not in desc),
        "is_malware": int(any(k in gtxt or k in desc for k in ("malware", "virus", "rootkit", "trojan"))),
        "is_new_user": int("adduser" in gtxt or "new user" in desc),
        "has_mitre": int(bool(ids)),
        "external_ip": int(_is_external(srcip)),
        "off_hours": int(hour < 6 or hour >= 22),
        "privileged_user": int(user in PRIVILEGED_USERS),
        "criticality": CRITICALITY.get(agent, DEFAULT_CRITICALITY),
        "sensitive_file": int(any(s in path for s in SENSITIVE_FILES)),
        "label": a.get("label"),  # only present in synthetic training data
    }


def build_features(raw_alerts):
    """List of alert dicts -> DataFrame with all feature columns (+ correlation features)."""
    df = pd.DataFrame([_parse_alert(a) for a in raw_alerts])
    if df.empty:
        return df
    df["ip_total"] = 0
    df["ip_fail_count"] = 0
    df["ip_fail_then_success"] = 0
    has_ip = df["srcip"] != ""
    if has_ip.any():
        sub = df[has_ip]
        g = sub.groupby("srcip")
        total = g["rule_id"].transform("count")
        fails = g["is_auth_fail"].transform("sum")
        any_success = g["is_auth_success"].transform("max")
        df.loc[has_ip, "ip_total"] = total
        df.loc[has_ip, "ip_fail_count"] = fails
        # a success from an IP that already failed many times = classic brute-force win
        df.loc[has_ip, "ip_fail_then_success"] = (
            (any_success == 1) & (fails >= 5) & (sub["is_auth_success"] == 1)
        ).astype(int)
    return df
