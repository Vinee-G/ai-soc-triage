"""Short explanations. Template first (free, instant). Optional local LLM (Ollama, free)."""
import json
import urllib.request
from .config import OLLAMA_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT

ACTIONS = {
    "brute": "Block the source IP at the firewall, enforce MFA/lockout, and review auth logs.",
    "success": "Treat the account as compromised: reset its password, kill active sessions, and check what it did.",
    "fim": "Compare the file against a known-good copy and find out who changed it and why.",
    "malware": "Isolate the host from the network and run a full malware scan.",
    "newuser": "Verify the new account was approved; disable it if not.",
    "web": "Check web logs for the attacker's IP, block it, and patch/validate the vulnerable input.",
    "default": "Review the alert details and confirm whether the activity is expected.",
}


def _action(row):
    if row["ip_fail_then_success"]:
        return ACTIONS["success"]
    if row["is_malware"]:
        return ACTIONS["malware"]
    if row["sensitive_file"] or row["is_fim"]:
        return ACTIONS["fim"]
    if row["is_new_user"]:
        return ACTIONS["newuser"]
    if row["is_web_attack"]:
        return ACTIONS["web"]
    if row["ip_fail_count"] >= 5:
        return ACTIONS["brute"]
    return ACTIONS["default"]


def template_explanation(row):
    why = "; ".join(row["reasons"]) if row["reasons"] else "low-risk routine event"
    mitre = f" (MITRE: {row['mitre_tactic']} {row['mitre_id']})" if row.get("mitre_tactic") else ""
    rep = f" (repeated {int(row['repeat_count'])}x)" if row.get("repeat_count", 1) > 1 else ""
    return (f"[{row['severity']} - {row['final_score']}] {row['description']}{rep} on {row['agent']}{mitre}. "
            f"Why: {why}. Next step: {_action(row)}")


def llm_explanation(row):
    """Ask a local Ollama model to rewrite the facts in 2 plain sentences. Falls back to the template."""
    facts = template_explanation(row)
    prompt = ("You are a SOC analyst assistant. Using ONLY the facts below, write 2 short plain-English "
              "sentences: what happened and what to do. Do not invent details.\n\nFACTS: " + facts)
    body = json.dumps({"model": OLLAMA_MODEL, "prompt": prompt, "stream": False}).encode()
    try:
        req = urllib.request.Request(OLLAMA_URL, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=OLLAMA_TIMEOUT) as r:
            text = json.loads(r.read())["response"].strip()
        return text or facts
    except Exception:
        return facts


def add_explanations(df, use_llm=False, llm_top_n=5):
    """Cost control: only the top-N alerts go to the LLM; everything else uses the free template."""
    df = df.copy()
    df["explanation"] = df.apply(template_explanation, axis=1)
    if use_llm:
        for i in df.head(llm_top_n).index:
            df.at[i, "explanation"] = llm_explanation(df.loc[i])
    return df
