import pandas as pd
from .features import load_alerts, build_features
from .scorer import score_alerts, load_model
from .explain import add_explanations


def group_incidents(df):
    """Collapse repeated alerts (same agent + rule + source IP) into ONE incident.
    Keeps the highest-scoring alert and records how many times it repeated.
    This stops a 25-alert brute-force burst from burying everything else."""
    df = df.copy()
    df["_key"] = df["agent"] + "|" + df["rule_id"] + "|" + df["srcip"]
    # rows without a source IP (e.g. file changes) are kept separate per alert
    no_ip = df["srcip"] == ""
    df.loc[no_ip, "_key"] = df.loc[no_ip, "_key"] + "|" + df.loc[no_ip].index.astype(str)
    counts = df.groupby("_key")["final_score"].transform("size")
    first_seen = df.groupby("_key")["timestamp"].transform("min")
    df["repeat_count"] = counts
    df["timestamp"] = first_seen
    out = df.sort_values("final_score", ascending=False).drop_duplicates("_key").drop(columns="_key")
    return out.reset_index(drop=True)


def run(lines, use_llm=False, llm_top_n=5, group=True):
    """lines: iterable of Wazuh alert JSON lines -> ranked DataFrame with explanations."""
    df = build_features(load_alerts(lines))
    if df.empty:
        return df
    ranked = score_alerts(df, load_model())
    if group:
        ranked = group_incidents(ranked)
    else:
        ranked["repeat_count"] = 1
    return add_explanations(ranked, use_llm=use_llm, llm_top_n=llm_top_n)
