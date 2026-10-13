"""Dashboard.   streamlit run app.py"""
import io
import pandas as pd
import streamlit as st
from triage.pipeline import run
from triage.scorer import load_model

st.set_page_config(page_title="AI SOC Alert Triage", layout="wide")
st.title("AI SOC Alert Triage")
st.caption("Ranks SIEM (Wazuh) alerts by severity and explains why. Rules + ML + optional local LLM.")

with st.sidebar:
    st.header("Input")
    source = st.radio("Alert source", ["Sample data", "Upload alerts.json", "File path (live Wazuh)"])
    use_llm = st.checkbox("Use local LLM (Ollama) for top alerts", value=False)
    top_n = st.slider("Alerts sent to LLM", 1, 15, 5, disabled=not use_llm)
    min_sev = st.multiselect("Show severities", ["Critical", "High", "Medium", "Low"], default=["Critical", "High", "Medium"])
    st.write("Model loaded:", "yes" if load_model() else "no (rules only - run train_model.py)")

lines = None
if source == "Sample data":
    with open("data/sample_alerts.jsonl") as f:
        lines = f.readlines()
elif source == "Upload alerts.json":
    up = st.file_uploader("Wazuh alerts.json (one JSON per line)", type=["json", "jsonl", "txt"])
    if up:
        lines = io.StringIO(up.getvalue().decode("utf-8", "ignore")).readlines()
else:
    path = st.text_input("Path", "/var/ossec/logs/alerts/alerts.json")
    try:
        with open(path) as f:
            lines = f.readlines()[-5000:]  # last 5000 alerts only: keeps it fast
    except OSError as e:
        st.error(f"Cannot read file: {e}")

if not lines:
    st.info("Choose an alert source to begin.")
    st.stop()

with st.spinner("Triaging..."):
    df = run(lines, use_llm=use_llm, llm_top_n=top_n)

if df.empty:
    st.warning("No valid alerts found.")
    st.stop()

counts = df["severity"].value_counts()
c = st.columns(5)
c[0].metric("Total alerts", len(df))
for col, sev in zip(c[1:], ["Critical", "High", "Medium", "Low"]):
    col.metric(sev, int(counts.get(sev, 0)))

view = df[df["severity"].isin(min_sev)]
left, right = st.columns([2, 1])
with left:
    st.subheader("Top alerts to look at first")
    for _, r in view.head(10).iterrows():
        icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡"}.get(r["severity"], "🟢")
        with st.expander(f"{icon} {r['severity']} ({r['final_score']}) - {r['description']} - {r['agent']}"):
            st.write(r["explanation"])
            st.caption(f"Source IP: {r['srcip'] or '-'} | User: {r['user'] or '-'} | Time: {r['timestamp']}")
with right:
    st.subheader("Severity mix")
    st.bar_chart(counts.reindex(["Critical", "High", "Medium", "Low"]).fillna(0))
    st.subheader("Top source IPs")
    ips = view[view["srcip"] != ""].groupby("srcip")["final_score"].agg(["count", "max"]).sort_values("max", ascending=False).head(8)
    st.dataframe(ips.rename(columns={"count": "alerts", "max": "max score"}))

st.subheader("All ranked alerts")
cols = ["timestamp", "severity", "final_score", "rule_score", "ml_score", "agent", "srcip", "description"]
st.dataframe(view[cols], use_container_width=True)
st.download_button("Download CSV", view.drop(columns=["reasons"]).to_csv(index=False), "triaged_alerts.csv")
