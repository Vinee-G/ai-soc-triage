"""Command-line triage.
  python run_triage.py                                   (uses data/sample_alerts.jsonl)
  python run_triage.py --input /var/ossec/logs/alerts/alerts.json --top 15 --llm
"""
import argparse
from triage.pipeline import run

p = argparse.ArgumentParser()
p.add_argument("--input", default="data/sample_alerts.jsonl")
p.add_argument("--top", type=int, default=10, help="how many alerts to print")
p.add_argument("--llm", action="store_true", help="use local Ollama for the top alerts")
p.add_argument("--out", default="output/triaged.csv")
a = p.parse_args()

with open(a.input) as f:
    df = run(f, use_llm=a.llm, llm_top_n=a.top)

if df.empty:
    raise SystemExit("No alerts found in the input file.")

print(f"\n{len(df)} alerts triaged.  Severity counts:\n{df['severity'].value_counts().to_string()}\n")
for i, r in df.head(a.top).iterrows():
    print(f"#{i + 1}  {r['explanation']}\n")

df.drop(columns=["reasons"]).to_csv(a.out, index=False)
print(f"Full ranked list saved -> {a.out}")
