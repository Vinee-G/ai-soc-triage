# AI SOC Alert Triage Tool

Reads SIEM alerts (Wazuh format), **ranks them by severity**, groups repeated alerts, and writes a short **plain-English explanation + next step** for each one.

**Cost: ₹0.** Python, open-source Wazuh, optional free local LLM (Ollama). No paid API needed.

## How it works

```
Wazuh alerts.json
      |
      v
 features.py   -> turns each alert into numbers (rule level, external IP, off-hours,
                  sensitive file, failed-logins-then-success from same IP, asset importance...)
      |
      v
 scorer.py     -> Rule score (transparent, with reasons)  +  ML score (Random Forest)
                  final score = 50% rules + 50% ML  ->  Low / Medium / High / Critical
      |
      v
 pipeline.py   -> groups repeated alerts into one incident (25 brute-force alerts = 1 line)
      |
      v
 explain.py    -> template explanation (free, instant)
                  + optional local LLM (Ollama) for the top N alerts only
      |
      v
 app.py (Streamlit dashboard)   or   run_triage.py (command line)
```

Why rules **and** ML? Rules are explainable ("why is this critical?") and ML catches combinations that rules miss. Using both is a good point to explain in interviews.

---

## Step-by-step guide

### Step 1 - Set up Python (10 min)
1. Install Python 3.10+ and VS Code.
2. In this folder:
```bash
python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate       # Linux / Mac
pip install -r requirements.txt
```

### Step 2 - Create demo data (1 min)
```bash
python generate_sample_alerts.py
```
This makes Wazuh-format fake alerts: noise, SQL injection, brute force, malware, and one full compromise story (brute force -> login success -> new user -> /etc/passwd changed).
`data/train_alerts.jsonl` has labels for training. `data/sample_alerts.jsonl` has no labels, for the demo.

### Step 3 - Train the model (1 min)
```bash
python train_model.py
```
You will see precision/recall, a confusion matrix, and the most important features. Take a screenshot for your report.

### Step 4 - Run the triage
```bash
python run_triage.py --top 10
```
Result is printed and saved to `output/triaged.csv`.

### Step 5 - Open the dashboard
```bash
streamlit run app.py
```
Choose "Sample data" first. You will see severity counts, the top alerts with explanations, top attacker IPs, and a CSV download.

### Step 6 - (Optional, free) Add the local LLM
1. Install Ollama from ollama.com.
2. `ollama pull llama3.2:1b` (small model, runs on a normal laptop).
3. In the dashboard tick **Use local LLM**, or run `python run_triage.py --llm`.

Only the top-N alerts go to the LLM; the rest use the free template. This is the cost-control design. If Ollama is not running, the tool silently falls back to the template.

### Step 7 - Connect REAL Wazuh alerts (this is what makes it resume-worthy)
Do this on your own isolated lab only.

1. **Lab (all free, VirtualBox):**
   - VM 1: Ubuntu Server running the Wazuh all-in-one install (about 8 GB RAM recommended). Get the current install command from the Wazuh quickstart at documentation.wazuh.com, since versions change.
   - VM 2: Ubuntu with the Wazuh agent installed (your "victim").
   - VM 3: Kali Linux (your "attacker").
   - Put all three on a host-only or internal network.
2. **Generate real alerts** from Kali against your own victim VM only, for example:
   - failed SSH logins: `hydra -l testuser -P small_wordlist.txt ssh://<victim-ip>`
   - a port scan: `nmap -sS <victim-ip>`
   - file integrity: edit a monitored file on the victim.
3. **Get the alerts.** On the Wazuh manager the file is `/var/ossec/logs/alerts/alerts.json`. Copy it to your PC:
   ```bash
   scp user@wazuh-ip:/var/ossec/logs/alerts/alerts.json data/real_alerts.json
   ```
   (Needs permission to read the file; use sudo to copy it to your home folder first.)
4. **Triage it:**
   ```bash
   python run_triage.py --input data/real_alerts.json
   ```
   or in the dashboard choose "Upload alerts.json".
5. Edit `triage/config.py`: put your real agent names in `CRITICALITY`.

If your laptop cannot run 3 VMs, skip Wazuh at first and finish Steps 1-6; then run only the Wazuh manager + 1 agent.

**Splunk instead?** Export alerts as JSON and map the fields (rule level, description, source IP, user, timestamp) inside `_parse_alert()` in `triage/features.py`. Everything else stays the same. Wazuh is easier and fully free, so use it as the main one.

### Step 8 - Improve it (pick 1 or 2 for extra marks)
- Label 100-200 of YOUR real alerts by hand (Low/Medium/High/Critical) and retrain: this is the most valuable improvement.
- Compare Random Forest vs XGBoost vs Logistic Regression in a table.
- Add a feedback button: analyst marks "wrong severity" and the label is saved for retraining.
- Send Critical alerts to Telegram or email.
- Add more features (time between alerts, threat-intel IP lists such as the free AbuseIPDB tier).

### Step 9 - Write the report / GitHub README
Include: architecture diagram, dataset description, features, results table, dashboard screenshots, limitations, future work.

---

## Be honest about the results (important)
The training data is **synthetic**, labeled by rules we wrote. So the high accuracy (about 98%) only proves the pipeline works. It does **not** prove it will be that accurate on real networks. In your report, say this clearly, then show results on your real lab alerts (Step 7) and your hand-labeled set (Step 8). Interviewers respect this much more than an unexplained "99% accuracy".

Also noted: the Critical class has lower precision (the model sometimes marks a High alert as Critical), which is the safer direction for a SOC. Mention it as a trade-off.

## Resume bullets (adjust to your real numbers)
- Built an AI-assisted SOC alert triage tool that ranks Wazuh SIEM alerts by severity using a hybrid rule-based and Random Forest scoring model, with MITRE ATT&CK context.
- Reduced alert noise by grouping repeated alerts into incidents and correlating failed-then-successful logins per source IP.
- Generated analyst-ready explanations and recommended actions using templates plus an optional local LLM (Ollama), keeping running cost at zero.
- Deployed a Streamlit dashboard and tested it against alerts generated in a VirtualBox lab (Wazuh + Kali).

## Troubleshooting
| Problem | Fix |
|---|---|
| `ModuleNotFoundError` | Activate the venv and run `pip install -r requirements.txt` |
| Dashboard says "rules only" | Run `python train_model.py` |
| LLM is slow | Lower "Alerts sent to LLM" or use the template only |
| Wazuh VM too slow | Give it 8 GB RAM / 4 CPUs, or use fewer VMs |
| No alerts found in file | Each line must be one JSON object (Wazuh `alerts.json`, not `alerts.log`) |

## Legal reminder
Only attack and scan machines that you own or have written permission to test.

## Folder structure
```
app.py                    dashboard
run_triage.py             command-line tool
train_model.py            trains the ML model
generate_sample_alerts.py demo + training data
triage/config.py          your lab settings
triage/features.py        alert -> numbers
triage/scorer.py          rule score + ML score
triage/explain.py         explanations (template + optional LLM)
triage/pipeline.py        glue + incident grouping
```
