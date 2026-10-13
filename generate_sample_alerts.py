"""Creates fake Wazuh-style alerts so you can build and demo the project WITHOUT running Wazuh.

  python generate_sample_alerts.py            -> data/train_alerts.jsonl (with labels) + data/sample_alerts.jsonl (no labels)

Label meaning: 0 = Low, 1 = Medium, 2 = High, 3 = Critical.
NOTE: these labels come from rules written by us. For the final report, also test on REAL alerts from your Wazuh lab.
"""
import json
import random
from datetime import datetime, timedelta, timezone

AGENTS = ["web-server", "db-server", "dc-server", "app-server", "hr-laptop", "dev-laptop"]
INTERNAL = ["192.168.1.%d", "10.0.0.%d"]


def ext_ip(rng):
    return f"{rng.choice([45, 91, 103, 185, 203])}.{rng.randint(1, 250)}.{rng.randint(1, 250)}.{rng.randint(1, 250)}"


def int_ip(rng):
    return rng.choice(INTERNAL) % rng.randint(2, 250)


def alert(ts, agent, level, rid, desc, groups, label, srcip="", user="", mitre=None, path=None, fired=1):
    a = {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "rule": {"level": level, "description": desc, "id": rid, "groups": groups, "firedtimes": fired},
        "agent": {"id": "00" + str(AGENTS.index(agent) + 1), "name": agent},
        "data": {},
        "label": label,
    }
    if srcip:
        a["data"]["srcip"] = srcip
    if user:
        a["data"]["srcuser"] = user
    if mitre:
        a["rule"]["mitre"] = {"id": [mitre[0]], "tactic": [mitre[1]]}
    if path:
        a["syscheck"] = {"path": path}
    return a


def work_time(rng, base):
    return base + timedelta(hours=rng.randint(9, 17), minutes=rng.randint(0, 59))


def night_time(rng, base):
    return base + timedelta(hours=rng.choice([0, 1, 2, 3, 4, 23]), minutes=rng.randint(0, 59))


def scenario(rng, base, kind):
    out = []
    agent = rng.choice(AGENTS)
    if kind == "noise_fail":
        out.append(alert(work_time(rng, base), agent, 5, "5716", "sshd: authentication failed.",
                         ["syslog", "sshd", "authentication_failed"], 0, int_ip(rng), rng.choice(["alice", "bob", "dev"]),
                         ("T1110", "Credential Access")))
    elif kind == "noise_sudo":
        out.append(alert(work_time(rng, base), agent, 3, "5402", "Successful sudo to ROOT executed.",
                         ["syslog", "sudo"], 0, "", "dev"))
    elif kind == "noise_login":
        out.append(alert(work_time(rng, base), agent, 3, "5501", "PAM: Login session opened.",
                         ["syslog", "pam", "authentication_success"], 0, int_ip(rng), rng.choice(["alice", "bob"])))
    elif kind == "fim_tmp":
        out.append(alert(work_time(rng, base), agent, 7, "550", "Integrity checksum changed.",
                         ["ossec", "syscheck"], 1, "", "", None, "/var/www/html/uploads/report.txt"))
    elif kind == "rootcheck_warn":
        out.append(alert(work_time(rng, base), agent, 7, "510", "Host-based anomaly detection event (rootcheck).",
                         ["ossec", "rootcheck"], 1))
    elif kind == "web_scan":
        ip = ext_ip(rng)
        for _ in range(rng.randint(1, 3)):
            out.append(alert(work_time(rng, base), "web-server", 6, "31101", "Web server 400 error code.",
                             ["web", "accesslog", "attack"], 1, ip, "", ("T1595", "Reconnaissance")))
    elif kind == "sqli":
        ip = ext_ip(rng)
        for i in range(rng.randint(2, 6)):
            out.append(alert(rng.choice([work_time, night_time])(rng, base), "web-server", 7, "31103",
                             "SQL injection attempt.", ["web", "accesslog", "attack", "sql_injection"], 2, ip, "",
                             ("T1190", "Initial Access"), fired=i + 1))
    elif kind == "brute_only":
        ip = ext_ip(rng)
        t = night_time(rng, base)
        for i in range(rng.randint(8, 30)):
            out.append(alert(t + timedelta(seconds=i * 3), rng.choice(["web-server", "app-server", "db-server"]), 10,
                             "5712", "sshd: brute force trying to get access to the system.",
                             ["syslog", "sshd", "authentication_failures"], 2, ip, "root",
                             ("T1110", "Credential Access"), fired=i + 1))
    elif kind == "brute_success":
        ip = ext_ip(rng)
        t = night_time(rng, base)
        victim = rng.choice(["db-server", "dc-server", "web-server"])
        n = rng.randint(8, 25)
        for i in range(n):
            out.append(alert(t + timedelta(seconds=i * 3), victim, 10, "5712",
                             "sshd: brute force trying to get access to the system.",
                             ["syslog", "sshd", "authentication_failures"], 2, ip, "admin",
                             ("T1110", "Credential Access"), fired=i + 1))
        end = t + timedelta(seconds=n * 3 + 20)
        out.append(alert(end, victim, 3, "5715", "sshd: authentication success.",
                         ["syslog", "sshd", "authentication_success"], 3, ip, "admin", ("T1078", "Initial Access")))
        if rng.random() < 0.6:
            out.append(alert(end + timedelta(minutes=2), victim, 8, "5902", "New user added to the system.",
                             ["syslog", "adduser", "account_changed"], 3, "", "backdoor", ("T1136", "Persistence")))
        if rng.random() < 0.6:
            out.append(alert(end + timedelta(minutes=4), victim, 7, "550", "Integrity checksum changed.",
                             ["ossec", "syscheck"], 3, "", "", None, "/etc/passwd"))
    elif kind == "fim_sensitive":
        out.append(alert(night_time(rng, base), rng.choice(["db-server", "dc-server"]), 7, "550",
                         "Integrity checksum changed.", ["ossec", "syscheck"], 2, "", "", None,
                         rng.choice(["/etc/shadow", "/etc/sudoers", "/root/.ssh/authorized_keys"])))
    elif kind == "malware":
        out.append(alert(rng.choice([work_time, night_time])(rng, base), agent, 12, "100002",
                         "Malware detected: trojan signature matched.", ["malware", "virus"], 3, "", "",
                         ("T1204", "Execution")))
    elif kind == "new_user_ok":
        out.append(alert(work_time(rng, base), agent, 8, "5902", "New user added to the system.",
                         ["syslog", "adduser", "account_changed"], 1, "", "intern", ("T1136", "Persistence")))
    return out


KINDS = {  # kind: weight (noise is common, attacks are rare - like real life)
    "noise_fail": 30, "noise_sudo": 20, "noise_login": 25, "fim_tmp": 8, "rootcheck_warn": 4, "web_scan": 6,
    "sqli": 4, "brute_only": 3, "brute_success": 2, "fim_sensitive": 2, "malware": 2, "new_user_ok": 3,
}


def generate(n_scenarios, seed, keep_labels, inject_chain=False):
    rng = random.Random(seed)
    base = datetime(2026, 10, 12, tzinfo=timezone.utc)
    kinds = rng.choices(list(KINDS), weights=list(KINDS.values()), k=n_scenarios)
    alerts = []
    for k in kinds:
        alerts += scenario(rng, base, k)
    if inject_chain:  # guarantee the demo contains a real compromise story
        alerts += scenario(rng, base, "brute_success")
    alerts.sort(key=lambda a: a["timestamp"])
    if not keep_labels:
        for a in alerts:
            a.pop("label", None)
    return alerts


if __name__ == "__main__":
    for name, n, seed, labels, chain in [("train_alerts", 3000, 42, True, False), ("sample_alerts", 150, 7, False, True)]:
        data = generate(n, seed, labels, chain)
        with open(f"data/{name}.jsonl", "w") as f:
            f.write("\n".join(json.dumps(a) for a in data) + "\n")
        print(f"data/{name}.jsonl -> {len(data)} alerts")
