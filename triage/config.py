"""Settings you can edit to match YOUR lab."""

# How important is each machine? 1 = normal laptop, 2 = server, 3 = crown jewels.
# Use the agent names you see in Wazuh.
CRITICALITY = {
    "db-server": 3,
    "dc-server": 3,
    "web-server": 2,
    "app-server": 2,
    "hr-laptop": 1,
    "dev-laptop": 1,
}
DEFAULT_CRITICALITY = 1

# Files that should never change unexpectedly
SENSITIVE_FILES = ("/etc/passwd", "/etc/shadow", "/etc/sudoers", "authorized_keys")

PRIVILEGED_USERS = {"root", "admin", "administrator"}

# Severity bands on the final 0-100 score
BANDS = [(25, "Low"), (50, "Medium"), (75, "High"), (101, "Critical")]

# Optional free local LLM (Ollama). Small model = runs on a normal laptop.
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2:1b"
OLLAMA_TIMEOUT = 60
