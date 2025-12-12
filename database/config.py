import json
from pathlib import Path

CONFIG_FILE = Path.home() / ".local_password_manager" / "config.json"
CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)

def save_config(vault_path: str):
    config = {"vault_path": vault_path}
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4)

def load_config() -> str | None:
    if not CONFIG_FILE.exists():
        return None
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        config = json.load(f)
    return config.get("vault_path")
