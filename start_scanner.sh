#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER="$SCRIPT_DIR/codex_quota_401_scanner.py"
CONFIG_FILE="${2:-$SCRIPT_DIR/scanner_config.json}"
AUTH_DIR="${1:-}"

if [[ -z "$AUTH_DIR" ]]; then
  echo "Usage: $0 <auth_dir> [config_file] [extra scanner args...]"
  exit 1
fi

if [[ $# -ge 2 ]]; then
  shift 2
else
  shift 1
fi

EXTRA_ARGS=("$@")

python3 - "$CONFIG_FILE" "$AUTH_DIR" <<'PY'
import json
import pathlib
import sys

config_path = pathlib.Path(sys.argv[1]).expanduser()
auth_dir = str(pathlib.Path(sys.argv[2]).expanduser().resolve())

if config_path.exists():
    data = json.loads(config_path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise SystemExit(f"config root must be a JSON object: {config_path}")
else:
    data = {
        "base_url": "https://chatgpt.com/backend-api/codex",
        "quota_path": "/responses",
        "model": "gpt-5",
        "timeout": 20,
        "refresh_before_check": False,
        "refresh_url": "https://auth.openai.com/oauth/token",
        "output_json": False,
        "delete_401": False,
        "yes": False,
        "proxy": {
            "http": "",
            "https": "",
            "no_proxy": "localhost,127.0.0.1",
        },
    }

data["auth_dir"] = auth_dir
config_path.parent.mkdir(parents=True, exist_ok=True)
config_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(f"Config updated: {config_path}")
PY

if [[ ${#EXTRA_ARGS[@]} -gt 0 ]]; then
  exec python3 "$SCANNER" --config "$CONFIG_FILE" "${EXTRA_ARGS[@]}"
fi

exec python3 "$SCANNER" --config "$CONFIG_FILE"
