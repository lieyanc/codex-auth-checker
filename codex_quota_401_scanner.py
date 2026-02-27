#!/usr/bin/env python3
"""Scan Codex auth files and report credentials that fail with HTTP 401.

This script ports key parts from CLIProxyAPI's Codex implementation:

- Default Codex base URL from `internal/runtime/executor/codex_executor.go`
- Codex request headers style from `applyCodexHeaders`
- Refresh-token flow from `internal/auth/codex/openai_auth.go`

Usage examples:

  python codex_quota_401_scanner.py --auth-dir ./auths
  python codex_quota_401_scanner.py --config ./scanner_config.json
  python codex_quota_401_scanner.py --auth-dir ~/.cli-proxy-api --refresh-before-check
  python codex_quota_401_scanner.py --auth-dir ./auths --output-json
  python codex_quota_401_scanner.py --auth-dir ./auths --delete-401 --assume-yes
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Iterable
from urllib import error, parse, request


DEFAULT_CODEX_BASE_URL = "https://chatgpt.com/backend-api/codex"
DEFAULT_REFRESH_URL = "https://auth.openai.com/oauth/token"
DEFAULT_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
DEFAULT_VERSION = "0.98.0"
DEFAULT_USER_AGENT = "codex_cli_rs/0.98.0 (python-port)"
DEFAULT_CONFIG_PATH = "scanner_config.json"

# ── terminal progress helpers ─────────────────────────────────────────────────

_USE_COLOR: bool = sys.stderr.isatty()

_C_RED    = "\033[31m" if _USE_COLOR else ""
_C_GREEN  = "\033[32m" if _USE_COLOR else ""
_C_YELLOW = "\033[33m" if _USE_COLOR else ""
_C_CYAN   = "\033[36m" if _USE_COLOR else ""
_C_BOLD   = "\033[1m"  if _USE_COLOR else ""
_C_DIM    = "\033[2m"  if _USE_COLOR else ""
_C_RESET  = "\033[0m"  if _USE_COLOR else ""
_ERASE_LINE = "\033[2K\r" if _USE_COLOR else ""


def _bar(done: int, total: int, width: int = 20) -> str:
    filled = round(width * done / total) if total else 0
    return "█" * filled + "░" * (width - filled)


def _num(idx: int, total: int) -> str:
    w = len(str(total))
    return f"{idx:0{w}d}/{total}"


def _emit(msg: str, *, end: str = "\n") -> None:
    print(msg, end=end, file=sys.stderr, flush=True)


def _progress_header(auth_dir: "Path", total: int) -> None:
    _emit(f"{_C_BOLD}Scanning{_C_RESET} {_C_CYAN}{auth_dir}{_C_RESET}")
    _emit(f"Found {_C_BOLD}{total}{_C_RESET} JSON file(s)")
    _emit("")


def _progress_checking(idx: int, total: int, label: str, retry: int = 0) -> None:
    bar = _bar(idx - 1, total)
    num = _num(idx, total)
    suffix = f" {_C_YELLOW}(retry {retry}){_C_RESET}" if retry > 0 else ""
    if _USE_COLOR:
        _emit(
            f"{_ERASE_LINE}  {_C_DIM}[{num}]{_C_RESET} {_C_CYAN}[{bar}]{_C_RESET}  {label}{suffix} ...",
            end="",
        )
    else:
        retry_note = f" (retry {retry})" if retry > 0 else ""
        _emit(f"  [{num}] {label}{retry_note} ...")


def _progress_result(idx: int, total: int, label: str, tag: str, color: str) -> None:
    bar = _bar(idx, total)
    num = _num(idx, total)
    if _USE_COLOR:
        _emit(
            f"{_ERASE_LINE}  {_C_DIM}[{num}]{_C_RESET} {_C_CYAN}[{bar}]{_C_RESET}  "
            f"{_C_BOLD}{color}{tag}{_C_RESET}  {label}"
        )
    else:
        _emit(f"  [{num}] {tag}  {label}")


@dataclass
class CheckResult:
    file: str
    provider: str
    email: str
    account_id: str
    status_code: int | None
    unauthorized_401: bool
    error: str
    response_preview: str


@dataclass
class DeleteError:
    file: str
    error: str


def _first_non_empty_str(values: Iterable[Any]) -> str:
    for value in values:
        if isinstance(value, str):
            stripped = value.strip()
            if stripped:
                return stripped
    return ""


def _dot_get(data: Any, dotted_key: str) -> Any:
    current = data
    for key in dotted_key.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _pick(data: dict[str, Any], candidates: list[str]) -> str:
    values = [_dot_get(data, key) for key in candidates]
    return _first_non_empty_str(values)


def _looks_like_codex(path: Path, payload: dict[str, Any]) -> bool:
    provider = _pick(payload, ["type", "provider", "metadata.type"])
    if provider:
        return provider.lower() == "codex"

    name = path.name.lower()
    if name.startswith("codex-"):
        return True

    access_token = _pick(
        payload,
        [
            "access_token",
            "accessToken",
            "token.access_token",
            "token.accessToken",
            "metadata.access_token",
            "metadata.accessToken",
            "metadata.token.access_token",
            "metadata.token.accessToken",
            "attributes.api_key",
        ],
    )
    refresh_token = _pick(
        payload,
        [
            "refresh_token",
            "refreshToken",
            "token.refresh_token",
            "token.refreshToken",
            "metadata.refresh_token",
            "metadata.refreshToken",
            "metadata.token.refresh_token",
            "metadata.token.refreshToken",
        ],
    )
    account_id = _pick(payload, ["account_id", "accountId", "metadata.account_id", "metadata.accountId"])

    return bool(access_token and (refresh_token or account_id))


def _extract_auth_fields(payload: dict[str, Any]) -> dict[str, str]:
    return {
        "provider": _pick(payload, ["type", "provider", "metadata.type"]) or "codex",
        "email": _pick(payload, ["email", "metadata.email", "attributes.email"]),
        "access_token": _pick(
            payload,
            [
                "access_token",
                "accessToken",
                "token.access_token",
                "token.accessToken",
                "metadata.access_token",
                "metadata.accessToken",
                "metadata.token.access_token",
                "metadata.token.accessToken",
                "attributes.api_key",
            ],
        ),
        "refresh_token": _pick(
            payload,
            [
                "refresh_token",
                "refreshToken",
                "token.refresh_token",
                "token.refreshToken",
                "metadata.refresh_token",
                "metadata.refreshToken",
                "metadata.token.refresh_token",
                "metadata.token.refreshToken",
            ],
        ),
        "account_id": _pick(payload, ["account_id", "accountId", "metadata.account_id", "metadata.accountId"]),
        "base_url": _pick(
            payload,
            [
                "base_url",
                "baseUrl",
                "metadata.base_url",
                "metadata.baseUrl",
                "attributes.base_url",
                "attributes.baseUrl",
            ],
        ),
    }


def _http_request(
    *,
    url: str,
    method: str,
    headers: dict[str, str],
    body: bytes | None,
    timeout: float,
    opener: request.OpenerDirector | None,
) -> tuple[int, bytes]:
    req = request.Request(url=url, data=body, method=method.upper())
    for key, value in headers.items():
        req.add_header(key, value)

    try:
        open_url = opener.open if opener is not None else request.urlopen
        with open_url(req, timeout=timeout) as resp:
            return int(resp.status), resp.read()
    except error.HTTPError as exc:
        return int(exc.code), exc.read()


def _refresh_access_token(
    refresh_url: str,
    refresh_token: str,
    timeout: float,
    opener: request.OpenerDirector | None,
) -> tuple[str, str]:
    body = parse.urlencode(
        {
            "client_id": DEFAULT_CLIENT_ID,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": "openid profile email",
        }
    ).encode("utf-8")

    status, resp_body = _http_request(
        url=refresh_url,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        body=body,
        timeout=timeout,
        opener=opener,
    )

    if status != 200:
        msg = resp_body.decode("utf-8", errors="replace")[:300]
        raise RuntimeError(f"refresh failed with {status}: {msg}")

    try:
        parsed = json.loads(resp_body.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"refresh response is not valid JSON: {exc}") from exc

    new_token = _first_non_empty_str([parsed.get("access_token")])
    new_refresh = _first_non_empty_str([parsed.get("refresh_token")])
    if not new_token:
        raise RuntimeError("refresh succeeded but access_token missing")

    return new_token, new_refresh


def _build_probe_headers(access_token: str, account_id: str) -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Version": DEFAULT_VERSION,
        "Openai-Beta": "responses=experimental",
        "User-Agent": DEFAULT_USER_AGENT,
        "Originator": "codex_cli_rs",
    }
    if account_id:
        headers["Chatgpt-Account-Id"] = account_id
    return headers


def _build_probe_body(model: str) -> bytes:
    payload = {
        "model": model,
        "stream": False,
        "instructions": "",
        "input": "ping",
        "max_output_tokens": 1,
    }
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


def _load_json(path: Path) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8-sig")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("root JSON value is not an object")
    return obj


def _load_optional_config(config_path: str) -> dict[str, Any]:
    path = Path(config_path).expanduser()
    if not path.exists():
        return {}
    if not path.is_file():
        raise ValueError(f"config path is not a file: {path}")
    try:
        return _load_json(path)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"failed to load config file {path}: {exc}") from exc


def _config_get(config: dict[str, Any], key: str) -> Any:
    if key in config:
        return config.get(key)
    dash_key = key.replace("_", "-")
    if dash_key in config:
        return config.get(dash_key)
    return None


def _resolve_option(cli_value: Any, config_value: Any, default: Any) -> Any:
    if cli_value is not None:
        return cli_value
    if config_value is not None:
        return config_value
    return default


def _coerce_bool(value: Any, name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in {0, 1}:
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "y", "on"}:
            return True
        if normalized in {"0", "false", "no", "n", "off"}:
            return False
    raise ValueError(f"{name} must be a boolean value")


def _extract_proxy_from_config(config: dict[str, Any]) -> tuple[str, str, str]:
    proxy_raw = config.get("proxy")
    proxy = proxy_raw if isinstance(proxy_raw, dict) else {}
    http_proxy = _first_non_empty_str(
        [
            proxy.get("http"),
            proxy.get("http_proxy"),
            _config_get(config, "http_proxy"),
        ]
    )
    https_proxy = _first_non_empty_str(
        [
            proxy.get("https"),
            proxy.get("https_proxy"),
            _config_get(config, "https_proxy"),
        ]
    )
    no_proxy = _first_non_empty_str(
        [
            proxy.get("no_proxy"),
            _config_get(config, "no_proxy"),
        ]
    )
    return http_proxy, https_proxy, no_proxy


def _resolve_runtime_args(args: argparse.Namespace) -> argparse.Namespace:
    config = _load_optional_config(args.config)

    args.auth_dir = _resolve_option(args.auth_dir, _config_get(config, "auth_dir"), "")
    if not args.auth_dir or args.auth_dir.strip().lower() == "input":
        if not sys.stdin.isatty():
            raise ValueError("auth directory missing. Use --auth-dir or set auth_dir in config.")
        try:
            entered = input("Auth directory path: ").strip()
        except (EOFError, KeyboardInterrupt):
            raise ValueError("auth directory input cancelled.")
        if not entered:
            raise ValueError("auth directory missing. Use --auth-dir or set auth_dir in config.")
        args.auth_dir = entered

    args.base_url = _resolve_option(args.base_url, _config_get(config, "base_url"), DEFAULT_CODEX_BASE_URL)
    args.quota_path = _resolve_option(args.quota_path, _config_get(config, "quota_path"), "/responses")
    args.model = _resolve_option(args.model, _config_get(config, "model"), "gpt-5")
    args.refresh_url = _resolve_option(args.refresh_url, _config_get(config, "refresh_url"), DEFAULT_REFRESH_URL)

    timeout_raw = _resolve_option(args.timeout, _config_get(config, "timeout"), 20)
    try:
        args.timeout = float(timeout_raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("timeout must be a number") from exc
    if args.timeout <= 0:
        raise ValueError("timeout must be greater than zero")

    max_retries_raw = _resolve_option(args.max_retries, _config_get(config, "max_retries"), 3)
    try:
        args.max_retries = int(max_retries_raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("max_retries must be an integer") from exc
    if args.max_retries < 0:
        raise ValueError("max_retries must be >= 0")

    args.refresh_before_check = _coerce_bool(
        _resolve_option(args.refresh_before_check, _config_get(config, "refresh_before_check"), False),
        "refresh_before_check",
    )
    args.output_json = _coerce_bool(
        _resolve_option(args.output_json, _config_get(config, "output_json"), False),
        "output_json",
    )
    args.delete_401 = _coerce_bool(
        _resolve_option(args.delete_401, _config_get(config, "delete_401"), False),
        "delete_401",
    )
    args.assume_yes = _coerce_bool(
        _resolve_option(args.assume_yes, _config_get(config, "assume_yes"), False),
        "assume_yes",
    )

    cfg_http_proxy, cfg_https_proxy, cfg_no_proxy = _extract_proxy_from_config(config)
    args.http_proxy = _resolve_option(args.http_proxy, cfg_http_proxy, "")
    args.https_proxy = _resolve_option(args.https_proxy, cfg_https_proxy, "")
    args.no_proxy = _resolve_option(args.no_proxy, cfg_no_proxy, "")

    return args


def _build_http_opener(
    *,
    http_proxy: str,
    https_proxy: str,
    no_proxy: str,
) -> request.OpenerDirector | None:
    if no_proxy:
        os.environ["NO_PROXY"] = no_proxy
        os.environ["no_proxy"] = no_proxy

    proxy_map: dict[str, str] = {}
    if http_proxy:
        proxy_map["http"] = http_proxy
    if https_proxy:
        proxy_map["https"] = https_proxy
    if not proxy_map:
        return None

    return request.build_opener(request.ProxyHandler(proxy_map))


def scan_auth_files(args: argparse.Namespace, opener: request.OpenerDirector | None) -> list[CheckResult]:
    auth_dir = Path(args.auth_dir).expanduser().resolve()
    if not auth_dir.exists() or not auth_dir.is_dir():
        raise FileNotFoundError(f"auth directory not found: {auth_dir}")

    results: list[CheckResult] = []

    all_json = sorted(auth_dir.rglob("*.json"))
    _progress_header(auth_dir, len(all_json))

    for idx, path in enumerate(all_json, 1):
        try:
            payload = _load_json(path)
        except Exception as exc:  # noqa: BLE001
            results.append(
                CheckResult(
                    file=str(path),
                    provider="unknown",
                    email="",
                    account_id="",
                    status_code=None,
                    unauthorized_401=False,
                    error=f"parse error: {exc}",
                    response_preview="",
                )
            )
            continue

        if not _looks_like_codex(path, payload):
            continue

        fields = _extract_auth_fields(payload)
        access_token = fields["access_token"]
        refresh_token = fields["refresh_token"]

        label = fields["email"] or path.name
        _progress_checking(idx, len(all_json), label)

        try:
            if args.refresh_before_check and refresh_token:
                access_token, _ = _refresh_access_token(
                    args.refresh_url,
                    refresh_token,
                    args.timeout,
                    opener,
                )
        except Exception as exc:  # noqa: BLE001
            _progress_result(idx, len(all_json), label, "refresh failed", _C_YELLOW)
            results.append(
                CheckResult(
                    file=str(path),
                    provider=fields["provider"],
                    email=fields["email"],
                    account_id=fields["account_id"],
                    status_code=None,
                    unauthorized_401=False,
                    error=str(exc),
                    response_preview="",
                )
            )
            continue

        if not access_token:
            _progress_result(idx, len(all_json), label, "no token", _C_YELLOW)
            results.append(
                CheckResult(
                    file=str(path),
                    provider=fields["provider"],
                    email=fields["email"],
                    account_id=fields["account_id"],
                    status_code=None,
                    unauthorized_401=False,
                    error="missing access token",
                    response_preview="",
                )
            )
            continue

        base_url = fields["base_url"] or args.base_url
        probe_url = base_url.rstrip("/") + "/" + args.quota_path.lstrip("/")

        headers = _build_probe_headers(access_token, fields["account_id"])
        body = _build_probe_body(args.model)

        last_exc: Exception | None = None
        probe_result: tuple[int, bytes] | None = None
        for attempt in range(args.max_retries + 1):
            if attempt > 0:
                _progress_checking(idx, len(all_json), label, retry=attempt)
            try:
                probe_result = _http_request(
                    url=probe_url,
                    method="POST",
                    headers=headers,
                    body=body,
                    timeout=args.timeout,
                    opener=opener,
                )
                last_exc = None
                break
            except (error.URLError, OSError) as exc:
                last_exc = exc

        if probe_result is not None:
            status, resp_body = probe_result
            _tag_color = _C_RED if status == 401 else (_C_GREEN if status < 400 else _C_YELLOW)
            _progress_result(idx, len(all_json), label, str(status), _tag_color)
            preview = resp_body.decode("utf-8", errors="replace")[:300]
            results.append(
                CheckResult(
                    file=str(path),
                    provider=fields["provider"],
                    email=fields["email"],
                    account_id=fields["account_id"],
                    status_code=status,
                    unauthorized_401=(status == 401),
                    error="",
                    response_preview=preview,
                )
            )
        else:
            retry_note = f" (after {args.max_retries} retries)" if args.max_retries > 0 else ""
            _progress_result(idx, len(all_json), label, f"network error{retry_note}", _C_YELLOW)
            results.append(
                CheckResult(
                    file=str(path),
                    provider=fields["provider"],
                    email=fields["email"],
                    account_id=fields["account_id"],
                    status_code=None,
                    unauthorized_401=False,
                    error=f"network error: {last_exc}",
                    response_preview="",
                )
            )

    return results


def _print_table(results: list[CheckResult]) -> None:
    if not results:
        print("No codex auth files found.")
        return

    unauthorized = [r for r in results if r.unauthorized_401]
    print(f"Checked codex files: {len(results)}")
    print(f"401 unauthorized files: {len(unauthorized)}")
    print()

    for item in unauthorized:
        print(f"[401] {item.file}")

    if unauthorized:
        print()

    others = [r for r in results if not r.unauthorized_401]
    if others:
        print("Non-401 results:")
        for item in others:
            status = "-" if item.status_code is None else str(item.status_code)
            reason = item.error or item.response_preview.replace("\n", " ")[:120]
            print(f"[{status}] {item.file} :: {reason}")


def _confirm_deletion(targets: list[str], assume_yes: bool) -> bool:
    if not targets:
        return False
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        print("No interactive terminal for confirmation; deletion cancelled. Use --assume-yes to force.")
        return False

    print()
    print(f"Delete {len(targets)} files with 401? This action cannot be undone.")
    answer = input("Confirm deletion? [y/N]: ").strip().lower()
    return answer in {"y", "yes"}


def _delete_files(paths: list[str]) -> tuple[list[str], list[DeleteError]]:
    deleted: list[str] = []
    errors: list[DeleteError] = []
    seen: set[str] = set()

    for raw_path in paths:
        path = Path(raw_path)
        normalized = str(path.resolve())
        if normalized in seen:
            continue
        seen.add(normalized)

        try:
            path.unlink()
            deleted.append(str(path))
        except Exception as exc:  # noqa: BLE001
            errors.append(DeleteError(file=str(path), error=str(exc)))

    return deleted, errors


def _print_deletion_summary(
    *,
    requested: bool,
    target_count: int,
    confirmed: bool,
    deleted_files: list[str],
    errors: list[DeleteError],
) -> None:
    if not requested:
        return
    if target_count == 0:
        print()
        print("Delete mode enabled, but no 401 files found.")
        return

    print()
    if not confirmed:
        print("Deletion cancelled by user.")
        return

    print(f"Deletion completed: {len(deleted_files)}/{target_count} removed.")
    for path in deleted_files:
        print(f"[deleted] {path}")
    for item in errors:
        print(f"[delete-failed] {item.file} :: {item.error}")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Traverse auth folder and detect Codex auth files returning 401 during quota probe."
    )
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help=f"JSON config path (default: {DEFAULT_CONFIG_PATH}; ignored if missing).",
    )
    parser.add_argument("--auth-dir", default=None, help="Folder containing auth JSON files.")
    parser.add_argument(
        "--base-url",
        default=None,
        help=f"Codex base URL (fallback default: {DEFAULT_CODEX_BASE_URL})",
    )
    parser.add_argument(
        "--quota-path",
        default=None,
        help="API path used for quota/auth probe (fallback default: /responses)",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Model used in probe request body (fallback default: gpt-5)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="HTTP timeout in seconds (fallback default: 20)",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=None,
        help="Max retry attempts on network error (fallback default: 3, 0 = no retry).",
    )
    parser.add_argument(
        "--refresh-before-check",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Refresh access token with refresh_token before probe.",
    )
    parser.add_argument(
        "--refresh-url",
        default=None,
        help=f"Token refresh endpoint (fallback default: {DEFAULT_REFRESH_URL})",
    )
    parser.add_argument(
        "--output-json",
        action="store_true",
        default=None,
        help="Print full results as JSON instead of table view.",
    )
    parser.add_argument(
        "--delete-401",
        action="store_true",
        default=None,
        help="Delete auth files that returned HTTP 401 after confirmation.",
    )
    parser.add_argument(
        "--assume-yes",
        action="store_true",
        default=None,
        help="Skip deletion confirmation prompt (only applies with --delete-401).",
    )
    parser.add_argument(
        "--http-proxy",
        default=None,
        help="HTTP proxy URL, for example: http://127.0.0.1:7890",
    )
    parser.add_argument(
        "--https-proxy",
        default=None,
        help="HTTPS proxy URL, for example: http://127.0.0.1:7890",
    )
    parser.add_argument(
        "--no-proxy",
        default=None,
        help="Comma-separated hosts that bypass proxy.",
    )
    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    try:
        args = _resolve_runtime_args(args)
        opener = _build_http_opener(
            http_proxy=args.http_proxy,
            https_proxy=args.https_proxy,
            no_proxy=args.no_proxy,
        )
        results = scan_auth_files(args, opener)
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    unauthorized_files = [item.file for item in results if item.unauthorized_401]
    delete_confirmed = False
    deleted_files: list[str] = []
    delete_errors: list[DeleteError] = []

    if args.delete_401 and unauthorized_files:
        delete_confirmed = _confirm_deletion(unauthorized_files, args.assume_yes)
        if delete_confirmed:
            deleted_files, delete_errors = _delete_files(unauthorized_files)

    if args.output_json:
        print(
            json.dumps(
                {
                    "results": [asdict(item) for item in results],
                    "deletion": {
                        "requested": args.delete_401,
                        "target_count": len(unauthorized_files),
                        "confirmed": delete_confirmed,
                        "deleted_count": len(deleted_files),
                        "deleted_files": deleted_files,
                        "errors": [asdict(item) for item in delete_errors],
                    },
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        _print_table(results)
        _print_deletion_summary(
            requested=args.delete_401,
            target_count=len(unauthorized_files),
            confirmed=delete_confirmed,
            deleted_files=deleted_files,
            errors=delete_errors,
        )

    has_401 = any(item.unauthorized_401 for item in results)
    return 1 if has_401 else 0


if __name__ == "__main__":
    raise SystemExit(main())
