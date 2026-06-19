"""netsh advfirewall wrapper.

Pure stdlib; no DB, no audit, no FastAPI. Higher layers (the
/mitigation/* endpoints in W3-Sub3) wrap this with permission checks,
audit-log writes, and approval-flow state transitions.

Public surface:
    is_admin()             -> bool
    validate_ip(ip, *, allow_private=False) -> (bool, reason)
    block_ip(ip,   *, allow_private=False) -> dict
    unblock_ip(ip)                         -> dict
    list_blocked_ips()                     -> list[dict]

All public functions return — never raise — on the netsh side. Bad
input still raises a TypeError up front via the Python signature.
"""

import ctypes
import ipaddress
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


# ── Module-level constants ────────────────────────────────────────
RULE_NAME_PREFIX = "AI-IDS Block"
BLOCKED_IPS_LEDGER_PATH = "data/blocked_ips.json"
NETSH_TIMEOUT_SECONDS = 10


# ── Project root resolution (mirrors src/utils/db.py) ─────────────
_p = Path(__file__).resolve().parent
while _p != _p.parent:
    if (_p / "env" / "requirements.txt").exists():
        break
    _p = _p.parent
else:
    _p = Path.cwd()
PROJECT_ROOT = _p


# ── Public API ────────────────────────────────────────────────────
def is_admin() -> bool:
    """True iff the current process has Windows admin rights.

    Returns False on non-Windows or any failure of the elevation probe;
    callers always treat False as "block the operation."
    """
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


def validate_ip(ip, *, allow_private: bool = False) -> tuple[bool, str]:
    """Return (is_valid, reason). reason is "" on success.

    With allow_private=False (the HARD_CONSTRAINTS default), rejects
    every IP that isn't routable on the public Internet: loopback,
    private (RFC1918, ULA), link-local, multicast, reserved, and the
    unspecified addresses.
    """
    if not isinstance(ip, str) or not ip:
        return False, "IP must be a non-empty string"

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError as e:
        return False, f"Not a valid IP address ({ip}): {e}"

    if allow_private:
        return True, ""

    # Check in the order the user is most likely to recognize, so the
    # reason message names the meaningful property rather than the
    # broadest one (is_private is a superset of loopback / link-local
    # in some Python versions).
    if addr.is_unspecified:
        return False, (f"IP is unspecified ({ip}); pass allow_private=True to override")
    if addr.is_loopback:
        return False, (f"IP is loopback ({ip}); pass allow_private=True to override")
    if addr.is_link_local:
        return False, (f"IP is link-local ({ip}); pass allow_private=True to override")
    if addr.is_multicast:
        return False, (f"IP is multicast ({ip}); pass allow_private=True to override")
    if addr.is_reserved:
        return False, (f"IP is reserved ({ip}); pass allow_private=True to override")
    if addr.is_private:
        return False, (f"IP is private ({ip}); pass allow_private=True to override")

    return True, ""


def block_ip(ip: str, *, allow_private: bool = False) -> dict:
    """Add a netsh inbound block rule for `ip`. Idempotent: if a rule
    of the same name already exists, returns ok=True without re-adding.
    """
    rule_name = f"{RULE_NAME_PREFIX} {ip}"

    ok, reason = validate_ip(ip, allow_private=allow_private)
    if not ok:
        return _result(False, ip, rule_name, "", "", reason)

    if not is_admin():
        return _result(
            False, ip, rule_name, "", "",
            "Process is not running as administrator; "
            "netsh advfirewall requires elevation.",
        )

    if _rule_exists(rule_name):
        return _result(True, ip, rule_name, "Rule already exists, no-op.", "", None)

    argv = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=in",
        "action=block",
        f"remoteip={ip}",
    ]
    try:
        proc = subprocess.run(
            argv,
            capture_output=True, text=True,
            timeout=NETSH_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return _result(False, ip, rule_name, "", "",
                       f"netsh timed out after {NETSH_TIMEOUT_SECONDS}s")
    except FileNotFoundError:
        return _result(False, ip, rule_name, "", "",
                       "netsh executable not found on PATH")
    except OSError as e:
        return _result(False, ip, rule_name, "", "",
                       f"OSError invoking netsh: {e}")

    if proc.returncode == 0:
        _append_to_ledger(ip, rule_name, "block")
        return _result(True, ip, rule_name, proc.stdout, proc.stderr, None)

    return _result(False, ip, rule_name, proc.stdout, proc.stderr,
                   f"netsh exited with code {proc.returncode}")


def unblock_ip(ip: str) -> dict:
    """Delete the netsh rule for `ip`. Idempotent: if no rule exists,
    returns ok=True without touching netsh.
    """
    rule_name = f"{RULE_NAME_PREFIX} {ip}"

    if not is_admin():
        return _result(
            False, ip, rule_name, "", "",
            "Process is not running as administrator; "
            "netsh advfirewall requires elevation.",
        )

    if not _rule_exists(rule_name):
        return _result(True, ip, rule_name, "No rule for this IP, no-op.", "", None)

    argv = [
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={rule_name}",
    ]
    try:
        proc = subprocess.run(
            argv,
            capture_output=True, text=True,
            timeout=NETSH_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return _result(False, ip, rule_name, "", "",
                       f"netsh timed out after {NETSH_TIMEOUT_SECONDS}s")
    except FileNotFoundError:
        return _result(False, ip, rule_name, "", "",
                       "netsh executable not found on PATH")
    except OSError as e:
        return _result(False, ip, rule_name, "", "",
                       f"OSError invoking netsh: {e}")

    if proc.returncode == 0:
        _append_to_ledger(ip, rule_name, "unblock")
        return _result(True, ip, rule_name, proc.stdout, proc.stderr, None)

    return _result(False, ip, rule_name, proc.stdout, proc.stderr,
                   f"netsh exited with code {proc.returncode}")


def list_blocked_ips() -> list[dict]:
    """Return [{ip, rule_name, blocked_at}, ...] for every IP whose most
    recent ledger entry is a 'block' (i.e. not subsequently unblocked).

    Best-effort: missing / corrupt ledger returns []. Never raises.
    """
    entries = _read_ledger()
    last: dict[str, dict] = {}
    for e in entries:
        ip = e.get("ip")
        if not isinstance(ip, str):
            continue
        last[ip] = e

    active = []
    for ip, e in last.items():
        if e.get("action") == "block":
            active.append({
                "ip": ip,
                "rule_name": e.get("rule_name", f"{RULE_NAME_PREFIX} {ip}"),
                "blocked_at": e.get("ts", ""),
            })
    # Stable sort by IP for deterministic output.
    active.sort(key=lambda d: d["ip"])
    return active


# ── Private helpers ───────────────────────────────────────────────
def _result(ok, ip, rule_name, stdout, stderr, error):
    return {
        "ok": ok,
        "ip": ip,
        "rule_name": rule_name,
        "stdout": stdout,
        "stderr": stderr,
        "error": error,
    }


def _rule_exists(rule_name: str) -> bool:
    """True iff netsh reports the named rule exists. Defensive: any
    exception (timeout, netsh missing, etc.) returns False so the
    caller falls through to the real add/delete and surfaces the real
    error instead of a misleading 'rule not found' shortcut.
    """
    try:
        proc = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule",
             f"name={rule_name}"],
            capture_output=True, text=True,
            timeout=NETSH_TIMEOUT_SECONDS,
        )
    except Exception:
        return False

    if proc.returncode == 0 and rule_name in (proc.stdout or ""):
        return True
    return False


def _ledger_path() -> Path:
    # Read the module attribute dynamically so tests can monkeypatch it.
    p = Path(BLOCKED_IPS_LEDGER_PATH)
    if p.is_absolute():
        return p
    return PROJECT_ROOT / p


def _read_ledger() -> list[dict]:
    path = _ledger_path()
    try:
        if not path.exists():
            return []
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, list):
            return []
        return data
    except Exception as e:
        print(f"[firewall] ledger read failed: {e}", file=sys.stderr)
        return []


def _append_to_ledger(ip: str, rule_name: str, action: str) -> None:
    try:
        path = _ledger_path()
        os.makedirs(path.parent, exist_ok=True)
        entries = _read_ledger()
        entries.append({
            "ip": ip,
            "rule_name": rule_name,
            "action": action,
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
        })
        tmp = path.with_suffix(path.suffix + ".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(entries, fh, indent=2)
        os.replace(tmp, path)
    except Exception as e:
        print(f"[firewall] ledger write failed: {e}", file=sys.stderr)
