"""W3-Sub2 tests for src/mitigation/firewall.py.

All netsh calls are mocked. No real subprocess invocations during this
test run. The ledger test (V6) uses tmp_path so production
data/blocked_ips.json is never touched.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Make the project root importable regardless of how pytest is invoked.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.mitigation import firewall  # noqa: E402


# ── V1: validate_ip ───────────────────────────────────────────────
def test_validate_ip_rejects_private_by_default():
    ok, reason = firewall.validate_ip("192.168.142.128")
    assert ok is False
    assert "private" in reason.lower()

    ok, _ = firewall.validate_ip("10.0.0.1")
    assert ok is False

    ok, reason = firewall.validate_ip("127.0.0.1")
    assert ok is False
    assert "loopback" in reason.lower()

    ok, reason = firewall.validate_ip("169.254.1.1")
    assert ok is False
    assert "link-local" in reason.lower()

    ok, _ = firewall.validate_ip("")
    assert ok is False

    ok, _ = firewall.validate_ip("not-an-ip")
    assert ok is False

    ok, reason = firewall.validate_ip("8.8.8.8")
    assert ok is True
    assert reason == ""

    ok, _ = firewall.validate_ip("192.168.1.1", allow_private=True)
    assert ok is True


# ── V2: block_ip with is_admin=False ──────────────────────────────
def test_block_ip_returns_not_admin_error():
    with patch.object(firewall, "is_admin", return_value=False), \
         patch("subprocess.run") as mock_run:
        result = firewall.block_ip("8.8.8.8")
    assert result["ok"] is False
    assert "administrator" in (result["error"] or "").lower()
    # And subprocess must not have been called.
    mock_run.assert_not_called()


# ── V3: block_ip happy path ───────────────────────────────────────
def test_block_ip_happy_path_calls_netsh_with_argv_list():
    fake_proc = MagicMock(returncode=0, stdout="Ok.\n", stderr="")
    with patch.object(firewall, "is_admin",       return_value=True), \
         patch.object(firewall, "_rule_exists",   return_value=False), \
         patch.object(firewall, "_append_to_ledger") as mock_ledger, \
         patch("subprocess.run", return_value=fake_proc) as mock_run:
        result = firewall.block_ip("8.8.8.8")

    assert result["ok"] is True
    assert result["rule_name"] == "AI-IDS Block 8.8.8.8"
    assert "Ok" in result["stdout"]
    assert result["error"] is None

    # Single subprocess call, argv list (not a string), shell defaults to False
    mock_run.assert_called_once()
    call_args, call_kwargs = mock_run.call_args
    argv = call_args[0]
    assert isinstance(argv, list), "argv must be a list, not a shell string"
    assert argv[0] == "netsh"
    assert "remoteip=8.8.8.8" in argv
    assert f"name=AI-IDS Block 8.8.8.8" in argv
    assert call_kwargs.get("shell", False) is False
    mock_ledger.assert_called_once_with("8.8.8.8", "AI-IDS Block 8.8.8.8", "block")


# ── V4: block_ip idempotent when rule exists ──────────────────────
def test_block_ip_idempotent_when_rule_exists():
    with patch.object(firewall, "is_admin",     return_value=True), \
         patch.object(firewall, "_rule_exists", return_value=True), \
         patch.object(firewall, "_append_to_ledger") as mock_ledger, \
         patch("subprocess.run") as mock_run:
        result = firewall.block_ip("8.8.8.8")

    assert result["ok"] is True
    assert "already exists" in result["stdout"].lower()
    mock_run.assert_not_called()
    mock_ledger.assert_not_called()


# ── V5: unblock_ip happy path + idempotent ────────────────────────
def test_unblock_ip_happy_then_idempotent():
    fake_proc = MagicMock(returncode=0, stdout="Deleted 1 rule(s).\n", stderr="")
    # First call: rule exists -> netsh runs. Second call: rule gone -> no-op.
    with patch.object(firewall, "is_admin", return_value=True), \
         patch.object(firewall, "_rule_exists", side_effect=[True, False]), \
         patch.object(firewall, "_append_to_ledger") as mock_ledger, \
         patch("subprocess.run", return_value=fake_proc) as mock_run:
        first = firewall.unblock_ip("8.8.8.8")
        second = firewall.unblock_ip("8.8.8.8")

    assert first["ok"] is True
    assert first["error"] is None
    assert "Deleted" in first["stdout"]
    mock_run.assert_called_once()  # only the first call hit netsh
    mock_ledger.assert_called_once_with("8.8.8.8", "AI-IDS Block 8.8.8.8", "unblock")

    assert second["ok"] is True
    assert second["stdout"] == "No rule for this IP, no-op."


# ── V6: ledger round-trip ─────────────────────────────────────────
def test_ledger_round_trip(tmp_path, monkeypatch):
    ledger = tmp_path / "ledger.json"
    monkeypatch.setattr(firewall, "BLOCKED_IPS_LEDGER_PATH", str(ledger))

    # 1. block 8.8.8.8 -> unblock 8.8.8.8 -> list should be []
    firewall._append_to_ledger("8.8.8.8", "AI-IDS Block 8.8.8.8", "block")
    firewall._append_to_ledger("8.8.8.8", "AI-IDS Block 8.8.8.8", "unblock")
    assert firewall.list_blocked_ips() == []

    # Confirm the on-disk file is well-formed JSON with both entries.
    on_disk = json.loads(ledger.read_text(encoding="utf-8"))
    assert len(on_disk) == 2
    assert [e["action"] for e in on_disk] == ["block", "unblock"]
    assert all(e["ts"].endswith("Z") for e in on_disk)

    # 2. block 1.1.1.1 -> list should be [{ip:1.1.1.1, ...}]
    firewall._append_to_ledger("1.1.1.1", "AI-IDS Block 1.1.1.1", "block")
    active = firewall.list_blocked_ips()
    assert len(active) == 1
    assert active[0]["ip"] == "1.1.1.1"
    assert active[0]["rule_name"] == "AI-IDS Block 1.1.1.1"
    assert active[0]["blocked_at"].endswith("Z")
