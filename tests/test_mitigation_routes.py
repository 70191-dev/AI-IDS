"""W3-Sub3 tests for src/serve/mitigation_routes.py.

No real netsh is ever invoked. firewall.block_ip / unblock_ip /
list_blocked_ips are patched per test.

A tempfile SQLite DB is bound via the IDS_DB_PATH env var BEFORE
importing src.utils.db so module-level DB_PATH resolution picks it up.
A small FastAPI app that only mounts mitigation_router is built per
fixture; the heavy production app + lifespan (which loads ML models)
is intentionally bypassed.
"""

import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

# ── Bind a tempfile DB BEFORE importing src.utils.db ──────────────
_TMPDIR = Path(tempfile.mkdtemp(prefix="aiids_w3sub3_"))
os.environ["IDS_DB_PATH"] = str(_TMPDIR / "test.db")
# Default for the suite: private-IP override OFF (HARD_CONSTRAINTS default).
# V5 monkeypatches it on.
os.environ.pop("MITIGATION_ALLOW_PRIVATE", None)

# Make project root importable
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from src.utils import db  # noqa: E402
from src.auth.passwords import hash_password  # noqa: E402
from src.auth.tokens import create_session  # noqa: E402
from src.mitigation import firewall  # noqa: E402
from src.serve.mitigation_routes import router as mitigation_router  # noqa: E402


# ── Schema bootstrap (once per session) ───────────────────────────
db.init_db()


# ── Per-test wipe + reseed ────────────────────────────────────────
def _wipe_all():
    """Clear every table this test suite touches. FK-safe order."""
    conn = db.get_conn()
    try:
        conn.execute("PRAGMA foreign_keys = OFF")
        for table in (
            "mitigation_action", "mitigation_request",
            "audit_log", "session",
            "mitigation_record", "alert", "detection_result", "traffic_flow",
            "user",
        ):
            conn.execute(f"DELETE FROM {table}")
            conn.execute(f"DELETE FROM sqlite_sequence WHERE name='{table}'")
        conn.execute("PRAGMA foreign_keys = ON")
    finally:
        conn.close()


def _seed_users_and_alert():
    """Returns dict: admin_id, analyst_id, admin_token, analyst_token, alert_id."""
    now = datetime.now().isoformat(timespec="seconds")
    pw_hash = hash_password("password1234")

    conn = db.get_conn()
    try:
        cur = conn.execute(
            "INSERT INTO user (username, password_hash, role, created_at) "
            "VALUES (?, ?, 'admin', ?)",
            ("admin1", pw_hash, now),
        )
        admin_id = cur.lastrowid
        cur = conn.execute(
            "INSERT INTO user (username, password_hash, role, created_at) "
            "VALUES (?, ?, 'analyst', ?)",
            ("analyst1", pw_hash, now),
        )
        analyst_id = cur.lastrowid

        # alert FK chain: traffic_flow -> detection_result -> alert
        cur = conn.execute(
            "INSERT INTO traffic_flow "
            "  (ts, flow_id, src_ip, source_mode, raw_features_json) "
            "VALUES (?, 'test-flow-1', '8.8.8.8', 'manual', '{}')",
            (now,),
        )
        flow_pk = cur.lastrowid
        cur = conn.execute(
            "INSERT INTO detection_result "
            "  (flow_id, score, label, label_text, attack_type, "
            "   attack_confidence, model_version, threshold, created_at) "
            "VALUES (?, 0.92, 1, 'Attack', 'DoS', 0.95, 'test', 0.5, ?)",
            (flow_pk, now),
        )
        det_pk = cur.lastrowid
        cur = conn.execute(
            "INSERT INTO alert (detection_id, severity, status, created_at) "
            "VALUES (?, 'High', 'open', ?)",
            (det_pk, now),
        )
        alert_id = cur.lastrowid

        admin_sess   = create_session(conn, admin_id,   ip="127.0.0.1", ua="pytest")
        analyst_sess = create_session(conn, analyst_id, ip="127.0.0.1", ua="pytest")
    finally:
        conn.close()

    return {
        "admin_id":      admin_id,
        "analyst_id":    analyst_id,
        "admin_token":   admin_sess["token"],
        "analyst_token": analyst_sess["token"],
        "alert_id":      alert_id,
    }


@pytest.fixture
def env():
    """Fresh DB state + seeded users/alert + TestClient app."""
    _wipe_all()
    seeded = _seed_users_and_alert()
    app = FastAPI()
    app.include_router(mitigation_router)
    seeded["client"] = TestClient(app)
    seeded["admin_h"]   = {"Authorization": f"Bearer {seeded['admin_token']}"}
    seeded["analyst_h"] = {"Authorization": f"Bearer {seeded['analyst_token']}"}
    yield seeded


# ── Tiny helpers ──────────────────────────────────────────────────
def _audit_rows(action=None, status_=None):
    conn = db.get_conn()
    try:
        sql = "SELECT * FROM audit_log"
        clauses, params = [], []
        if action is not None:
            clauses.append("action = ?")
            params.append(action)
        if status_ is not None:
            clauses.append("status = ?")
            params.append(status_)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id ASC"
        return [dict(r) for r in conn.execute(sql, tuple(params)).fetchall()]
    finally:
        conn.close()


def _request_row(rid):
    conn = db.get_conn()
    try:
        r = conn.execute("SELECT * FROM mitigation_request WHERE id = ?", (rid,)).fetchone()
        return dict(r) if r else None
    finally:
        conn.close()


def _action_rows(target_ip=None):
    conn = db.get_conn()
    try:
        if target_ip is not None:
            rows = conn.execute(
                "SELECT * FROM mitigation_action WHERE target_ip = ? ORDER BY id ASC",
                (target_ip,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM mitigation_action ORDER BY id ASC"
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def _backdate_request(rid, seconds_ago=10):
    """Move requested_at into the past so the two-person rule doesn't fire."""
    backdated = (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).strftime(
        "%Y-%m-%dT%H:%M:%S.%f"
    ) + "Z"
    conn = db.get_conn()
    try:
        conn.execute(
            "UPDATE mitigation_request SET requested_at = ? WHERE id = ?",
            (backdated, rid),
        )
    finally:
        conn.close()


# ── V1: happy path ────────────────────────────────────────────────
def test_v1_analyst_creates_admin_approves_happy_path(env):
    c = env["client"]

    r = c.post(
        "/mitigation/requests",
        json={"alert_id": env["alert_id"], "target_ip": "8.8.8.8", "reason": "DoS source"},
        headers=env["analyst_h"],
    )
    assert r.status_code == 201, r.text
    body = r.json()
    rid = body["id"]
    assert body["status"] == "pending"
    assert body["target_ip"] == "8.8.8.8"
    assert body["requested_by"] == env["analyst_id"]

    # Backdate so the two-person rule cannot fire (admin != analyst anyway,
    # but this also exercises the >5s path).
    _backdate_request(rid, seconds_ago=10)

    block_result = {
        "ok": True, "ip": "8.8.8.8",
        "rule_name": "AI-IDS Block 8.8.8.8",
        "stdout": "Ok.", "stderr": "", "error": None,
    }
    with patch.object(firewall, "block_ip", return_value=block_result) as mock_block:
        r = c.post(
            f"/mitigation/requests/{rid}/approve",
            json={"note": "confirmed"},
            headers=env["admin_h"],
        )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["request"]["status"] == "approved"
    assert body["request"]["decided_by"] == env["admin_id"]
    assert body["action"]["action_type"] == "block"
    assert body["action"]["status"] == "success"
    assert body["block_result"]["ok"] is True
    mock_block.assert_called_once()

    # DB state
    db_req = _request_row(rid)
    assert db_req["status"] == "approved"
    actions = _action_rows("8.8.8.8")
    assert len(actions) == 1
    assert actions[0]["status"] == "success"
    assert actions[0]["request_id"] == rid

    # Audit chain
    creates  = _audit_rows(action="mitigation.request.create",  status_="success")
    approves = _audit_rows(action="mitigation.request.approve", status_="success")
    blocks   = _audit_rows(action="mitigation.block.execute",   status_="success")
    assert len(creates) == 1
    assert len(approves) == 1
    assert len(blocks) == 1
    assert f"request:{rid}" in (creates[0]["target"] or "")
    assert f"request:{rid}" == approves[0]["target"]
    assert f"request:{rid}" == blocks[0]["target"]


# ── V2: two-person rule fires ─────────────────────────────────────
def test_v2_two_person_rule_blocks_self_approval(env):
    c = env["client"]

    # Admin creates the request (admin has mitigation.request perm).
    r = c.post(
        "/mitigation/requests",
        json={"alert_id": env["alert_id"], "target_ip": "8.8.8.8"},
        headers=env["admin_h"],
    )
    assert r.status_code == 201
    rid = r.json()["id"]

    # Admin immediately approves their own request -- < 5s -> 403.
    with patch.object(firewall, "block_ip") as mock_block:
        r = c.post(
            f"/mitigation/requests/{rid}/approve",
            json={},
            headers=env["admin_h"],
        )
    assert r.status_code == 403, r.text
    assert "two-person rule" in r.json()["detail"].lower()
    mock_block.assert_not_called()

    # Request must still be pending.
    assert _request_row(rid)["status"] == "pending"

    fails = _audit_rows(action="mitigation.request.approve", status_="failure")
    assert len(fails) == 1
    assert "two-person" in (fails[0]["detail"] or "").lower()


# ── V3: two-person rule does NOT fire on deny ─────────────────────
def test_v3_deny_own_request_allowed(env):
    c = env["client"]
    r = c.post(
        "/mitigation/requests",
        json={"alert_id": env["alert_id"], "target_ip": "8.8.8.8"},
        headers=env["admin_h"],
    )
    rid = r.json()["id"]

    r = c.post(
        f"/mitigation/requests/{rid}/deny",
        json={"note": "false positive"},
        headers=env["admin_h"],
    )
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "denied"
    assert _request_row(rid)["status"] == "denied"

    denies = _audit_rows(action="mitigation.request.deny", status_="success")
    assert len(denies) == 1


# ── V4: duplicate pending request returns 409 ─────────────────────
def test_v4_duplicate_pending_returns_409(env):
    c = env["client"]
    r1 = c.post(
        "/mitigation/requests",
        json={"alert_id": env["alert_id"], "target_ip": "8.8.8.8"},
        headers=env["analyst_h"],
    )
    assert r1.status_code == 201
    first_id = r1.json()["id"]

    r2 = c.post(
        "/mitigation/requests",
        json={"alert_id": env["alert_id"], "target_ip": "8.8.8.8"},
        headers=env["analyst_h"],
    )
    assert r2.status_code == 409, r2.text
    detail = r2.json()["detail"]
    assert detail["existing_request_id"] == first_id


# ── V5: private IP rejected without env var, allowed with it ──────
def test_v5_private_ip_gated_by_env_var(env, monkeypatch):
    c = env["client"]
    monkeypatch.delenv("MITIGATION_ALLOW_PRIVATE", raising=False)
    r = c.post(
        "/mitigation/requests",
        json={"alert_id": env["alert_id"], "target_ip": "192.168.142.128"},
        headers=env["analyst_h"],
    )
    assert r.status_code == 400, r.text
    assert "private" in r.json()["detail"].lower()

    monkeypatch.setenv("MITIGATION_ALLOW_PRIVATE", "true")
    r = c.post(
        "/mitigation/requests",
        json={"alert_id": env["alert_id"], "target_ip": "192.168.142.128"},
        headers=env["analyst_h"],
    )
    assert r.status_code == 201, r.text
    assert r.json()["target_ip"] == "192.168.142.128"


# ── V6: approve with block_ip returning ok=False ──────────────────
def test_v6_approve_with_netsh_failure_does_not_revert(env):
    c = env["client"]
    r = c.post(
        "/mitigation/requests",
        json={"alert_id": env["alert_id"], "target_ip": "8.8.8.8"},
        headers=env["analyst_h"],
    )
    rid = r.json()["id"]
    _backdate_request(rid, seconds_ago=10)

    fail_result = {
        "ok": False, "ip": "8.8.8.8",
        "rule_name": "AI-IDS Block 8.8.8.8",
        "stdout": "", "stderr": "Error.",
        "error": "netsh exited with code 1",
    }
    with patch.object(firewall, "block_ip", return_value=fail_result):
        r = c.post(
            f"/mitigation/requests/{rid}/approve",
            json={},
            headers=env["admin_h"],
        )
    # Endpoint returns 200 even on netsh failure, with a warning key.
    assert r.status_code == 200, r.text
    body = r.json()
    assert "warning" in body
    assert body["request"]["status"] == "approved"   # not reverted
    assert body["action"]["status"] == "failure"
    assert body["action"]["error_detail"] == "netsh exited with code 1"

    approves = _audit_rows(action="mitigation.request.approve", status_="success")
    block_fails = _audit_rows(action="mitigation.block.execute", status_="failure")
    assert len(approves) == 1
    assert len(block_fails) == 1


# ── V7: approve a non-pending request returns 409 ─────────────────
def test_v7_approve_non_pending_returns_409(env):
    c = env["client"]
    r = c.post(
        "/mitigation/requests",
        json={"alert_id": env["alert_id"], "target_ip": "8.8.8.8"},
        headers=env["analyst_h"],
    )
    rid = r.json()["id"]
    _backdate_request(rid, seconds_ago=10)

    block_ok = {"ok": True, "ip": "8.8.8.8", "rule_name": "AI-IDS Block 8.8.8.8",
                "stdout": "Ok.", "stderr": "", "error": None}
    with patch.object(firewall, "block_ip", return_value=block_ok):
        r1 = c.post(f"/mitigation/requests/{rid}/approve", json={}, headers=env["admin_h"])
        r2 = c.post(f"/mitigation/requests/{rid}/approve", json={}, headers=env["admin_h"])
    assert r1.status_code == 200
    assert r2.status_code == 409
    assert "already approved" in r2.json()["detail"].lower()


# ── V8: permission gates ──────────────────────────────────────────
def test_v8_permission_gates(env):
    c = env["client"]
    # Seed a request to target.
    r = c.post(
        "/mitigation/requests",
        json={"alert_id": env["alert_id"], "target_ip": "8.8.8.8"},
        headers=env["analyst_h"],
    )
    rid = r.json()["id"]

    # Analyst cannot approve.
    r = c.post(f"/mitigation/requests/{rid}/approve", json={}, headers=env["analyst_h"])
    assert r.status_code == 403, r.text

    # Analyst cannot unblock.
    r = c.post("/mitigation/unblock", json={"ip": "8.8.8.8"}, headers=env["analyst_h"])
    assert r.status_code == 403, r.text

    # Missing bearer -> 401.
    r = c.post(
        "/mitigation/requests",
        json={"alert_id": env["alert_id"], "target_ip": "8.8.8.8"},
    )
    assert r.status_code == 401, r.text


# ── V9: unblock with no prior request returns 400 ─────────────────
def test_v9_unblock_with_no_prior_request_400(env):
    c = env["client"]
    with patch.object(firewall, "unblock_ip") as mock_unblock:
        r = c.post(
            "/mitigation/unblock",
            json={"ip": "8.8.8.8"},
            headers=env["admin_h"],
        )
    assert r.status_code == 400, r.text
    assert "never the subject of a mitigation request" in r.json()["detail"]
    mock_unblock.assert_not_called()


# ── V10: unblock happy path ───────────────────────────────────────
def test_v10_unblock_happy_path_links_to_prior_request(env):
    c = env["client"]
    # Pending -> approved (so an approved request exists for 8.8.8.8).
    r = c.post(
        "/mitigation/requests",
        json={"alert_id": env["alert_id"], "target_ip": "8.8.8.8"},
        headers=env["analyst_h"],
    )
    rid = r.json()["id"]
    _backdate_request(rid, seconds_ago=10)

    block_ok = {"ok": True, "ip": "8.8.8.8", "rule_name": "AI-IDS Block 8.8.8.8",
                "stdout": "Ok.", "stderr": "", "error": None}
    with patch.object(firewall, "block_ip", return_value=block_ok):
        c.post(f"/mitigation/requests/{rid}/approve", json={}, headers=env["admin_h"])

    unblock_ok = {"ok": True, "ip": "8.8.8.8", "rule_name": "AI-IDS Block 8.8.8.8",
                  "stdout": "Deleted 1 rule(s).", "stderr": "", "error": None}
    with patch.object(firewall, "unblock_ip", return_value=unblock_ok) as mock_unblock:
        r = c.post(
            "/mitigation/unblock",
            json={"ip": "8.8.8.8", "reason": "false positive"},
            headers=env["admin_h"],
        )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["action"]["action_type"] == "unblock"
    assert body["action"]["status"] == "success"
    assert body["action"]["request_id"] == rid       # linked to the approved request
    assert body["unblock_result"]["ok"] is True
    mock_unblock.assert_called_once()

    unblock_audits = _audit_rows(action="mitigation.unblock.execute", status_="success")
    assert len(unblock_audits) == 1


# ── V11: GET /mitigation/requests ordering + usernames + filter ───
def test_v11_list_requests_ordered_with_usernames_and_filter(env):
    c = env["client"]

    # 3 requests, manually set distinct timestamps.
    conn = db.get_conn()
    try:
        base = datetime.now(timezone.utc)
        for i, target in enumerate(["1.1.1.1", "8.8.8.8", "9.9.9.9"]):
            ts = (base - timedelta(seconds=(3 - i) * 10)).strftime(
                "%Y-%m-%dT%H:%M:%S.%f"
            ) + "Z"
            conn.execute(
                "INSERT INTO mitigation_request "
                "(alert_id, target_ip, requested_by, requested_at, status) "
                "VALUES (?, ?, ?, ?, 'pending')",
                (env["alert_id"], target, env["analyst_id"], ts),
            )
    finally:
        conn.close()

    # Mark one as approved by admin so the joined username appears.
    conn = db.get_conn()
    try:
        decided_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        conn.execute(
            "UPDATE mitigation_request "
            "   SET status='approved', decided_by=?, decided_at=? "
            " WHERE target_ip='1.1.1.1'",
            (env["admin_id"], decided_ts),
        )
    finally:
        conn.close()

    r = c.get("/mitigation/requests", headers=env["analyst_h"])
    assert r.status_code == 200, r.text
    rows = r.json()
    assert len(rows) == 3
    # newest first
    ips_in_order = [row["target_ip"] for row in rows]
    assert ips_in_order == ["9.9.9.9", "8.8.8.8", "1.1.1.1"]
    # username join present
    for row in rows:
        assert row["requested_by_username"] == "analyst1"
    approved_row = next(r for r in rows if r["target_ip"] == "1.1.1.1")
    assert approved_row["decided_by_username"] == "admin1"

    # Status filter.
    r = c.get("/mitigation/requests?status=pending", headers=env["analyst_h"])
    assert r.status_code == 200
    pending = r.json()
    assert {row["target_ip"] for row in pending} == {"8.8.8.8", "9.9.9.9"}


# ── V12: GET /mitigation/blocked returns enriched ledger ──────────
def test_v12_blocked_endpoint_enriches_ledger_with_db(env):
    c = env["client"]
    # Set up: pending -> approved so the mitigation_action lookup finds a row.
    r = c.post(
        "/mitigation/requests",
        json={"alert_id": env["alert_id"], "target_ip": "8.8.8.8"},
        headers=env["analyst_h"],
    )
    rid = r.json()["id"]
    _backdate_request(rid, seconds_ago=10)

    block_ok = {"ok": True, "ip": "8.8.8.8", "rule_name": "AI-IDS Block 8.8.8.8",
                "stdout": "Ok.", "stderr": "", "error": None}
    with patch.object(firewall, "block_ip", return_value=block_ok):
        c.post(f"/mitigation/requests/{rid}/approve", json={}, headers=env["admin_h"])

    fake_ledger = [{
        "ip": "8.8.8.8",
        "rule_name": "AI-IDS Block 8.8.8.8",
        "blocked_at": "2026-05-25T12:00:00.000000Z",
    }]
    with patch.object(firewall, "list_blocked_ips", return_value=fake_ledger):
        r = c.get("/mitigation/blocked", headers=env["admin_h"])
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body) == 1
    entry = body[0]
    assert entry["ip"] == "8.8.8.8"
    assert entry["rule_name"] == "AI-IDS Block 8.8.8.8"
    assert entry["blocked_at"] == "2026-05-25T12:00:00.000000Z"
    assert entry["request_id"] == rid
    assert entry["approved_by_username"] == "admin1"
