"""W4-Sub4a smoke test for end-to-end API wiring.

Boots the FastAPI app (src.serve.app) in-process via FastAPI's
TestClient, exercises the auth → predict → mitigation → audit
chain, and confirms all nine SQLite tables are present.

Real netsh is never invoked — `firewall.block_ip` is patched.
Real packet capture is never started. Real elevation is not
required: the loopback gate on /predict is satisfied by the
TestClient itself.

Pattern (env-var-before-import + defensive DB_PATH override)
mirrors tests/test_mitigation_routes.py for consistency.
"""

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

# ── Bind a tempfile DB BEFORE importing src.utils.db ──────────────
_TMPDIR = Path(tempfile.mkdtemp(prefix="aiids_smoke_"))
_SMOKE_DB = _TMPDIR / "smoke.db"
os.environ["IDS_DB_PATH"] = str(_SMOKE_DB)
# HARD_CONSTRAINTS default: private-IP override OFF. Smoke uses 8.8.8.8.
os.environ.pop("MITIGATION_ALLOW_PRIVATE", None)

# Make project root importable.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from src.utils import db  # noqa: E402
# Note: if another test module (e.g., test_mitigation_routes.py)
# imported `db` before us, its env-var won and `db.DB_PATH` already
# points to that test's tmpdir. That's fine — we share the same
# test-mode DB; our lifespan's idempotent init_db() ensures tables
# exist, and we seed under unique usernames so no collisions.

from src.serve.app import app  # noqa: E402  (imports must follow DB rebind)
from src.mitigation import firewall  # noqa: E402


# ── Test-only seeding helpers (no production code involved) ───────
def _seed_users() -> dict:
    """Insert one admin and one analyst directly via the auth helpers.

    Returns {admin_id, analyst_id, admin_username, analyst_username,
    password}. Passwords are plaintext for the test; bcrypt happens
    inside hash_password() so the runtime path is real.
    """
    from src.auth.passwords import hash_password
    from datetime import datetime

    password = "smoke-pass-1234"
    now = datetime.now().isoformat(timespec="seconds")
    pw_hash = hash_password(password)

    conn = db.get_conn()
    try:
        cur = conn.execute(
            "INSERT INTO user (username, password_hash, role, created_at) "
            "VALUES (?, ?, 'admin', ?)",
            ("smoke_admin", pw_hash, now),
        )
        admin_id = cur.lastrowid
        cur = conn.execute(
            "INSERT INTO user (username, password_hash, role, created_at) "
            "VALUES (?, ?, 'analyst', ?)",
            ("smoke_analyst", pw_hash, now),
        )
        analyst_id = cur.lastrowid
    finally:
        conn.close()

    return {
        "admin_id":         admin_id,
        "analyst_id":       analyst_id,
        "admin_username":   "smoke_admin",
        "analyst_username": "smoke_analyst",
        "password":         password,
    }


def _seed_alert(src_ip: str = "8.8.8.8") -> int:
    """Insert one traffic_flow → detection_result → alert chain so a
    mitigation request can attach to alert_id. Returns alert_id."""
    from datetime import datetime

    now = datetime.now().isoformat(timespec="seconds")
    conn = db.get_conn()
    try:
        cur = conn.execute(
            "INSERT INTO traffic_flow "
            "  (ts, flow_id, src_ip, source_mode, raw_features_json) "
            "VALUES (?, 'smoke-flow-1', ?, 'manual', '{}')",
            (now, src_ip),
        )
        flow_pk = cur.lastrowid
        cur = conn.execute(
            "INSERT INTO detection_result "
            "  (flow_id, score, label, label_text, attack_type, "
            "   attack_confidence, model_version, threshold, created_at) "
            "VALUES (?, 0.92, 1, 'Attack', 'DoS', 0.95, 'smoke', 0.5, ?)",
            (flow_pk, now),
        )
        det_pk = cur.lastrowid
        cur = conn.execute(
            "INSERT INTO alert (detection_id, severity, status, created_at) "
            "VALUES (?, 'High', 'open', ?)",
            (det_pk, now),
        )
        return cur.lastrowid
    finally:
        conn.close()


# ── Session-scoped fixture: one app boot, one DB ─────────────────
@pytest.fixture(scope="module")
def smoke_client():
    """Boot the real FastAPI app in-process. Lifespan loads models
    and calls db.init_db() against our tmp DB.

    `client=("127.0.0.1", 0)` makes request.client.host == "127.0.0.1"
    inside handlers so the /predict loopback gate (which inspects
    socket-level host, not X-Forwarded-For) accepts our requests as
    legitimate machine-to-machine callers.
    """
    with TestClient(app, client=("127.0.0.1", 0)) as client:
        yield client


# ── Assertion 1 + 6 combined: boot + table inventory ─────────────
def test_smoke_app_boots_and_health_ok(smoke_client):
    """A1: App boots, /health 200, admin_elevated key present
    (value can be True or False — depends on test runner)."""
    r = smoke_client.get("/health")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ok"
    assert "admin_elevated" in body
    assert body["model_binary"] is True   # lifespan loaded the binary head
    assert "db_path" in body


def test_smoke_all_tables_present():
    """A6: All nine ERD/auth/mitigation tables exist in the SQLite
    file after the lifespan has run init_db()."""
    expected = {
        # Phase 1 ERD
        "traffic_flow", "detection_result", "alert", "mitigation_record",
        # Week 2 auth
        "user", "session", "audit_log",
        # Week 3 mitigation
        "mitigation_request", "mitigation_action",
    }
    conn = db.get_conn()
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    finally:
        conn.close()
    present = {r["name"] for r in rows}
    missing = expected - present
    assert not missing, f"missing tables: {missing}; present: {present}"


# ── Assertions 2–5: full chain in one test ───────────────────────
def test_smoke_full_chain_auth_predict_mitigation_audit(smoke_client):
    seeded = _seed_users()
    alert_id = _seed_alert("8.8.8.8")

    # ── A2: auth ───────────────────────────────────────────────
    r = smoke_client.post("/auth/login", json={
        "username": seeded["admin_username"],
        "password": seeded["password"],
    })
    assert r.status_code == 200, r.text
    admin_login = r.json()
    assert "token" in admin_login
    assert admin_login["role"] == "admin"
    admin_token = admin_login["token"]
    admin_h = {"Authorization": f"Bearer {admin_token}"}

    r = smoke_client.get("/auth/me", headers=admin_h)
    assert r.status_code == 200, r.text
    me = r.json()
    assert me["role"] == "admin"
    assert me["user_id"] == seeded["admin_id"]

    r = smoke_client.post("/auth/login", json={
        "username": seeded["analyst_username"],
        "password": seeded["password"],
    })
    assert r.status_code == 200, r.text
    analyst_login = r.json()
    assert analyst_login["role"] == "analyst"
    analyst_token = analyst_login["token"]
    analyst_h = {"Authorization": f"Bearer {analyst_token}"}

    # ── A3: /predict (loopback satisfied by TestClient) ────────
    # Send an empty features dict — build_feature_df zero-fills
    # missing UNIFIED_FEATURES; output schema is what we assert.
    r = smoke_client.post("/predict", json={
        "flow_id": "smoke-predict-1",
        "features": {},
        "src_ip": "203.0.113.5",
    })
    assert r.status_code == 200, r.text
    pred = r.json()
    assert "label" in pred and "score" in pred
    assert pred["flow_id"] == "smoke-predict-1"
    assert 0.0 <= pred["score"] <= 1.0

    # ── A4: mitigation chain ───────────────────────────────────
    # analyst creates the request
    r = smoke_client.post(
        "/mitigation/requests",
        headers=analyst_h,
        json={"alert_id": alert_id, "target_ip": "8.8.8.8",
              "reason": "smoke test"},
    )
    assert r.status_code == 201, r.text
    req = r.json()
    request_id = req["id"]

    # admin approves — different user, so two-person window passes.
    # block_ip is patched: no real netsh.
    block_ok = {
        "ok": True, "ip": "8.8.8.8", "rule_name": "AI-IDS Block 8.8.8.8",
        "stdout": "Ok.", "stderr": "", "error": None,
    }
    with patch.object(firewall, "block_ip", return_value=block_ok) as mock_block:
        r = smoke_client.post(
            f"/mitigation/requests/{request_id}/approve",
            headers=admin_h,
            json={"note": "smoke test approval"},
        )
    assert r.status_code == 200, r.text
    approve = r.json()
    assert approve["request"]["status"] == "approved"
    assert approve["block_result"]["ok"] is True
    assert mock_block.called

    # ── A5: audit log captured the chain ───────────────────────
    r = smoke_client.get("/audit", headers=admin_h, params={"limit": 500})
    assert r.status_code == 200, r.text
    audit_rows = r.json()
    actions = [row["action"] for row in audit_rows]
    expected_actions = {
        "login",
        "user.create",                  # admin created via POST /users below — see deviation note
        "mitigation.request.create",
        "mitigation.request.approve",
        "mitigation.block.execute",
    }
    # user.create only fires if we exercise POST /users. Do that
    # now to round out the audit set.
    r = smoke_client.post("/users", headers=admin_h, json={
        "username": "smoke_extra",
        "password": "another-password-1234",
        "role": "analyst",
    })
    assert r.status_code == 200, r.text

    # re-fetch audit after the user.create
    r = smoke_client.get("/audit", headers=admin_h, params={"limit": 500})
    assert r.status_code == 200, r.text
    actions = {row["action"] for row in r.json()}
    missing = expected_actions - actions
    assert not missing, (
        f"audit log missing expected actions: {missing}; saw: {sorted(actions)}"
    )
