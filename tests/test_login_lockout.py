"""W4-Sub4d tests for the C3 login hardening in src/serve/auth_routes.py.

Covers the two new behaviours:
  - timing equalization: the missing-user path invokes a dummy bcrypt
    verify so response time does not leak username existence;
  - per-user lockout: 5 failed attempts lock the account for 15 minutes,
    and a successful login resets the counter atomically.

No real netsh, no ML model load. A tempfile SQLite DB is bound via the
IDS_DB_PATH env var BEFORE importing src.utils.db (same pattern as
tests/test_mitigation_routes.py). A FastAPI app mounting only the auth
router is built per fixture.
"""

import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

# ── Bind a tempfile DB BEFORE importing src.utils.db ──────────────
_TMPDIR = Path(tempfile.mkdtemp(prefix="aiids_w4sub4d_"))
os.environ["IDS_DB_PATH"] = str(_TMPDIR / "test.db")
os.environ.pop("MITIGATION_ALLOW_PRIVATE", None)

# Make project root importable
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from src.utils import db  # noqa: E402
from src.auth.passwords import hash_password  # noqa: E402
from src.serve.auth_routes import router as auth_router  # noqa: E402


# ── Schema bootstrap (idempotent; creates login_attempts) ─────────
db.init_db()

_USERNAME = "lockout_user"
_PASSWORD = "password1234"
_WRONG = "wrong_password_xx"


def _wipe_all():
    """Clear the tables these tests touch. FK-safe order."""
    conn = db.get_conn()
    try:
        conn.execute("PRAGMA foreign_keys = OFF")
        for table in ("login_attempts", "audit_log", "session", "user"):
            conn.execute(f"DELETE FROM {table}")
            conn.execute(f"DELETE FROM sqlite_sequence WHERE name='{table}'")
        conn.execute("PRAGMA foreign_keys = ON")
    finally:
        conn.close()


def _seed_user(username: str = _USERNAME, password: str = _PASSWORD) -> int:
    now = datetime.now().isoformat(timespec="seconds")
    conn = db.get_conn()
    try:
        cur = conn.execute(
            "INSERT INTO user (username, password_hash, role, created_at) "
            "VALUES (?, ?, 'analyst', ?)",
            (username, hash_password(password), now),
        )
        return cur.lastrowid
    finally:
        conn.close()


def _audit_rows(action=None):
    conn = db.get_conn()
    try:
        if action is not None:
            rows = conn.execute(
                "SELECT * FROM audit_log WHERE action = ? ORDER BY id ASC",
                (action,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY id ASC"
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@pytest.fixture
def client():
    """Fresh DB state + a TestClient mounting only the auth router."""
    _wipe_all()
    app = FastAPI()
    app.include_router(auth_router)
    return TestClient(app)


# ── Test 1: missing-user path runs the dummy verify ───────────────
def test_missing_user_triggers_dummy_hash_verify(client):
    # Patch at the usage site (auth_routes imports the name directly), so
    # the call is actually observed. Asserts the code path, not wall-clock
    # timing — won't flake on slow CI.
    with patch("src.serve.auth_routes.verify_dummy_for_timing") as mock_dummy:
        r = client.post("/auth/login", json={
            "username": "no_such_user",
            "password": "irrelevant1234",
        })
    assert r.status_code == 401, r.text
    assert r.json()["detail"] == "Invalid credentials"
    assert mock_dummy.call_count == 1


# ── Test 2: lockout after the threshold ───────────────────────────
def test_lockout_after_threshold(client):
    _seed_user()

    for i in range(5):
        r = client.post("/auth/login", json={
            "username": _USERNAME, "password": _WRONG,
        })
        assert r.status_code == 401, f"attempt {i}: {r.text}"

    # 6th attempt with the CORRECT password must still be rejected: the
    # account is locked, so the password is never even checked.
    r = client.post("/auth/login", json={
        "username": _USERNAME, "password": _PASSWORD,
    })
    assert r.status_code == 401, r.text
    assert r.json()["detail"] == "Invalid credentials"

    locked_rows = _audit_rows(action="auth.login.locked")
    assert len(locked_rows) >= 1, "expected at least one auth.login.locked audit row"


# ── Test 3: a successful login resets the failure counter ─────────
def test_successful_login_resets_counter(client):
    _seed_user()

    # 4 failures — one below the threshold, so no lock yet.
    for i in range(4):
        r = client.post("/auth/login", json={
            "username": _USERNAME, "password": _WRONG,
        })
        assert r.status_code == 401, f"pre-reset attempt {i}: {r.text}"

    # Correct password succeeds and resets the counter.
    r = client.post("/auth/login", json={
        "username": _USERNAME, "password": _PASSWORD,
    })
    assert r.status_code == 200, r.text

    # 4 more failures. If the counter had NOT reset, 4 + 4 = 8 >= 5 would
    # have locked the account. Because it reset, we are at 4 again.
    for i in range(4):
        r = client.post("/auth/login", json={
            "username": _USERNAME, "password": _WRONG,
        })
        assert r.status_code == 401, f"post-reset attempt {i}: {r.text}"

    # Still not locked: the correct password is accepted.
    r = client.post("/auth/login", json={
        "username": _USERNAME, "password": _PASSWORD,
    })
    assert r.status_code == 200, r.text
