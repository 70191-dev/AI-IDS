"""
AI-IDS SQLite Persistence Layer
───────────────────────────────
Maps to the proposal's Figure 4.2 ERD:
    traffic_flow ──< detection_result ──< alert ──< mitigation_record

All writes from /predict happen in a single transaction. /alerts and /stats
read from this DB.
"""

import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Project root ─────────────────────────────────────────────────
_p = Path(__file__).resolve().parent
while _p != _p.parent:
    if (_p / "env" / "requirements.txt").exists():
        break
    _p = _p.parent
else:
    _p = Path.cwd()
PROJECT_ROOT = _p

# IDS_DB_PATH lets tests / sandboxed runs target a different SQLite file
# without touching production. Default is data/ids.db at project root.
_env_db = os.environ.get("IDS_DB_PATH")
if _env_db:
    DB_PATH = Path(_env_db)
    DB_DIR = DB_PATH.parent
    DB_DIR.mkdir(parents=True, exist_ok=True)
else:
    DB_DIR = PROJECT_ROOT / "data"
    DB_DIR.mkdir(parents=True, exist_ok=True)
    DB_PATH = DB_DIR / "ids.db"

SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS traffic_flow (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                 TEXT    NOT NULL,
    flow_id            TEXT    NOT NULL,
    src_ip             TEXT,
    dst_ip             TEXT,
    src_port           INTEGER,
    dst_port           INTEGER,
    protocol           INTEGER,
    duration           REAL,
    source_mode        TEXT    NOT NULL CHECK(source_mode IN ('replay','live','manual')),
    raw_features_json  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_flow_ts     ON traffic_flow(ts);
CREATE INDEX IF NOT EXISTS idx_flow_flowid ON traffic_flow(flow_id);
CREATE INDEX IF NOT EXISTS idx_flow_src    ON traffic_flow(src_ip);

CREATE TABLE IF NOT EXISTS detection_result (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id            INTEGER NOT NULL,
    score              REAL    NOT NULL,
    label              INTEGER NOT NULL,
    label_text         TEXT    NOT NULL,
    attack_type        TEXT,
    attack_confidence  REAL,
    model_version      TEXT,
    threshold          REAL,
    created_at         TEXT    NOT NULL,
    FOREIGN KEY (flow_id) REFERENCES traffic_flow(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_det_created ON detection_result(created_at);
CREATE INDEX IF NOT EXISTS idx_det_flowid  ON detection_result(flow_id);
CREATE INDEX IF NOT EXISTS idx_det_label   ON detection_result(label);
CREATE INDEX IF NOT EXISTS idx_det_attack  ON detection_result(attack_type);

CREATE TABLE IF NOT EXISTS alert (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    detection_id  INTEGER NOT NULL,
    severity      TEXT    NOT NULL,
    status        TEXT    NOT NULL DEFAULT 'open',
    created_at    TEXT    NOT NULL,
    FOREIGN KEY (detection_id) REFERENCES detection_result(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_alert_created   ON alert(created_at);
CREATE INDEX IF NOT EXISTS idx_alert_detection ON alert(detection_id);
CREATE INDEX IF NOT EXISTS idx_alert_severity  ON alert(severity);

CREATE TABLE IF NOT EXISTS mitigation_record (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id              INTEGER NOT NULL,
    attack_type           TEXT,
    severity              TEXT,
    description           TEXT,
    recommendations_json  TEXT    NOT NULL,
    created_at            TEXT    NOT NULL,
    FOREIGN KEY (alert_id) REFERENCES alert(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_mit_created ON mitigation_record(created_at);
CREATE INDEX IF NOT EXISTS idx_mit_alert   ON mitigation_record(alert_id);

-- Week 2: auth + audit. Additive only. Does not touch the four ERD tables above.

CREATE TABLE IF NOT EXISTS user (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    username       TEXT    NOT NULL UNIQUE,
    password_hash  TEXT    NOT NULL,
    role           TEXT    NOT NULL CHECK(role IN ('admin','analyst')),
    created_at     TEXT    NOT NULL,
    created_by     INTEGER,
    disabled_at    TEXT,
    last_login_at  TEXT,
    FOREIGN KEY (created_by) REFERENCES user(id)
);
CREATE INDEX IF NOT EXISTS idx_user_username ON user(username);

CREATE TABLE IF NOT EXISTS session (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    token         TEXT    NOT NULL UNIQUE,
    user_id       INTEGER NOT NULL,
    created_at    TEXT    NOT NULL,
    expires_at    TEXT    NOT NULL,
    revoked_at    TEXT,
    last_seen_at  TEXT,
    user_agent    TEXT,
    ip_address    TEXT,
    FOREIGN KEY (user_id) REFERENCES user(id)
);
CREATE INDEX IF NOT EXISTS idx_session_token   ON session(token);
CREATE INDEX IF NOT EXISTS idx_session_user_id ON session(user_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT    NOT NULL,
    actor_user_id   INTEGER,
    actor_username  TEXT,
    action          TEXT    NOT NULL,
    target          TEXT,
    status          TEXT    NOT NULL CHECK(status IN ('success','failure')),
    detail          TEXT,
    ip_address      TEXT,
    user_agent      TEXT,
    FOREIGN KEY (actor_user_id) REFERENCES user(id)
);
CREATE INDEX IF NOT EXISTS idx_audit_ts            ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_actor_user_id ON audit_log(actor_user_id);

-- Week 3: mitigation workflow. Additive only. The Phase 1 mitigation_record
-- table above stays untouched; these tables track the request/approve/execute
-- chain that wraps it.

CREATE TABLE IF NOT EXISTS mitigation_request (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id        INTEGER NOT NULL,
    target_ip       TEXT    NOT NULL,
    reason          TEXT,
    requested_by    INTEGER NOT NULL,
    requested_at    TEXT    NOT NULL,
    status          TEXT    NOT NULL CHECK(status IN ('pending','approved','denied','expired','cancelled')),
    decided_by      INTEGER,
    decided_at      TEXT,
    decision_note   TEXT,
    FOREIGN KEY (alert_id)     REFERENCES alert(id),
    FOREIGN KEY (requested_by) REFERENCES user(id),
    FOREIGN KEY (decided_by)   REFERENCES user(id)
);
CREATE INDEX IF NOT EXISTS idx_mit_req_status       ON mitigation_request(status);
CREATE INDEX IF NOT EXISTS idx_mit_req_alert_id     ON mitigation_request(alert_id);
CREATE INDEX IF NOT EXISTS idx_mit_req_requested_by ON mitigation_request(requested_by);

CREATE TABLE IF NOT EXISTS mitigation_action (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id      INTEGER NOT NULL,
    action_type     TEXT    NOT NULL CHECK(action_type IN ('block','unblock')),
    target_ip       TEXT    NOT NULL,
    executed_by     INTEGER NOT NULL,
    executed_at     TEXT    NOT NULL,
    status          TEXT    NOT NULL CHECK(status IN ('success','failure')),
    netsh_stdout    TEXT,
    netsh_stderr    TEXT,
    error_detail    TEXT,
    FOREIGN KEY (request_id)  REFERENCES mitigation_request(id),
    FOREIGN KEY (executed_by) REFERENCES user(id)
);
CREATE INDEX IF NOT EXISTS idx_mit_action_request_id  ON mitigation_action(request_id);
CREATE INDEX IF NOT EXISTS idx_mit_action_target_ip   ON mitigation_action(target_ip);
CREATE INDEX IF NOT EXISTS idx_mit_action_executed_at ON mitigation_action(executed_at);

CREATE TABLE IF NOT EXISTS login_attempts (
    username TEXT PRIMARY KEY,
    failure_count INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    last_failure_at TEXT
);
"""


def get_conn() -> sqlite3.Connection:
    """Open a connection with FK + WAL enabled and Row factory set."""
    conn = sqlite3.connect(str(DB_PATH), timeout=10.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


def init_db() -> None:
    """Create tables/indexes if they don't exist. Idempotent."""
    conn = get_conn()
    try:
        conn.executescript(SCHEMA_DDL)
    finally:
        conn.close()


def _flow_meta_from_features(flow_id: str, features: dict) -> dict:
    """Extract IP/port/protocol fields where available. flow_id format
    is `<src_ip>-<uuid8>` for replay, `live-<uuid8>` for live capture."""
    src_ip = None
    if isinstance(flow_id, str) and "-" in flow_id:
        head = flow_id.split("-", 1)[0]
        if head != "live":
            src_ip = head
    return {
        "src_ip":   src_ip,
        "dst_ip":   features.get("dst_ip"),
        "src_port": features.get("src_port"),
        "dst_port": features.get("destination_port", features.get("dst_port")),
        "protocol": features.get("protocol"),
        "duration": features.get("flow_duration"),
    }


def insert_flow_result(
    flow_id: str,
    features: dict,
    score: float,
    label: int,
    label_text: str,
    attack_type: str,
    attack_confidence: float,
    severity: str,
    mitigation: dict,
    model_version: Optional[str],
    threshold: float,
    source_mode: str = "replay",
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    protocol: Optional[int] = None,
) -> dict:
    """
    Insert one prediction across all relevant tables in a single transaction.
    Returns dict of inserted row IDs: {flow_pk, detection_pk, alert_pk, mitigation_pk}.
    alert_pk and mitigation_pk are None for benign flows.

    Explicit src_ip/dst_ip/etc. (passed by live capture via /predict) take
    precedence over the flow_id-prefix fallback used for replay traffic.
    """
    now = datetime.now().isoformat(timespec="seconds")
    meta = _flow_meta_from_features(flow_id, features)
    if src_ip is not None:
        meta["src_ip"] = src_ip
    if dst_ip is not None:
        meta["dst_ip"] = dst_ip
    if src_port is not None:
        meta["src_port"] = src_port
    if dst_port is not None:
        meta["dst_port"] = dst_port
    if protocol is not None:
        meta["protocol"] = protocol

    conn = get_conn()
    try:
        conn.execute("BEGIN")

        cur = conn.execute(
            """INSERT INTO traffic_flow
                 (ts, flow_id, src_ip, dst_ip, src_port, dst_port, protocol,
                  duration, source_mode, raw_features_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                now, flow_id,
                meta["src_ip"], meta["dst_ip"],
                meta["src_port"], meta["dst_port"],
                meta["protocol"], meta["duration"],
                source_mode,
                json.dumps(features, default=float),
            ),
        )
        flow_pk = cur.lastrowid

        cur = conn.execute(
            """INSERT INTO detection_result
                 (flow_id, score, label, label_text, attack_type,
                  attack_confidence, model_version, threshold, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                flow_pk, float(score), int(label), label_text,
                attack_type or None,
                float(attack_confidence) if attack_confidence else 0.0,
                model_version, float(threshold), now,
            ),
        )
        detection_pk = cur.lastrowid

        alert_pk = None
        mitigation_pk = None
        if int(label) == 1:
            cur = conn.execute(
                """INSERT INTO alert (detection_id, severity, status, created_at)
                   VALUES (?, ?, 'open', ?)""",
                (detection_pk, severity, now),
            )
            alert_pk = cur.lastrowid

            cur = conn.execute(
                """INSERT INTO mitigation_record
                     (alert_id, attack_type, severity, description,
                      recommendations_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    alert_pk,
                    mitigation.get("attack_type", attack_type),
                    severity,
                    mitigation.get("description", ""),
                    json.dumps(mitigation.get("recommendations", [])),
                    now,
                ),
            )
            mitigation_pk = cur.lastrowid

        conn.execute("COMMIT")
        return {
            "flow_pk": flow_pk,
            "detection_pk": detection_pk,
            "alert_pk": alert_pk,
            "mitigation_pk": mitigation_pk,
        }
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def fetch_recent_alerts(limit: int = 200) -> list:
    """Return the most recent detections (attacks + benign) as alert rows
    suitable for the dashboard. Joins all four tables."""
    limit = max(1, min(int(limit), 1000))
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT
                d.created_at         AS time,
                f.flow_id            AS flow_id,
                f.src_ip             AS src_ip,
                a.id                 AS alert_id,
                d.score              AS score,
                d.label_text         AS label,
                d.attack_type        AS attack_type,
                COALESCE(a.severity,'None') AS severity,
                f.dst_port           AS dst_port,
                f.source_mode        AS source_mode
            FROM detection_result d
            JOIN traffic_flow     f ON f.id = d.flow_id
            LEFT JOIN alert       a ON a.detection_id = d.id
            ORDER BY d.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def fetch_stats() -> dict:
    """Aggregate counts straight from SQL — source of truth."""
    conn = get_conn()
    try:
        total_flows   = conn.execute("SELECT COUNT(*) FROM detection_result").fetchone()[0]
        total_attacks = conn.execute("SELECT COUNT(*) FROM detection_result WHERE label = 1").fetchone()[0]
        total_benign  = total_flows - total_attacks

        attack_rows = conn.execute(
            """SELECT attack_type, COUNT(*) AS n
               FROM detection_result
               WHERE label = 1 AND attack_type IS NOT NULL AND attack_type <> ''
               GROUP BY attack_type
               ORDER BY n DESC"""
        ).fetchall()
        attack_types = {r["attack_type"]: r["n"] for r in attack_rows}

        sev_rows = conn.execute(
            """SELECT severity, COUNT(*) AS n
               FROM alert
               GROUP BY severity
               ORDER BY n DESC"""
        ).fetchall()
        severity_counts = {r["severity"]: r["n"] for r in sev_rows}

        first_seen = conn.execute(
            "SELECT MIN(created_at) AS t FROM detection_result"
        ).fetchone()["t"]

        return {
            "total_flows": total_flows,
            "total_attacks": total_attacks,
            "total_benign": total_benign,
            "attack_rate_pct": round(total_attacks / total_flows * 100, 1) if total_flows else 0,
            "attack_types": attack_types,
            "severity_counts": severity_counts,
            "uptime_since": first_seen,
        }
    finally:
        conn.close()


def table_counts() -> dict:
    """Diagnostic helper used by the smoke test."""
    conn = get_conn()
    try:
        out = {}
        for t in ("traffic_flow", "detection_result", "alert", "mitigation_record"):
            out[t] = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        return out
    finally:
        conn.close()
