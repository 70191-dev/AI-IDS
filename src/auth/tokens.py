"""Opaque server-side session tokens (NOT JWT).

32 random bytes encoded url-safe via secrets.token_urlsafe, stored in
the session table. Validation joins session -> user so a disabled
account is rejected even if its token is still otherwise valid.
"""

import secrets
import sqlite3
from datetime import datetime, timedelta
from typing import Optional

SESSION_TTL_HOURS = 8


def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def generate_token() -> str:
    return secrets.token_urlsafe(32)


def create_session(
    conn: sqlite3.Connection,
    user_id: int,
    ip: Optional[str] = None,
    ua: Optional[str] = None,
) -> dict:
    token = generate_token()
    now = datetime.now()
    expires = now + timedelta(hours=SESSION_TTL_HOURS)
    created_at = now.isoformat(timespec="seconds")
    expires_at = expires.isoformat(timespec="seconds")

    conn.execute(
        """INSERT INTO session
             (token, user_id, created_at, expires_at,
              revoked_at, last_seen_at, user_agent, ip_address)
           VALUES (?, ?, ?, ?, NULL, NULL, ?, ?)""",
        (token, user_id, created_at, expires_at, ua, ip),
    )
    return {"token": token, "expires_at": expires_at}


def validate_token(conn: sqlite3.Connection, token: str) -> Optional[dict]:
    if not token:
        return None

    row = conn.execute(
        """SELECT s.id           AS session_id,
                  s.user_id      AS user_id,
                  s.expires_at   AS expires_at,
                  s.revoked_at   AS revoked_at,
                  u.username     AS username,
                  u.role         AS role,
                  u.disabled_at  AS disabled_at
             FROM session s
             JOIN user    u ON u.id = s.user_id
            WHERE s.token = ?""",
        (token,),
    ).fetchone()

    if row is None:
        return None
    if row["revoked_at"] is not None:
        return None
    if row["disabled_at"] is not None:
        return None
    now = _now_iso()
    if row["expires_at"] < now:
        return None

    conn.execute(
        "UPDATE session SET last_seen_at = ? WHERE id = ?",
        (now, row["session_id"]),
    )
    return {
        "user_id": row["user_id"],
        "username": row["username"],
        "role": row["role"],
        "session_id": row["session_id"],
    }


def revoke_token(conn: sqlite3.Connection, token: str) -> bool:
    cur = conn.execute(
        "UPDATE session SET revoked_at = ? WHERE token = ? AND revoked_at IS NULL",
        (_now_iso(), token),
    )
    return cur.rowcount > 0


def cleanup_expired_sessions(conn: sqlite3.Connection) -> int:
    cur = conn.execute(
        "UPDATE session SET revoked_at = expires_at "
        "WHERE expires_at < ? AND revoked_at IS NULL",
        (_now_iso(),),
    )
    return cur.rowcount
