"""Central audit-log writer.

Every endpoint, RBAC denial, and bootstrap step writes through this
function so the audit_log schema lives in one place.
"""

import sqlite3
from datetime import datetime
from typing import Optional


def log_audit(
    conn: sqlite3.Connection,
    *,
    actor_user_id: Optional[int],
    actor_username: Optional[str],
    action: str,
    target: Optional[str],
    status: str,
    detail: Optional[str] = None,
    ip: Optional[str] = None,
    ua: Optional[str] = None,
) -> int:
    if status not in ("success", "failure"):
        raise ValueError(f"audit status must be 'success' or 'failure', got {status!r}")

    ts = datetime.now().isoformat(timespec="seconds")
    cur = conn.execute(
        """INSERT INTO audit_log
             (ts, actor_user_id, actor_username, action, target,
              status, detail, ip_address, user_agent)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (ts, actor_user_id, actor_username, action, target, status, detail, ip, ua),
    )
    return cur.lastrowid
