"""
One-time CLI to create the initial admin user.

Usage:
    python tools/bootstrap_admin.py --username <name> [--password <pw>]

If --password is omitted, the script prompts interactively (getpass).
Refuses to create a second admin if one already exists; in that case
use the /users endpoint or delete the DB.

Writes one row to `user` (role='admin', created_by=NULL) and one row
to `audit_log` (action='bootstrap_admin', status='success').
"""

import argparse
import getpass
import re
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

# Resolve project root so we can import src.utils.db regardless of CWD.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.utils import db  # noqa: E402
from src.auth.passwords import hash_password  # noqa: E402

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
PASSWORD_MIN_LEN = 12


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="bootstrap_admin",
        description="Create the initial admin user for the AI-IDS dashboard.",
    )
    p.add_argument("--username", required=True, help="3-32 chars, [A-Za-z0-9_]")
    p.add_argument(
        "--password",
        default=None,
        help=f"At least {PASSWORD_MIN_LEN} chars. If omitted, prompted interactively.",
    )
    return p.parse_args(argv)


def validate_username(username: str) -> None:
    if not USERNAME_RE.fullmatch(username):
        raise SystemExit(
            f"Invalid username '{username}'. "
            f"Must be 3-32 characters of [A-Za-z0-9_]."
        )


def validate_password(password: str) -> None:
    if len(password) < PASSWORD_MIN_LEN:
        raise SystemExit(
            f"Password too short — minimum {PASSWORD_MIN_LEN} characters."
        )


def existing_admin_username(conn: sqlite3.Connection) -> str | None:
    row = conn.execute(
        "SELECT username FROM user WHERE role = 'admin' AND disabled_at IS NULL "
        "ORDER BY id LIMIT 1"
    ).fetchone()
    return row["username"] if row else None


def create_admin(conn: sqlite3.Connection, username: str, password: str) -> int:
    now = datetime.now().isoformat(timespec="seconds")
    password_hash = hash_password(password)
    try:
        conn.execute("BEGIN")

        cur = conn.execute(
            """INSERT INTO user
                 (username, password_hash, role, created_at, created_by)
               VALUES (?, ?, 'admin', ?, NULL)""",
            (username, password_hash, now),
        )
        new_id = cur.lastrowid

        conn.execute(
            """INSERT INTO audit_log
                 (ts, actor_user_id, actor_username, action, target,
                  status, detail, ip_address, user_agent)
               VALUES (?, ?, ?, 'bootstrap_admin', ?, 'success',
                       'initial admin via CLI', NULL, NULL)""",
            (now, new_id, username, f"user:{new_id}"),
        )

        conn.execute("COMMIT")
        return new_id
    except Exception:
        conn.execute("ROLLBACK")
        raise


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    validate_username(args.username)

    password = args.password
    if password is None:
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm:  ")
        if password != confirm:
            print("Passwords do not match.", file=sys.stderr)
            return 1
    validate_password(password)

    db.init_db()
    conn = db.get_conn()
    try:
        existing = existing_admin_username(conn)
        if existing is not None:
            print(
                f"Admin user '{existing}' already exists. "
                "Delete the DB or use the /users endpoint instead.",
                file=sys.stderr,
            )
            return 1

        new_id = create_admin(conn, args.username, password)
        print(f"Created admin user '{args.username}' with id {new_id}.")
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
