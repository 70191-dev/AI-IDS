"""User Management page — admin-only.

Streamlit's built-in `pages/` mechanism auto-discovers this file and
renders it in the sidebar nav. The page name shown there is "Users"
(Streamlit strips the leading "1_" prefix).

Visibility is OPTION X (defense-in-depth): an analyst will still see
"Users" in the sidebar but a click hits the require_login + permission
check below and gets a hard "Admin only" stop. See CHANGES.md for the
recorded limitation.

Phase 2 redesign: re-styled to match the SOC console palette and to
foreground "who can do what" — role badges, self-badge, disabled badge.
Workflow is identical (same endpoints, same fields).
"""

import html
import re
import pandas as pd
import streamlit as st

from dashboard.auth_ui import require_login, api_request

st.set_page_config(page_title="AI-IDS | Users", layout="wide")

# ── Theme (matches dashboard/app.py SOC palette) ─────────────
USERS_CSS = """
<style>
body, .stApp { background-color: #0f1419; color: #d4dae3; }
section.main { background-color: #0f1419; }
header[data-testid="stHeader"] { background: transparent !important; }
#MainMenu, footer, .stDeployButton { display: none !important; }

/* Match dashboard scanline texture for visual continuity. */
.stApp::before {
    content: ""; position: fixed; inset: 0; pointer-events: none;
    background-image: repeating-linear-gradient(
        180deg,
        rgba(255,255,255,0.012) 0px,
        rgba(255,255,255,0.012) 1px,
        transparent 1px,
        transparent 3px
    );
    z-index: 0;
}
section.main > div { position: relative; z-index: 1; }

h1, h2, h3 { color: #e6ecf3; font-weight: 600; letter-spacing: -0.2px; }
h1 { font-size: 22px; }
h2 { font-size: 17px; }
h3 { font-size: 13px; text-transform: uppercase; letter-spacing: 0.6px; color: #8aa6c4; }

hr { border-color: #2a3441 !important; opacity: 0.7; }

div[data-testid="stAlert"] {
    background: #151b23 !important;
    border-color: #2a3441 !important;
    color: #d4dae3 !important;
    border-radius: 6px;
}

.stButton > button {
    background: #1c2530; color: #e6ecf3; border: 1px solid #2a3441;
    font-weight: 500;
    transition: background-color 0.15s ease, border-color 0.15s ease,
                transform 0.10s ease;
}
.stButton > button:hover { background: #243040; border-color: #3b4759; color: #ffffff; }
.stButton > button:active { transform: translateY(1px); }

section[data-testid="stSidebar"] {
    background: #0c1218; border-right: 1px solid #2a3441;
}

div[data-testid="stDataFrame"] {
    border: 1px solid #2a3441; border-radius: 6px;
    transition: border-color 0.18s ease;
}
div[data-testid="stDataFrame"]:hover { border-color: #3b4759; }

/* Expander chrome — subtle hover to make the manage-user rows feel
   clickable rather than static blocks. */
div[data-testid="stExpander"] {
    border: 1px solid #2a3441;
    border-radius: 6px;
    background: #131922;
    transition: border-color 0.18s ease, box-shadow 0.18s ease;
    margin-bottom: 8px;
}
div[data-testid="stExpander"]:hover {
    border-color: #3b4759;
    box-shadow: 0 4px 12px rgba(0,0,0,0.30);
}

.chip {
    display: inline-block; padding: 2px 9px; border-radius: 3px;
    font-size: 11px; font-weight: 600; letter-spacing: 0.3px;
}
.chip-red    { background: rgba(239,68,68,0.16);  color: #f87171; border: 1px solid rgba(239,68,68,0.35); }
.chip-amber  { background: rgba(245,158,11,0.16); color: #fbbf24; border: 1px solid rgba(245,158,11,0.35); }
.chip-teal   { background: rgba(20,184,166,0.16); color: #5eead4; border: 1px solid rgba(20,184,166,0.35); }
.chip-blue   { background: rgba(59,130,246,0.16); color: #93c5fd; border: 1px solid rgba(59,130,246,0.35); }
.chip-slate  { background: rgba(148,163,184,0.14); color: #cbd5e1; border: 1px solid rgba(148,163,184,0.30); }
</style>
"""
st.markdown(USERS_CSS, unsafe_allow_html=True)

session = require_login()
if "users.write" not in session["permissions"]:
    st.error("Admin only — you don't have permission to view this page.")
    st.stop()

st.markdown("<h1>User Management</h1>", unsafe_allow_html=True)
st.caption(
    "Create accounts, edit roles, reset passwords, disable / re-enable. "
    "Every action below is recorded in the Audit Log with the actor and source IP."
)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
PASSWORD_MIN_LEN = 12
ROLES = ("analyst", "admin")


# ── Fetch users ───────────────────────────────────────────────
code, users = api_request("GET", "/users")
if code != 200 or not isinstance(users, list):
    st.error(f"Failed to load users (status={code}): {users}")
    st.stop()


# ── User list ─────────────────────────────────────────────────
st.markdown("### Current users")
if users:
    df = pd.DataFrame(users)[[
        "id", "username", "role", "created_at", "created_by",
        "disabled_at", "last_login_at",
    ]]
    st.dataframe(df, hide_index=True, use_container_width=True)
else:
    st.info("No users yet.")


st.markdown("<hr/>", unsafe_allow_html=True)


# ── Create user ───────────────────────────────────────────────
st.markdown("### Create new user")
with st.expander("Create new user", expanded=False):
    with st.form("create_user_form", clear_on_submit=True):
        new_username = st.text_input("Username", help="3-32 chars, [A-Za-z0-9_]")
        new_password = st.text_input("Password", type="password",
                                     help=f"At least {PASSWORD_MIN_LEN} chars")
        new_confirm  = st.text_input("Confirm password", type="password")
        new_role     = st.selectbox("Role", ROLES, index=0)
        submitted    = st.form_submit_button("Create user")

    if submitted:
        if not USERNAME_RE.fullmatch(new_username or ""):
            st.error("Username must be 3-32 characters of [A-Za-z0-9_].")
        elif len(new_password) < PASSWORD_MIN_LEN:
            st.error(f"Password must be at least {PASSWORD_MIN_LEN} characters.")
        elif new_password != new_confirm:
            st.error("Passwords do not match.")
        else:
            code, body = api_request(
                "POST", "/users",
                json={"username": new_username, "password": new_password, "role": new_role},
            )
            if 200 <= code < 300:
                st.success(f"Created user '{new_username}' (id={body.get('id')}).")
                st.rerun()
            else:
                detail = (body or {}).get("detail", body)
                st.error(f"Create failed ({code}): {detail}")


st.markdown("<hr/>", unsafe_allow_html=True)

# ── Per-user actions ──────────────────────────────────────────
st.markdown("### Manage existing users")
my_id = session.get("user_id")

for u in users:
    uid = u["id"]
    is_self = (uid == my_id)
    disabled_at = u.get("disabled_at")
    is_disabled = disabled_at is not None

    chips = []
    role_class = "chip-teal" if u["role"] == "admin" else "chip-blue"
    chips.append(f'<span class="chip {role_class}">{html.escape(u["role"]).upper()}</span>')
    if is_self:
        chips.append('<span class="chip chip-amber">YOU</span>')
    if is_disabled:
        chips.append('<span class="chip chip-red">DISABLED</span>')

    header_html = (
        f"{html.escape(u['username'])} &nbsp; " + " ".join(chips)
    )
    # Streamlit's expander label doesn't honor HTML, so put the chips
    # inside the expander as a header instead, and use a plain text label.
    badge_summary = []
    if is_self: badge_summary.append("you")
    if is_disabled: badge_summary.append("disabled")
    suffix = f"  ({', '.join(badge_summary)})" if badge_summary else ""

    with st.expander(f"Manage {u['username']} — {u['role']}{suffix}", expanded=False):
        st.markdown(header_html, unsafe_allow_html=True)
        st.markdown("")

        # ── Change role ───────────────────────────
        st.markdown("**Change role**")
        rc1, rc2 = st.columns([2, 1])
        new_role = rc1.selectbox(
            "Role", ROLES,
            index=ROLES.index(u["role"]) if u["role"] in ROLES else 0,
            key=f"role_select_{uid}",
            disabled=is_self,
        )
        if is_self:
            rc2.caption("Cannot demote yourself")
        if rc2.button("Update role", key=f"role_update_btn_{uid}", disabled=is_self):
            if new_role != u["role"]:
                code, body = api_request(
                    "PATCH", f"/users/{uid}", json={"role": new_role}
                )
                if 200 <= code < 300:
                    st.success(f"Role updated to '{new_role}'.")
                    st.rerun()
                else:
                    detail = (body or {}).get("detail", body)
                    st.error(f"Role update failed ({code}): {detail}")
            else:
                st.info("Role unchanged.")

        st.markdown("---")

        # ── Reset password ────────────────────────
        st.markdown("**Reset password**")
        pw1 = st.text_input(
            "New password", type="password", key=f"pw_new_{uid}",
            help=f"At least {PASSWORD_MIN_LEN} chars",
        )
        pw2 = st.text_input(
            "Confirm new password", type="password", key=f"pw_confirm_{uid}",
        )
        if st.button("Reset password", key=f"pw_reset_btn_{uid}"):
            if len(pw1) < PASSWORD_MIN_LEN:
                st.error(f"Password must be at least {PASSWORD_MIN_LEN} chars.")
            elif pw1 != pw2:
                st.error("Passwords do not match.")
            else:
                code, body = api_request(
                    "PATCH", f"/users/{uid}", json={"password": pw1}
                )
                if 200 <= code < 300:
                    st.success("Password reset.")
                    st.rerun()
                else:
                    detail = (body or {}).get("detail", body)
                    st.error(f"Password reset failed ({code}): {detail}")

        st.markdown("---")

        # ── Disable / enable ──────────────────────
        st.markdown("**Account status**")
        if is_disabled:
            st.caption(f"Disabled at {disabled_at}.")
            if st.button("Re-enable user", key=f"enable_btn_{uid}"):
                code, body = api_request(
                    "PATCH", f"/users/{uid}", json={"disabled": False}
                )
                if 200 <= code < 300:
                    st.success(f"User '{u['username']}' re-enabled.")
                    st.rerun()
                else:
                    detail = (body or {}).get("detail", body)
                    st.error(f"Re-enable failed ({code}): {detail}")
        else:
            if is_self:
                st.caption("Cannot disable yourself.")
            if st.button("Disable user", key=f"disable_btn_{uid}", disabled=is_self):
                code, body = api_request(
                    "PATCH", f"/users/{uid}", json={"disabled": True}
                )
                if 200 <= code < 300:
                    st.success(f"User '{u['username']}' disabled. "
                               "Their active sessions were revoked.")
                    st.rerun()
                else:
                    detail = (body or {}).get("detail", body)
                    st.error(f"Disable failed ({code}): {detail}")
