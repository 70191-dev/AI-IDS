"""Streamlit login flow + bearer-token-aware API client.

Imported by dashboard/app.py (and the dashboard/pages/* admin pages in
sub-task 5). All UI auth state lives in st.session_state["auth"]:

    st.session_state["auth"] = {
        "token":       <opaque session token>,
        "username":    <str>,
        "role":        "admin" | "analyst",
        "permissions": [<perm strings>],
        "expires_at":  <ISO-8601 local time string>,
    }

The /auth/me lookup happens once at login and the permissions are cached
into session_state, so per-render checks like
`"capture.control" in session["permissions"]` don't roundtrip the API.
"""

import base64
from pathlib import Path

import requests
import streamlit as st
from datetime import datetime
from typing import Optional

API_BASE = "http://127.0.0.1:8000"
_SESSION_KEY = "auth"
_ICON_PATH = Path(__file__).resolve().parent.parent / "assets" / "icon_login.png"
_ICON_FALLBACK = Path(__file__).resolve().parent.parent / "assets" / "icon.png"


@st.cache_data(show_spinner=False)
def _icon_data_uri() -> Optional[str]:
    """Return a base64 data: URI for the login icon, or None if missing.

    Prefers the downscaled login PNG (assets/icon_login.png); falls back to
    the full-resolution assets/icon.png. Cached so the file is read once
    per Streamlit session.
    """
    for p in (_ICON_PATH, _ICON_FALLBACK):
        if p.exists():
            try:
                return "data:image/png;base64," + base64.b64encode(p.read_bytes()).decode("ascii")
            except Exception:
                pass
    return None


_LOGIN_CSS = """
<style>
/* Login-screen theming. Mirrors dashboard SOC palette so the brand
   feels consistent from first paint. */
body, .stApp { background-color: #0f1419; color: #d4dae3; }
section.main { background-color: #0f1419; }
header[data-testid="stHeader"] { background: transparent !important; }
#MainMenu, footer, .stDeployButton { display: none !important; }

/* Faint scanline texture (same as dashboard). */
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

h2 { color: #e6ecf3; font-weight: 600; letter-spacing: -0.2px; }

/* Themed form controls */
div[data-testid="stForm"] {
    background: #151b23;
    border: 1px solid #2a3441;
    border-radius: 8px;
    padding: 18px 20px 14px 20px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.45);
}
div[data-testid="stTextInput"] input {
    background-color: #0c1218 !important;
    color: #e6ecf3 !important;
    border: 1px solid #2a3441 !important;
    border-radius: 4px !important;
}
div[data-testid="stTextInput"] input:focus {
    border-color: #3b82f6 !important;
    box-shadow: 0 0 0 1px rgba(59,130,246,0.30) !important;
}
.stButton > button, .stFormSubmitButton > button {
    background: #1c2530;
    color: #e6ecf3;
    border: 1px solid #2a3441;
    font-weight: 600;
    letter-spacing: 0.3px;
    transition: background-color 0.15s ease, border-color 0.15s ease,
                box-shadow 0.18s ease, transform 0.10s ease;
}
.stButton > button:hover, .stFormSubmitButton > button:hover {
    background: #243040;
    border-color: rgba(59,130,246,0.55);
    color: #ffffff;
    box-shadow: 0 0 12px rgba(59,130,246,0.25);
}
.stButton > button:active, .stFormSubmitButton > button:active {
    transform: translateY(1px);
}

div[data-testid="stAlert"] {
    background: #151b23 !important;
    border-color: #2a3441 !important;
    color: #d4dae3 !important;
    border-radius: 6px;
}

section[data-testid="stSidebar"] {
    background: #0c1218;
    border-right: 1px solid #2a3441;
}

/* Icon hero — slow breath glow so the brand feels alive, not static. */
@keyframes icon-glow {
    0%, 100% { filter: drop-shadow(0 0 14px rgba(59,130,246,0.30))
                       drop-shadow(0 0 26px rgba(59,130,246,0.10)); }
    50%      { filter: drop-shadow(0 0 22px rgba(59,130,246,0.55))
                       drop-shadow(0 0 42px rgba(59,130,246,0.22)); }
}
.login-icon {
    width: 124px; height: 124px;
    animation: icon-glow 5s ease-in-out infinite;
    animation-delay: -2s;
}
.login-hero {
    text-align: center;
    margin-top: 3.2em;
    margin-bottom: 0.4em;
}
.login-eyebrow {
    font-size: 11px; letter-spacing: 1.6px;
    color: #8aa6c4; font-weight: 700;
    margin-top: 14px;
}
.login-sub {
    color: #8693a8; font-size: 12px; margin-top: 2px;
}
.login-foot {
    text-align: center; color: #6b7a90;
    font-size: 11px; margin-top: 14px;
    letter-spacing: 0.3px;
}
</style>
"""


# ── Session helpers ──────────────────────────────────────────────────
def get_session() -> Optional[dict]:
    """Return the live session dict, or None if missing/expired."""
    sess = st.session_state.get(_SESSION_KEY)
    if not sess:
        return None
    expires_at = sess.get("expires_at", "")
    now_iso = datetime.now().isoformat(timespec="seconds")
    if expires_at and expires_at < now_iso:
        st.session_state.pop(_SESSION_KEY, None)
        return None
    return sess


def auth_headers() -> dict:
    sess = get_session()
    if sess and sess.get("token"):
        return {"Authorization": f"Bearer {sess['token']}"}
    return {}


def _clear_session_and_rerun():
    st.session_state.pop(_SESSION_KEY, None)
    st.rerun()


# ── API wrapper ──────────────────────────────────────────────────────
def api_request(method: str, path: str, **kwargs) -> tuple[int, Optional[dict]]:
    """Bearer-aware request wrapper.

    Returns (status_code, json_body | None). On 401 the local session
    is cleared and Streamlit re-runs (kicking the user back to login).
    Network errors return (0, None) so callers can render a toast.
    """
    headers = kwargs.pop("headers", {})
    headers = {**auth_headers(), **headers}
    timeout = kwargs.pop("timeout", 5)
    try:
        r = requests.request(
            method.upper(), f"{API_BASE}{path}",
            headers=headers, timeout=timeout, **kwargs,
        )
    except requests.RequestException:
        return 0, None

    try:
        body = r.json()
    except ValueError:
        body = {"detail": r.text} if r.text else None

    if r.status_code == 401 and get_session() is not None:
        # Token must have expired or been revoked server-side.
        _clear_session_and_rerun()

    return r.status_code, body


# ── Login flow ───────────────────────────────────────────────────────
def login_screen() -> None:
    """Render the centered login form. Stores session on success."""
    st.markdown(_LOGIN_CSS, unsafe_allow_html=True)

    icon_uri = _icon_data_uri()
    icon_html = (
        f'<img class="login-icon" src="{icon_uri}" alt="AI-IDS shield"/>'
        if icon_uri else ''
    )
    st.markdown(
        f"""
        <div class="login-hero">
          {icon_html}
          <div class="login-eyebrow">AI-IDS &middot; SOC CONSOLE</div>
          <h2 style='margin:6px 0 4px 0;'>Sign in</h2>
          <div class="login-sub">
            Two-role access &mdash; analysts request, admins approve.
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    _, mid, _ = st.columns([1, 2, 1])
    with mid:
        with st.form("login_form", clear_on_submit=False):
            username = st.text_input("Username", autocomplete="username")
            password = st.text_input("Password", type="password", autocomplete="current-password")
            submitted = st.form_submit_button("Sign in", use_container_width=True)

        if submitted:
            if not username or not password:
                st.error("Username and password are required.")
                return

            try:
                r = requests.post(
                    f"{API_BASE}/auth/login",
                    json={"username": username, "password": password},
                    timeout=5,
                )
            except requests.RequestException as e:
                st.error(f"Could not reach API: {e}")
                return

            if r.status_code == 200:
                body = r.json()
                token = body["token"]
                # Pull permissions from /auth/me so we don't have to ship
                # the permission matrix to the client.
                try:
                    me_r = requests.get(
                        f"{API_BASE}/auth/me",
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=5,
                    )
                    me = me_r.json() if me_r.ok else {}
                except requests.RequestException:
                    me = {}

                st.session_state[_SESSION_KEY] = {
                    "token":       token,
                    "username":    body.get("username", username),
                    "role":        body.get("role", "analyst"),
                    "permissions": me.get("permissions", []),
                    "expires_at":  body.get("expires_at", ""),
                    "session_id":  me.get("session_id"),
                    "user_id":     me.get("user_id"),
                }
                st.rerun()
            elif r.status_code == 401:
                st.error("Invalid credentials.")
            else:
                try:
                    detail = r.json().get("detail", r.text)
                except ValueError:
                    detail = r.text
                st.error(f"Login failed ({r.status_code}): {detail}")


def logout_button() -> None:
    """Sidebar button that revokes the server-side session and clears state."""
    if st.sidebar.button("Sign out", key="logout_btn", use_container_width=True):
        sess = get_session()
        if sess and sess.get("token"):
            try:
                requests.post(
                    f"{API_BASE}/auth/logout",
                    headers={"Authorization": f"Bearer {sess['token']}"},
                    timeout=3,
                )
            except requests.RequestException:
                pass
        st.session_state.pop(_SESSION_KEY, None)
        st.rerun()


def require_login() -> dict:
    """Gate the page on a live session. Renders login_screen + st.stop() if not."""
    sess = get_session()
    if sess is None:
        login_screen()
        st.stop()
    return sess
