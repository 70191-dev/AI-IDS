# dashboard/app.py — SOC Console (Phase 2 redesign)
#
# Operational story: attack -> model scores -> analyst requests block ->
# admin approves -> netsh blocks -> audit log proves it. The layout below
# is structured to make that pipeline legible at a glance:
#
#   1. Live State Strip      — is the pipeline ON? (capture, replay, blocks)
#   2. Detection KPI strip   — what has the model seen?
#   3. Recent Alerts table   — operator-grade triage columns
#   4. Request Block panel   — analyst action surface
#   5. Score + sources       — secondary context
#
# Backend contract is frozen. Every call below maps to an existing
# endpoint in src/serve/{app.py,mitigation_routes.py}. No new endpoints,
# no schema changes.

import html
import socket
from pathlib import Path

import pandas as pd
import plotly.express as px
import requests
import streamlit as st
from streamlit_autorefresh import st_autorefresh

# ── Project root anchor (paths are NOT relative to CWD) ─────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ------------- CONFIG -------------
st.set_page_config(
    page_title="AI-IDS | SOC Console",
    layout="wide",
    initial_sidebar_state="auto",
)

# ------------- THEME / STYLES -------------
# Muted operational palette. Slate background, restrained accents:
#   surface  #0f1419 / #151b23 / #1c2530
#   border   #2a3441
#   text     #d4dae3 primary, #8693a8 muted
#   accents  amber (warn), red (attack), teal (ok), blue (info)
SOC_CSS = """
<style>
/*
 * Animation policy for Streamlit reruns (every 4s via st_autorefresh):
 *   - All keyframes use 0% == 100% so a mid-cycle DOM swap looks like a
 *     continuation, not a flicker.
 *   - "Live" indicators use negative animation-delay so each element
 *     starts ALREADY partway through its cycle on first paint — no
 *     dead-on-arrival opacity dip.
 *   - High-severity row emphasis is STATIC (inset box-shadow), not
 *     animated, because a once-on-render pulse would fight the 4s tick.
 */

/* ---- base ---- */
body, .stApp { background-color: #0f1419; color: #d4dae3; }
section.main { background-color: #0f1419; }
header[data-testid="stHeader"] { background: transparent !important; }
#MainMenu, footer, .stDeployButton { display: none !important; }

/* Very faint CRT scanline texture — adds depth without competing with text.
   Fixed-position so it doesn't scroll. */
.stApp::before {
    content: "";
    position: fixed;
    inset: 0;
    pointer-events: none;
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

/* ---- typography ---- */
h1, h2, h3, h4, h5, h6 { color: #e6ecf3; font-weight: 600; letter-spacing: -0.2px; }
h1 { font-size: 22px; }
h2 { font-size: 18px; }
h3 { font-size: 15px; text-transform: uppercase; letter-spacing: 0.6px; color: #8aa6c4; }
.stCaption, .stMarkdown p { color: #8693a8; }

/* ---- keyframes (all 0% == 100% so reruns don't flash) ---- */
@keyframes dot-breathe-teal {
    0%, 100% { box-shadow: 0 0 4px rgba(20,184,166,0.55), 0 0 10px rgba(20,184,166,0.18); }
    50%      { box-shadow: 0 0 8px rgba(20,184,166,0.95), 0 0 18px rgba(20,184,166,0.45); }
}
@keyframes dot-breathe-amber {
    0%, 100% { box-shadow: 0 0 4px rgba(245,158,11,0.55), 0 0 10px rgba(245,158,11,0.18); }
    50%      { box-shadow: 0 0 8px rgba(245,158,11,0.95), 0 0 18px rgba(245,158,11,0.45); }
}
@keyframes step-lit-pulse {
    0%, 100% { background: rgba(20,184,166,0.08); border-color: rgba(20,184,166,0.32); color: #5eead4; }
    50%      { background: rgba(20,184,166,0.18); border-color: rgba(20,184,166,0.70); color: #99f6e4; }
}
@keyframes badge-blocked-glow {
    0%, 100% { box-shadow: 0 0 6px rgba(20,184,166,0.30); }
    50%      { box-shadow: 0 0 12px rgba(20,184,166,0.60); }
}

/* ---- KPI cards (with subtle hover lift) ---- */
div[data-testid="stMetric"] {
    background: #151b23;
    border: 1px solid #2a3441;
    border-radius: 6px;
    padding: 10px 14px;
    transition: transform 0.18s ease,
                border-color 0.18s ease,
                box-shadow 0.18s ease;
}
div[data-testid="stMetric"]:hover {
    transform: translateY(-1px);
    border-color: #3b4759;
    box-shadow: 0 6px 16px rgba(0,0,0,0.45);
}
div[data-testid="stMetric"] label {
    color: #8aa6c4 !important;
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
div[data-testid="stMetric"] [data-testid="stMetricValue"] {
    color: #e6ecf3 !important;
    font-weight: 600;
    font-size: 22px;
}
div[data-testid="stMetric"] [data-testid="stMetricDelta"] { color: #f59e0b !important; }

/* ---- dividers ---- */
hr { border-color: #2a3441 !important; opacity: 0.7; margin: 14px 0 !important; }

/* ---- chips / badges ---- */
.chip {
    display: inline-block;
    padding: 2px 9px;
    border-radius: 3px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.3px;
    font-family: 'Segoe UI', system-ui, sans-serif;
}
.chip-red     { background: rgba(239,68,68,0.16);  color: #f87171; border: 1px solid rgba(239,68,68,0.35); }
.chip-amber   { background: rgba(245,158,11,0.16); color: #fbbf24; border: 1px solid rgba(245,158,11,0.35); }
.chip-teal    { background: rgba(20,184,166,0.16); color: #5eead4; border: 1px solid rgba(20,184,166,0.35); }
.chip-blue    { background: rgba(59,130,246,0.16); color: #93c5fd; border: 1px solid rgba(59,130,246,0.35); }
.chip-slate   { background: rgba(148,163,184,0.14); color: #cbd5e1; border: 1px solid rgba(148,163,184,0.30); }

/* Breathing "live" version of the teal chip (used for "BLOCKED" status). */
.chip-live    {
    background: rgba(20,184,166,0.18);
    color: #5eead4;
    border: 1px solid rgba(20,184,166,0.50);
    animation: badge-blocked-glow 3s ease-in-out infinite;
    animation-delay: -1s;
}

.chip-dot {
    display: inline-block;
    width: 8px; height: 8px;
    border-radius: 50%;
    margin-right: 6px;
    vertical-align: middle;
}
.dot-on {
    background: #14b8a6;
    animation: dot-breathe-teal 2.4s ease-in-out infinite;
    animation-delay: -0.7s;
}
.dot-off  { background: #4b5563; }
.dot-warn {
    background: #f59e0b;
    animation: dot-breathe-amber 2.8s ease-in-out infinite;
    animation-delay: -1.2s;
}

/* ---- state strip card ---- */
.state-card {
    background: #151b23;
    border: 1px solid #2a3441;
    border-radius: 6px;
    padding: 10px 14px;
    height: 100%;
    transition: border-color 0.18s ease, box-shadow 0.18s ease;
}
.state-card:hover {
    border-color: #3b4759;
    box-shadow: 0 4px 12px rgba(0,0,0,0.35);
}
.state-card .label {
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    color: #8aa6c4;
}
.state-card .value {
    font-size: 16px;
    font-weight: 600;
    color: #e6ecf3;
    margin-top: 4px;
}
.state-card .sub {
    font-size: 11px;
    color: #8693a8;
    margin-top: 2px;
    font-family: 'Consolas', 'Courier New', monospace;
}

/* ---- alert table ---- */
.alert-tbl {
    width: 100%;
    border-collapse: separate;
    border-spacing: 0;
    font-size: 12.5px;
    border: 1px solid #2a3441;
    border-radius: 6px;
    overflow: hidden;
    font-family: 'Segoe UI', system-ui, sans-serif;
}
.alert-tbl thead th {
    background: #1c2530;
    color: #8aa6c4;
    font-size: 10.5px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    padding: 8px 12px;
    text-align: left;
    border-bottom: 1px solid #2a3441;
    white-space: nowrap;
}
.alert-tbl tbody td {
    padding: 7px 12px;
    border-bottom: 1px solid rgba(42,52,65,0.5);
    color: #d4dae3;
    vertical-align: middle;
    transition: background-color 0.15s ease;
}
.alert-tbl tbody td.mono {
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
    color: #b8c3d1;
}
.alert-tbl tbody tr:hover td { background: rgba(28,37,48,0.7); }

/* Attack rows: stronger tint + STATIC left stripe via inset box-shadow.
   Static (not animated) on purpose — see header note: pulse + 4s rerun
   would flicker. The eye still goes to the red. */
.alert-tbl tbody tr.row-attack td {
    background: rgba(239,68,68,0.07);
}
.alert-tbl tbody tr.row-attack td:first-child {
    box-shadow: inset 3px 0 0 #ef4444;
}
.alert-tbl tbody tr.row-attack:hover td { background: rgba(239,68,68,0.12); }

/* ---- chain-of-custody mini diagram ---- */
.flow-strip {
    display: flex; gap: 6px; align-items: center;
    font-size: 11px; color: #8693a8;
    margin: 4px 0 10px 0;
}
.flow-strip .step {
    padding: 3px 9px;
    border-radius: 3px;
    background: #151b23;
    border: 1px solid #2a3441;
    color: #6b7a90;            /* idle: dim */
    letter-spacing: 0.3px;
    font-weight: 600;
    transition: color 0.25s ease, border-color 0.25s ease;
}
/* "Lit" stage: gentle breathing glow. Staggered animation-delay across
   the 6 stages creates a left-to-right wave inside the 3.2s cycle. */
.flow-strip .step.lit {
    animation: step-lit-pulse 3.2s ease-in-out infinite;
}
.flow-strip .step.lit-1 { animation-delay: -0.0s; }
.flow-strip .step.lit-2 { animation-delay: -0.5s; }
.flow-strip .step.lit-3 { animation-delay: -1.0s; }
.flow-strip .step.lit-4 { animation-delay: -1.5s; }
.flow-strip .step.lit-5 { animation-delay: -2.0s; }
.flow-strip .step.lit-6 { animation-delay: -2.5s; }
/* "Passed" stage: completed, no animation, solid teal-muted. */
.flow-strip .step.passed {
    color: #5eead4;
    background: rgba(20,184,166,0.05);
    border-color: rgba(20,184,166,0.22);
}
.flow-strip .arrow { color: #4b5563; }

/* ---- info boxes ---- */
div[data-testid="stAlert"] {
    background: #151b23 !important;
    border-color: #2a3441 !important;
    color: #8693a8 !important;
    border-radius: 6px;
}

/* ---- charts ---- */
.plotly-graph-div { background: transparent !important; }

/* ---- scrollbar ---- */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #0f1419; }
::-webkit-scrollbar-thumb { background: #2a3441; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #3b4759; }

/* ---- buttons ---- */
.stButton > button {
    background: #1c2530;
    color: #e6ecf3;
    border: 1px solid #2a3441;
    font-weight: 500;
    transition: background-color 0.15s ease,
                border-color 0.15s ease,
                transform 0.10s ease;
}
.stButton > button:hover {
    background: #243040;
    border-color: #3b4759;
    color: #ffffff;
}
.stButton > button:active { transform: translateY(1px); }

/* ---- sidebar ---- */
section[data-testid="stSidebar"] {
    background: #0c1218;
    border-right: 1px solid #2a3441;
}
section[data-testid="stSidebar"] .stMarkdown h3 { color: #8aa6c4; }
</style>
"""
st.markdown(SOC_CSS, unsafe_allow_html=True)

# ------------- AUTH GATE -------------
# Must run BEFORE any dashboard content but AFTER the page CSS so the
# login form gets the theme. require_login() either renders the login
# screen + st.stop()s, or returns the live session dict.
from dashboard.auth_ui import require_login, logout_button, api_request  # noqa: E402
session = require_login()

# Auto-refresh only AFTER auth so the login screen doesn't tick every
# 4s (which would clear the password field while the user is typing).
if not st.session_state.get("report_generating"):
    st_autorefresh(interval=4000, key="autorefresh")

# ------------- Paths / Constants -------------
API_BASE = "http://127.0.0.1:8000"
ALERTS_CSV = PROJECT_ROOT / "logs" / "alerts.csv"
TOP_N = 10

# ------------- Plotly theme (reused) -------------
PLOT_STYLE = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(21,27,35,0.6)",
    font=dict(color="#8aa6c4", size=11, family="Segoe UI, system-ui, sans-serif"),
    margin=dict(t=30, b=28, l=40, r=16),
)

# ------------- Helper functions -------------
def api_get(endpoint, timeout=2):
    """Unauthenticated GET — used only for /health and other open endpoints.
    Authenticated reads go through api_request() from auth_ui."""
    try:
        r = requests.get(f"{API_BASE}{endpoint}", timeout=timeout)
        if r.ok:
            return r.json()
    except Exception:
        pass
    return None


@st.cache_data(ttl=60)
def _get_self_ips():
    """Resolve this host's local IPv4 addresses + hostname.

    Used in the Request Block dropdown (exclude self IPs so the operator
    can't accidentally block their own host). Cached for 60s.
    """
    hostname = socket.gethostname()
    ips: set = set()
    try:
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ips.add(info[4][0])
    except Exception:
        pass
    ips.update({"127.0.0.1", "0.0.0.0"})
    return hostname, sorted(ips)


def load_alerts_csv():
    """CSV fallback when the API hot-cache is empty (cold start)."""
    if ALERTS_CSV.exists() and ALERTS_CSV.stat().st_size > 10:
        try:
            df = pd.read_csv(ALERTS_CSV)
            if "time" in df.columns:
                df["time"] = pd.to_datetime(df["time"], errors="coerce")
            return df
        except Exception:
            pass
    return pd.DataFrame(columns=["time", "flow_id", "score", "label"])


# ── Control plane helpers ──────────────────────────────────────
def show_control_error(action, status_code, body):
    """Render a friendly toast for known error shapes (admin_required, scapy_missing, etc.)."""
    detail = body.get("detail") if isinstance(body, dict) else body
    if isinstance(detail, dict) and detail.get("error") == "admin_required":
        st.error(detail.get(
            "message",
            "Live capture requires running the API as Administrator. "
            "Close and relaunch START.bat with admin rights.",
        ), icon="🛡️")
    elif isinstance(detail, dict) and detail.get("error") == "scapy_missing":
        st.error(detail.get("message", "Scapy is not installed."), icon="📦")
    else:
        st.error(f"{action} failed ({status_code}): {detail}")


def get_data():
    """Pull stats + recent alerts + health. Falls back to CSV if /alerts empty."""
    stats = api_get("/stats")
    alerts_resp = api_get("/alerts?limit=200")
    health = api_get("/health")

    alerts_df = pd.DataFrame()
    if alerts_resp and "alerts" in alerts_resp:
        alerts_df = pd.DataFrame(alerts_resp["alerts"])
        if "time" in alerts_df.columns:
            alerts_df["time"] = pd.to_datetime(alerts_df["time"], errors="coerce")

    if alerts_df.empty:
        alerts_df = load_alerts_csv()

    api_online = health is not None

    if stats is None:
        total = len(alerts_df)
        attacks = int((alerts_df["label"].isin(["Attack", 1])).sum()) if not alerts_df.empty else 0
        stats = {
            "total_flows": total,
            "total_attacks": attacks,
            "total_benign": total - attacks,
            "attack_rate_pct": round(attacks / total * 100, 1) if total else 0,
            "attack_types": {},
            "severity_counts": {},
        }
        if not alerts_df.empty and "attack_type" in alerts_df.columns:
            stats["attack_types"] = alerts_df[
                alerts_df["attack_type"].notna() & (alerts_df["attack_type"] != "")
            ]["attack_type"].value_counts().to_dict()
        if not alerts_df.empty and "severity" in alerts_df.columns:
            stats["severity_counts"] = alerts_df[
                alerts_df["severity"].notna() & (alerts_df["severity"] != "") & (alerts_df["severity"] != "None")
            ]["severity"].value_counts().to_dict()

    return stats, alerts_df, health, api_online


# ------------- Load data -------------
stats, df, health, api_online = get_data()

if "score" in df.columns:
    df["score"] = pd.to_numeric(df["score"], errors="coerce").fillna(0.0)
else:
    df["score"] = 0.0
if "label" not in df.columns:
    df["label"] = 0

# ============================================================
#  SIDEBAR — Traffic Source Control (role-gated)
# ============================================================
has_replay  = "replay.control"  in session["permissions"]
has_capture = "capture.control" in session["permissions"]

# Pull replay/capture status once here so we can both render sidebar
# controls AND feed the top "live state" strip without double-calling.
replay_status  = api_get("/replay/status")  or {} if has_replay  else (api_get("/replay/status")  or {})
capture_status = api_get("/capture/status") or {} if has_capture else (api_get("/capture/status") or {})
replay_running  = bool(replay_status.get("running"))
capture_running = bool(capture_status.get("running"))

# Active block count — every signed-in user has view.dashboard so this
# call works for analyst + admin alike.
_blocked_code, _blocked_body = api_request("GET", "/mitigation/blocked")
active_blocks = len(_blocked_body) if (_blocked_code == 200 and isinstance(_blocked_body, list)) else 0

# Pending request count — informational for analysts, actionable for admins.
_pending_code, _pending_body = api_request("GET", "/mitigation/requests?status=pending")
pending_requests = len(_pending_body) if (_pending_code == 200 and isinstance(_pending_body, list)) else 0


with st.sidebar:
    st.markdown("### Session")
    st.caption(f"User **{session['username']}** · role **{session['role']}**")
    if "users.write" in session["permissions"]:
        st.caption("→ Users (sidebar nav)")
    if "audit.read" in session["permissions"]:
        st.caption("→ Audit Log (sidebar nav)")
    if "mitigation.approve" in session["permissions"]:
        st.caption("→ Mitigation (sidebar nav)")
    logout_button()

    if has_replay or has_capture:
        st.markdown("---")
        st.markdown("### Traffic Source")

        # ── Replay toggle (admin only) ──
        if has_replay:
            dot = '<span class="chip-dot dot-on"></span>' if replay_running else '<span class="chip-dot dot-off"></span>'
            st.markdown(f"{dot} **Replay** — {'running' if replay_running else 'stopped'}", unsafe_allow_html=True)
            rc1, rc2 = st.columns(2)
            if rc1.button("Start", key="replay_start_btn", use_container_width=True, disabled=replay_running):
                code, body = api_request(
                    "POST", "/replay/start",
                    json={"rate": 5.0, "attack_ratio": 0.45},
                )
                if 200 <= code < 300:
                    st.success("Replay started")
                    st.rerun()
                else:
                    show_control_error("Replay start", code, body or {})
            if rc2.button("Stop", key="replay_stop_btn", use_container_width=True, disabled=not replay_running):
                code, body = api_request("POST", "/replay/stop")
                if 200 <= code < 300:
                    st.info("Replay stopped")
                    st.rerun()
                else:
                    show_control_error("Replay stop", code, body or {})
            if replay_running:
                st.caption(
                    f"PID {replay_status.get('pid')} · rate {replay_status.get('rate')} · "
                    f"atk {replay_status.get('attack_ratio')}"
                )

            if has_capture:
                st.markdown("---")

        # ── Live capture toggle (admin only) ──
        if has_capture:
            dot = '<span class="chip-dot dot-on"></span>' if capture_running else '<span class="chip-dot dot-off"></span>'
            st.markdown(f"{dot} **Live Capture** — {'running' if capture_running else 'stopped'}", unsafe_allow_html=True)
            iface_resp = api_get("/capture/interfaces") or {}
            ifaces_raw = iface_resp.get("interfaces", [])

            # Backward-compat: pre-W3-Sub5 the endpoint returned a list of
            # bare strings.
            ifaces = []
            for entry in ifaces_raw:
                if isinstance(entry, dict) and entry.get("id"):
                    ifaces.append(entry)
                elif isinstance(entry, str):
                    ifaces.append({"id": entry, "name": "", "description": ""})

            def _iface_label(item):
                if not item or not item.get("id"):
                    return "(none available)"
                name = item.get("name") or ""
                desc = item.get("description") or ""
                if name and desc:
                    return f"{name} — {desc}"
                if name:
                    return name
                return item["id"]

            if iface_resp.get("error"):
                st.caption(f":orange[{iface_resp['error']}]")

            if ifaces:
                selected_iface_obj = st.selectbox(
                    "Interface",
                    options=ifaces,
                    index=0,
                    format_func=_iface_label,
                    disabled=capture_running,
                    key="capture_iface_select",
                )
                selected_iface = selected_iface_obj["id"]
                selected_label = _iface_label(selected_iface_obj)
            else:
                st.selectbox(
                    "Interface",
                    options=["(none available)"],
                    index=0,
                    disabled=True,
                    key="capture_iface_select_empty",
                )
                selected_iface = None
                selected_label = "(none)"

            cc1, cc2 = st.columns(2)
            if cc1.button("Start", key="capture_start_btn", use_container_width=True,
                          disabled=capture_running or not ifaces):
                code, body = api_request(
                    "POST", "/capture/start",
                    json={"iface": selected_iface},
                )
                if 200 <= code < 300:
                    st.success(f"Capture started on {selected_label}")
                    st.rerun()
                else:
                    show_control_error("Capture start", code, body or {})
            if cc2.button("Stop", key="capture_stop_btn", use_container_width=True, disabled=not capture_running):
                code, body = api_request("POST", "/capture/stop")
                if 200 <= code < 300:
                    st.info("Capture stopped")
                    st.rerun()
                else:
                    show_control_error("Capture stop", code, body or {})
            if capture_running:
                st.caption(
                    f"iface {capture_status.get('iface') or 'auto'} · since "
                    f"{capture_status.get('started_at','')}"
                )
            st.caption(":grey[Capture needs admin + Npcap (Windows).]")


# ============================================================
#  HEADER
# ============================================================
api_dot = '<span class="chip-dot dot-on"></span>' if api_online else '<span class="chip-dot dot-off"></span>'
admin_elev = bool(health and health.get("admin_elevated"))
elev_chip = (
    '<span class="chip chip-teal">ADMIN ELEVATED</span>' if admin_elev
    else '<span class="chip chip-amber">NOT ELEVATED</span>'
)
threshold_val = (health or {}).get("threshold", 0.5)
data_source   = (health or {}).get("data_source", "unknown")
model_version = (health or {}).get("model_version", "unknown")
n_classes     = len((health or {}).get("classes") or [])

h1, h2 = st.columns([3, 2])
with h1:
    st.markdown(
        f"<h1>{api_dot} AI-IDS · SOC Console</h1>",
        unsafe_allow_html=True,
    )
    # ── Flow-strip stage activation ─────────────────────────────
    # Each stage flips on when the corresponding pipeline state is
    # observed in the data we already pulled. Every "on" stage gets the
    # pulsing "lit" class; idle stages stay dim. The CSS adds a
    # staggered (negative) animation-delay per stage index, so when
    # multiple stages are lit the eye sees a left-to-right wave inside
    # the 3.2 s cycle. When ONE stage is lit (e.g. capture-only) it
    # pulses in isolation — still calm, still on-theme.
    _capture_on  = capture_running or replay_running
    _detect_on   = stats.get("total_attacks", 0) > 0
    _request_on  = pending_requests > 0
    _approve_on  = pending_requests > 0 or active_blocks > 0
    _block_on    = active_blocks > 0
    _any_on      = _capture_on or _detect_on or _request_on or _block_on
    _audit_on    = api_online and _any_on   # everything logs once anything happens

    _stages = [
        ("CAPTURE", _capture_on),
        ("DETECT",  _detect_on),
        ("REQUEST", _request_on),
        ("APPROVE", _approve_on),
        ("BLOCK",   _block_on),
        ("AUDIT",   _audit_on),
    ]

    _strip_parts = []
    for _i, (_name, _on) in enumerate(_stages):
        _cls = f"step lit lit-{_i + 1}" if _on else "step"
        _strip_parts.append(f'<span class="{_cls}">{_name}</span>')
        if _i < len(_stages) - 1:
            _strip_parts.append('<span class="arrow">→</span>')
    st.markdown(
        '<div class="flow-strip">' + "".join(_strip_parts) + '</div>',
        unsafe_allow_html=True,
    )
with h2:
    api_chip = (
        '<span class="chip chip-teal">API ONLINE</span>' if api_online
        else '<span class="chip chip-red">API OFFLINE</span>'
    )
    st.markdown(
        f"<div style='text-align:right; padding-top:8px;'>"
        f"{api_chip} &nbsp; {elev_chip} &nbsp; "
        f"<span class='chip chip-slate'>thr {threshold_val:.3f}</span> &nbsp; "
        f"<span class='chip chip-slate'>{html.escape(str(model_version))}</span>"
        f"</div>"
        f"<div style='text-align:right; color:#8693a8; font-size:11px; margin-top:6px;'>"
        f"dataset {html.escape(str(data_source))} · {n_classes} classes · auto-refresh 4s"
        f"</div>",
        unsafe_allow_html=True,
    )

st.markdown("<hr/>", unsafe_allow_html=True)

# ============================================================
#  LIVE STATE STRIP — is the pipeline ON?
# ============================================================
st.markdown("### Live State")

def _state_card(label, value, sub, dot_class=None):
    dot = f'<span class="chip-dot {dot_class}"></span>' if dot_class else ''
    sub_html = f'<div class="sub">{html.escape(sub)}</div>' if sub else ''
    return (
        f'<div class="state-card">'
        f'<div class="label">{html.escape(label)}</div>'
        f'<div class="value">{dot}{html.escape(value)}</div>'
        f'{sub_html}'
        f'</div>'
    )

s1, s2, s3, s4, s5 = st.columns(5)

cap_dot = "dot-on" if capture_running else "dot-off"
cap_sub = f"iface {capture_status.get('iface') or '—'}" if capture_running else "no live traffic"
s1.markdown(_state_card("Live Capture", "RUNNING" if capture_running else "IDLE", cap_sub, cap_dot),
            unsafe_allow_html=True)

rep_dot = "dot-on" if replay_running else "dot-off"
rep_sub = (f"rate {replay_status.get('rate')} · atk {replay_status.get('attack_ratio')}"
           if replay_running else "no replay traffic")
s2.markdown(_state_card("Replay", "RUNNING" if replay_running else "IDLE", rep_sub, rep_dot),
            unsafe_allow_html=True)

flows_seen = stats.get("total_flows", 0)
s3.markdown(_state_card("Flows Seen", f"{flows_seen:,}", "all-time, from SQL"),
            unsafe_allow_html=True)

attacks_detected = stats.get("total_attacks", 0)
attack_rate = stats.get("attack_rate_pct", 0)
atk_dot = "dot-warn" if attacks_detected else "dot-off"
s4.markdown(_state_card("Attacks Detected", f"{attacks_detected:,}",
                        f"{attack_rate:.1f}% of flows", atk_dot),
            unsafe_allow_html=True)

block_dot = "dot-on" if active_blocks else "dot-off"
block_sub = f"{pending_requests} pending request{'s' if pending_requests != 1 else ''}"
s5.markdown(_state_card("Active Blocks", f"{active_blocks}", block_sub, block_dot),
            unsafe_allow_html=True)

st.markdown("<hr/>", unsafe_allow_html=True)

# ============================================================
#  RECENT ALERTS — triage-first columns
# ============================================================
st.markdown("### Recent Alerts")
st.caption(
    "Time · Source IP · Attack Type · Score · Severity · Alert ID. "
    "Score chip color reflects confidence vs threshold; rows tinted red are model-positive."
)

if df.empty:
    st.info("No flows yet. Start replay or live capture from the sidebar to generate traffic.")
else:
    df_recent = df.sort_values("time", ascending=False).head(200).copy()

    # Severity chip colors
    SEV_CHIP = {
        "Critical": "chip-red",
        "High":     "chip-red",
        "Medium":   "chip-amber",
        "Low":      "chip-blue",
        "None":     "chip-slate",
        "":         "chip-slate",
    }

    def _score_chip(score, threshold):
        if score >= max(threshold, 0.8):
            return "chip-red", "HIGH"
        if score >= threshold:
            return "chip-amber", "MED"
        if score >= threshold * 0.9:
            return "chip-amber", "NEAR"
        return "chip-teal", "LOW"

    rows = ['<div style="max-height:430px; overflow-y:auto; border-radius:6px;">']
    rows.append('<table class="alert-tbl"><thead><tr>')
    rows.append(
        "<th>Time</th>"
        "<th>Source IP</th>"
        "<th>Attack Type</th>"
        "<th>Score</th>"
        "<th>Severity</th>"
        "<th>Alert ID</th>"
        "<th>Flow ID</th>"
    )
    rows.append("</tr></thead><tbody>")

    for _, r in df_recent.iterrows():
        t = str(r.get("time", ""))[:19]
        # C1 fix (W4-Sub4d): every user/network-controlled field is escaped.
        fid = html.escape(str(r.get("flow_id", "-")))
        src_ip_raw = r.get("src_ip")
        if not isinstance(src_ip_raw, str) or not src_ip_raw:
            # Fallback: parse from flow_id "ip-..." prefix (non-live flows).
            fid_str = str(r.get("flow_id", ""))
            if "-" in fid_str and not fid_str.startswith("live"):
                src_ip_raw = fid_str.split("-", 1)[0]
            else:
                src_ip_raw = "—"
        src_ip = html.escape(str(src_ip_raw))

        atype_raw = r.get("attack_type") or ""
        atype = html.escape(str(atype_raw)) if atype_raw else "—"

        score_raw = r.get("score", 0)
        try:
            score = float(score_raw)
        except (ValueError, TypeError):
            score = 0.0

        label_val = r.get("label")
        is_attack = label_val in ("Attack", 1, "1")

        chip_class, chip_text = _score_chip(score, float(threshold_val or 0.5))
        sev = str(r.get("severity") or "")
        sev_class = SEV_CHIP.get(sev, "chip-slate")
        sev_disp = sev if sev else "—"

        alert_id_raw = r.get("alert_id")
        if alert_id_raw is None or (isinstance(alert_id_raw, float) and pd.isna(alert_id_raw)):
            alert_id = "—"
        else:
            try:
                alert_id = str(int(alert_id_raw))
            except (ValueError, TypeError):
                alert_id = html.escape(str(alert_id_raw))

        row_class = "row-attack" if is_attack else ""
        rows.append(
            f'<tr class="{row_class}">'
            f'<td class="mono">{html.escape(t)}</td>'
            f'<td class="mono">{src_ip}</td>'
            f'<td>{atype}</td>'
            f'<td><span class="chip {chip_class}">{score:.4f} · {chip_text}</span></td>'
            f'<td><span class="chip {sev_class}">{html.escape(sev_disp)}</span></td>'
            f'<td class="mono">{alert_id}</td>'
            f'<td class="mono" style="color:#6b7a90; font-size:11px;">{fid}</td>'
            f'</tr>'
        )
    rows.append("</tbody></table></div>")
    st.markdown("".join(rows), unsafe_allow_html=True)

    # ── Request Block panel (mitigation.request perm) ──────────
    # The alert table is hand-rolled HTML and can't host per-row buttons;
    # the request flow lives in this expander immediately under it.
    if "mitigation.request" in session["permissions"]:
        pending_ips = set()
        if _pending_code == 200 and isinstance(_pending_body, list):
            pending_ips = {p.get("target_ip") for p in _pending_body if p.get("target_ip")}

        # Attack rows only; need both alert_id and a usable src_ip.
        attack_rows = df_recent[df_recent["label"].isin(["Attack", 1, "1"])].copy()

        def _src_from_flow(flow_id):
            if not isinstance(flow_id, str) or "-" not in flow_id:
                return ""
            head = flow_id.split("-", 1)[0]
            return "" if head == "live" else head

        if "src_ip" in attack_rows.columns:
            attack_rows["_src"] = attack_rows["src_ip"].fillna("").astype(str)
            missing = attack_rows["_src"] == ""
            attack_rows.loc[missing, "_src"] = attack_rows.loc[missing, "flow_id"].apply(_src_from_flow)
        else:
            attack_rows["_src"] = attack_rows["flow_id"].apply(_src_from_flow)

        if "alert_id" in attack_rows.columns:
            eligible = attack_rows[
                attack_rows["alert_id"].notna() & (attack_rows["_src"] != "")
            ].copy()
        else:
            eligible = attack_rows.iloc[0:0]

        # Exclude this host's own IPs so the operator can't self-block.
        _hostname_mit, _self_ips_mit = _get_self_ips()
        _self_ips_set = set(_self_ips_mit)
        _pre_self_filter = len(eligible)
        if not eligible.empty:
            eligible = eligible[~eligible["_src"].isin(_self_ips_set)]

        with st.expander(f"Request Block · {len(pending_ips)} pending", expanded=False):
            st.markdown(
                '<div class="flow-strip">'
                '<span class="step">ANALYST REQUESTS</span><span class="arrow">→</span>'
                '<span class="step" style="color:#fbbf24;">ADMIN APPROVES</span>'
                '<span class="arrow">→</span>'
                '<span class="step" style="color:#5eead4;">NETSH BLOCKS</span>'
                '</div>',
                unsafe_allow_html=True,
            )
            st.caption(
                f"Local host IPs excluded from selection: {', '.join(sorted(_self_ips_set))}"
            )
            if eligible.empty:
                if _pre_self_filter > 0:
                    st.caption(
                        "All recent attack rows have local-host sources. "
                        "Likely false positives from background traffic — "
                        "wait for fresh external attack traffic."
                    )
                else:
                    st.caption(
                        "No eligible attack rows in the cache (needs both an "
                        "alert_id and a resolvable src_ip). Restart the API to "
                        "hydrate the cache from SQL if you just upgraded."
                    )
            else:
                # Deduplicate by source IP: one dropdown row per unique
                # attacker, aggregating their alerts.
                groups = []
                for src, grp in eligible.groupby("_src", sort=False):
                    first = grp.iloc[0]
                    try:
                        max_score = float(grp["score"].astype(float).max())
                    except Exception:
                        max_score = 0.0
                    t_str = str(first["time"])[11:19] or str(first["time"])[:19]
                    groups.append({
                        "src_ip":          src,
                        "count":           int(len(grp)),
                        "latest_alert_id": int(first["alert_id"]),
                        "latest_time":     t_str,
                        "max_score":       max_score,
                        "latest_time_raw": first["time"],
                    })
                groups.sort(key=lambda g: g["latest_time_raw"], reverse=True)

                options = []
                for g in groups:
                    marker = " — PENDING" if g["src_ip"] in pending_ips else ""
                    plural = "s" if g["count"] != 1 else ""
                    label = (
                        f"{g['src_ip']} — {g['count']} alert{plural} "
                        f"— latest #{g['latest_alert_id']} at {g['latest_time']} "
                        f"— max score {g['max_score']:.4f}{marker}"
                    )
                    options.append({
                        "label":    label,
                        "alert_id": g["latest_alert_id"],
                        "src_ip":   g["src_ip"],
                    })

                plural_uniq = "s" if len(options) != 1 else ""
                st.caption(
                    f"{len(options)} unique attacker IP{plural_uniq} from "
                    f"{len(eligible)} recent attack alerts."
                )

                labels = [o["label"] for o in options]
                picked_label = st.selectbox(
                    "Pick an attacker", options=labels, key="mit_pick_alert"
                )
                picked = options[labels.index(picked_label)]
                already_pending = picked["src_ip"] in pending_ips
                tooltip = (
                    "A pending block request already exists for this IP."
                    if already_pending else None
                )
                if st.button(
                    "Request Block",
                    key="mit_request_btn",
                    disabled=already_pending,
                    help=tooltip,
                ):
                    code, body = api_request(
                        "POST", "/mitigation/requests",
                        json={
                            "alert_id":  picked["alert_id"],
                            "target_ip": picked["src_ip"],
                            "reason":    "Requested from dashboard alerts panel",
                        },
                    )
                    if code == 201:
                        rid = (body or {}).get("id")
                        st.success(
                            f"Block requested for {picked['src_ip']} "
                            f"(request id {rid}). Awaiting admin approval."
                        )
                        st.rerun()
                    elif code == 400:
                        detail = (body or {}).get("detail", "")
                        st.error(f"Validation failed: {detail}")
                    elif code == 409:
                        detail = (body or {}).get("detail", {})
                        if isinstance(detail, dict) and detail.get("error") == "duplicate_pending":
                            st.warning(
                                f"Already pending: request {detail.get('existing_request_id')}."
                            )
                        else:
                            st.error(f"Conflict ({code}): {detail}")
                    elif code == 0:
                        st.error("Could not reach API.")
                    else:
                        detail = (body or {}).get("detail", body)
                        st.error(f"Request failed ({code}): {detail}")

        # ---- AI incident report (local LLM via Ollama, advisory, read-only) ----
        # Isolated in an st.fragment so it reruns on its own when its widgets fire,
        # WITHOUT triggering a full-page rerun. This means the live dashboard keeps
        # auto-refreshing normally while the user generates/reads a report, and the
        # report displays on the first click (no page-refresh tearing it down).
        @st.fragment
        def _report_panel(rep_source_df):
            if "label" in rep_source_df.columns and "alert_id" in rep_source_df.columns:
                _rep_df = rep_source_df[rep_source_df["label"] == "Attack"]
                _rep_df = _rep_df[_rep_df["alert_id"].notna()]
            else:
                _rep_df = rep_source_df.iloc[0:0]

            with st.expander("Generate Incident Report (AI)", expanded=True):
                if _rep_df.empty:
                    st.caption("No attack alerts with an alert ID to report on yet.")
                    return

                _ropts = {}
                _rep_sorted = _rep_df.copy()
                _rep_sorted["_aid_int"] = _rep_sorted["alert_id"].astype(int)
                _rep_sorted = _rep_sorted.sort_values("_aid_int", ascending=False)
                for _, _rr in _rep_sorted.iterrows():
                    _raid = int(_rr["alert_id"])
                    _rlabel = f"Alert {_raid} · {_rr.get('attack_type') or 'Unknown'} · {_rr.get('severity') or 'Low'} · {_rr.get('src_ip') or 'unknown src'}"
                    _ropts[_rlabel] = _raid

                _ropt_keys = list(_ropts.keys())
                _rpick = st.selectbox("Select an alert", _ropt_keys, key="report_pick")

                # Capture the click in an on_click callback instead of the
                # `if st.button(...)` return value. Under the page's 4s
                # st_autorefresh, a bare button check can miss the first click
                # (an autorefresh rerun lands between render and click and
                # supersedes the click's rerun) — that was the "does nothing the
                # first time, works the second time" symptom. The callback fires
                # at widget-event time and records the request in session_state,
                # so generation is driven by persisted state and runs on whatever
                # rerun comes next, even the autorefresh one.
                def _arm_report():
                    st.session_state["report_pending_id"] = _ropts.get(
                        st.session_state.get("report_pick")
                    )
                    st.session_state["report_generating"] = True

                st.button("Generate Report", key="report_btn", on_click=_arm_report)

                if st.session_state.get("report_pending_id") is not None:
                    _raid = st.session_state["report_pending_id"]
                    try:
                        with st.spinner("Writing incident report locally… (this can take 10–40 seconds, please wait)"):
                            _rcode, _rbody = api_request("GET", f"/report/{_raid}", timeout=120)
                    finally:
                        st.session_state["report_generating"] = False
                        st.session_state.pop("report_pending_id", None)
                    if _rcode == 200 and _rbody and _rbody.get("report"):
                        st.session_state["last_report"] = {
                            "alert_id": _raid,
                            "text": _rbody["report"],
                            "model": _rbody.get("model", "local LLM"),
                        }
                        st.session_state.pop("last_report_error", None)
                    elif _rcode == 503:
                        st.session_state["last_report_error"] = (
                            "AI report service is offline. Start Ollama and ensure a model is "
                            "pulled (ollama pull llama3.2:1b). The IDS is unaffected."
                        )
                    elif _rcode == 404:
                        st.session_state["last_report_error"] = "That alert was not found in the database."
                    elif _rcode == 0:
                        st.session_state["last_report_error"] = "Could not reach the API."
                    else:
                        _rd = (_rbody or {}).get("detail", "unknown error")
                        st.session_state["last_report_error"] = f"Report failed ({_rcode}): {_rd}"

                _rerr = st.session_state.get("last_report_error")
                if _rerr:
                    st.warning(_rerr)

                _rlast = st.session_state.get("last_report")
                if _rlast:
                    # No widget key here on purpose: a keyed text_area caches its
                    # FIRST value in session_state and ignores later value= args, which
                    # made switching alerts keep showing the previous report. Keyless
                    # re-renders from the current value every run.
                    st.text_area("Incident Report", _rlast["text"], height=360)
                    st.download_button(
                        "Download report (.txt)",
                        data=_rlast["text"],
                        file_name=f"incident_report_alert_{_rlast['alert_id']}.txt",
                        mime="text/plain",
                        key="report_download_btn",
                    )
                    st.caption(f"Generated locally by {_rlast['model']} · advisory only, not a detection decision")
                    if st.button("Clear report", key="report_clear_btn"):
                        st.session_state.pop("last_report", None)
                        st.session_state.pop("last_report_error", None)
                        st.rerun(scope="fragment")

        _report_panel(df_recent)

st.markdown("<hr/>", unsafe_allow_html=True)

# ============================================================
#  SECONDARY CONTEXT: Score Distribution + Top Sources
# ============================================================
b1, b2 = st.columns(2)

with b1:
    st.markdown("### Score Distribution")
    if not df.empty:
        fig = px.histogram(
            df, x="score", nbins=25, height=320,
            color_discrete_sequence=["#3b82f6"],
        )
        fig.update_layout(**PLOT_STYLE)
        fig.update_layout(
            xaxis=dict(title="Score", gridcolor="rgba(42,52,65,0.4)"),
            yaxis=dict(title="Count", gridcolor="rgba(42,52,65,0.4)"),
            bargap=0.05,
        )
        # Draw a threshold line so the panel can SEE the cutoff.
        fig.add_vline(
            x=float(threshold_val or 0.5),
            line_color="#f59e0b",
            line_dash="dash",
            annotation_text=f"threshold {threshold_val:.3f}",
            annotation_position="top right",
            annotation_font_color="#fbbf24",
            annotation_font_size=10,
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.caption("No scores yet.")

with b2:
    st.markdown(f"### Top {TOP_N} Source IPs")
    if not df.empty:
        if "src_ip" in df.columns and df["src_ip"].notna().any():
            src_series = df["src_ip"].fillna("").astype(str)
            src_series = src_series.where(src_series != "",
                                          df["flow_id"].astype(str).str.split("-").str[0])
        else:
            src_series = df["flow_id"].astype(str).str.split("-").str[0]
        df["_src"] = src_series.replace({"live": "live-capture"})
        top = (df.groupby("_src").size().reset_index(name="count")
               .sort_values("count", ascending=False).head(TOP_N))
        fig2 = px.bar(
            top, x="count", y="_src", orientation="h", height=320,
            color_discrete_sequence=["#14b8a6"],
        )
        fig2.update_layout(**PLOT_STYLE)
        fig2.update_layout(
            yaxis=dict(categoryorder="total ascending", gridcolor="rgba(0,0,0,0)", title=""),
            xaxis=dict(gridcolor="rgba(42,52,65,0.4)", title="Alert Count"),
        )
        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.caption("No source data yet.")

st.markdown(
    "<div style='color:#6b7a90; font-size:11px; margin-top:6px;'>"
    "AI-IDS SOC Console · all traffic is locally simulated via replay scripts or live capture. "
    "Backend frozen for Phase 2 — UI redesign only."
    "</div>",
    unsafe_allow_html=True,
)
