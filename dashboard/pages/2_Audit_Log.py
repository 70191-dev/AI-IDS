"""Audit Log viewer — admin-only.

Streamlit's built-in `pages/` mechanism renders this as "Audit Log"
in the sidebar nav. Visibility is OPTION X (defense-in-depth): an
analyst sees the nav entry but is blocked at click time by the
permission check below.

Phase 2 redesign: present the log as a chain-of-custody record.
Newest first, status badged, columns labelled like an evidence log.
"""

from datetime import datetime, timedelta
import pandas as pd
import streamlit as st

from dashboard.auth_ui import require_login, api_request

st.set_page_config(page_title="AI-IDS | Audit Log", layout="wide")

# ── Theme (matches dashboard/app.py SOC palette) ─────────────
AUDIT_CSS = """
<style>
body, .stApp { background-color: #0f1419; color: #d4dae3; }
section.main { background-color: #0f1419; }
header[data-testid="stHeader"] { background: transparent !important; }
#MainMenu, footer, .stDeployButton { display: none !important; }

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
h3 { font-size: 13px; text-transform: uppercase; letter-spacing: 0.6px; color: #8aa6c4; }

hr { border-color: #2a3441 !important; opacity: 0.7; }

div[data-testid="stAlert"] {
    background: #151b23 !important;
    border-color: #2a3441 !important;
    color: #d4dae3 !important;
    border-radius: 6px;
}

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
    box-shadow: 0 6px 16px rgba(0,0,0,0.40);
}
div[data-testid="stMetric"] label {
    color: #8aa6c4 !important; font-size: 11px;
    text-transform: uppercase; letter-spacing: 0.5px;
}
div[data-testid="stMetric"] [data-testid="stMetricValue"] {
    color: #e6ecf3 !important; font-weight: 600; font-size: 20px;
}

.stButton > button, .stDownloadButton > button {
    background: #1c2530; color: #e6ecf3; border: 1px solid #2a3441;
    transition: background-color 0.15s ease, border-color 0.15s ease,
                transform 0.10s ease;
}
.stButton > button:hover, .stDownloadButton > button:hover {
    background: #243040; border-color: #3b4759; color: #ffffff;
}
.stButton > button:active, .stDownloadButton > button:active {
    transform: translateY(1px);
}

section[data-testid="stSidebar"] {
    background: #0c1218; border-right: 1px solid #2a3441;
}

div[data-testid="stDataFrame"] {
    border: 1px solid #2a3441; border-radius: 6px;
    transition: border-color 0.18s ease;
}
div[data-testid="stDataFrame"]:hover { border-color: #3b4759; }
</style>
"""
st.markdown(AUDIT_CSS, unsafe_allow_html=True)

session = require_login()
if "audit.read" not in session["permissions"]:
    st.error("Admin only — you don't have permission to view this page.")
    st.stop()

st.markdown("<h1>Audit Log</h1>", unsafe_allow_html=True)
st.caption(
    "Chain-of-custody record. Every authentication event, RBAC denial, "
    "user-management action, capture/replay toggle, and mitigation step "
    "is logged here with the actor, timestamp, and source IP. Most recent first."
)

DEFAULT_SINCE_DAYS = 7
COLUMNS = [
    "ts", "actor_username", "action", "status",
    "target", "detail", "ip_address",
]


# ── Filter row ────────────────────────────────────────────────
st.markdown("### Filter")
fc1, fc2, fc3, fc4, fc5 = st.columns([1, 1.2, 1.5, 1.2, 1])
limit  = fc1.number_input("Limit", min_value=1, max_value=500, value=100, step=10)
since  = fc2.date_input("Since", value=datetime.now().date() - timedelta(days=DEFAULT_SINCE_DAYS))
action = fc3.text_input("Action prefix", placeholder="user. / login / mitigation. ...")
actor  = fc4.text_input("Actor", placeholder="exact username")
status_choice = fc5.selectbox("Status", ["", "success", "failure"], index=0)

apply_clicked = st.button("Apply filters")


# ── Build params ──────────────────────────────────────────────
params = {"limit": int(limit)}
if since is not None:
    # ts in the DB is ISO 8601 with 'T' separator; using just the
    # date as a prefix works because lex-compare is correct: rows
    # with ts >= '2026-05-17' are everything from that calendar day.
    params["since"] = since.isoformat()
if action.strip():        params["action"] = action.strip()
if actor.strip():         params["actor"]  = actor.strip()
if status_choice:         params["status"] = status_choice


# ── Fetch ─────────────────────────────────────────────────────
code, rows = api_request("GET", "/audit", params=params)
if code != 200 or not isinstance(rows, list):
    st.error(f"Failed to load audit log (status={code}): {rows}")
    st.stop()


# ── Summary strip ─────────────────────────────────────────────
st.markdown("### Summary")
total = len(rows)
n_fail = sum(1 for r in rows if r.get("status") == "failure") if rows else 0
n_ok   = total - n_fail
n_unique_actors = len({r.get("actor_username") for r in rows if r.get("actor_username")}) if rows else 0
m1, m2, m3, m4 = st.columns(4)
m1.metric("Rows shown", f"{total:,}")
m2.metric("Success",    f"{n_ok:,}")
m3.metric("Failure",    f"{n_fail:,}")
m4.metric("Distinct actors", f"{n_unique_actors:,}")

st.markdown("<hr/>", unsafe_allow_html=True)


# ── Render ────────────────────────────────────────────────────
st.markdown("### Records")
if rows:
    df = pd.DataFrame(rows)
    # Reorder + keep only the columns we care about. Tolerate extra
    # columns the API may add later (id, user_agent, actor_user_id).
    cols_present = [c for c in COLUMNS if c in df.columns]
    # Friendlier headers — the underlying field names stay the same in
    # the exported CSV, but the rendered table now reads operationally.
    rename_map = {
        "ts":             "Timestamp",
        "actor_username": "Actor",
        "action":         "Action",
        "status":         "Status",
        "target":         "Target",
        "detail":         "Detail",
        "ip_address":     "Source IP",
    }
    display_df = df[cols_present].rename(columns={c: rename_map[c] for c in cols_present})
    st.dataframe(display_df, hide_index=True, use_container_width=True, height=480)
else:
    st.info("No audit rows for the current filter.")


# ── Filter recap ──────────────────────────────────────────────
filter_bits = [f"limit={params['limit']}"]
if "since"  in params:  filter_bits.append(f"since={params['since']}")
if "action" in params:  filter_bits.append(f"action~='{params['action']}*'")
if "actor"  in params:  filter_bits.append(f"actor='{params['actor']}'")
if "status" in params:  filter_bits.append(f"status='{params['status']}'")
st.caption(f"Filter: " + ", ".join(filter_bits))


# ── Export CSV ────────────────────────────────────────────────
if rows:
    csv_bytes = pd.DataFrame(rows).to_csv(index=False).encode("utf-8")
    fname = f"audit_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    st.download_button(
        "Export CSV",
        data=csv_bytes,
        file_name=fname,
        mime="text/csv",
        use_container_width=False,
    )
