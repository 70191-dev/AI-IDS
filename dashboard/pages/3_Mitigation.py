"""Threat Mitigation page — admin-only.

Streamlit's built-in `pages/` mechanism auto-discovers this file and
renders it in the sidebar nav as "Mitigation" (Streamlit strips the
leading "3_" prefix).

Visibility is OPTION X (defense-in-depth): an analyst will still see
"Mitigation" in the sidebar but a click hits the require_login +
permission check below and gets a hard "Admin only" stop. Matches the
pattern used by 1_Users.py and 2_Audit_Log.py.

No auto-refresh on this page: actions are user-driven (Approve / Deny /
Unblock), so silent ticking would be jarring while a click is mid-flight.

Phase 2 redesign focus: make the request state machine
(PENDING -> APPROVED -> BLOCKED, with DENIED as a terminal leaf) visible
at a glance, and surface the two-person rule + 5-second guard in the
chrome rather than only in error toasts.
"""

import html
import pandas as pd
import streamlit as st

from dashboard.auth_ui import require_login, api_request

st.set_page_config(page_title="AI-IDS | Mitigation", layout="wide")

# ── Theme (matches dashboard/app.py SOC palette) ─────────────
MIT_CSS = """
<style>
/* Same flicker-safe animation policy as dashboard/app.py: keyframes
   are 0% == 100% so any rerun-induced restart looks continuous, and
   live indicators use negative animation-delay so the first paint is
   already mid-cycle. */

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
h2 { font-size: 17px; }
h3 { font-size: 13px; text-transform: uppercase; letter-spacing: 0.6px; color: #8aa6c4; }

hr { border-color: #2a3441 !important; opacity: 0.7; }

/* ---- keyframes ---- */
@keyframes sm-step-pulse-amber {
    0%, 100% { background: rgba(245,158,11,0.06); border-color: rgba(245,158,11,0.35); }
    50%      { background: rgba(245,158,11,0.16); border-color: rgba(245,158,11,0.75); }
}
@keyframes blocked-glow {
    0%, 100% { box-shadow: 0 0 6px rgba(20,184,166,0.30); }
    50%      { box-shadow: 0 0 14px rgba(20,184,166,0.65); }
}

.chip {
    display: inline-block;
    padding: 2px 9px;
    border-radius: 3px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.3px;
}
.chip-red    { background: rgba(239,68,68,0.16);  color: #f87171; border: 1px solid rgba(239,68,68,0.35); }
.chip-amber  { background: rgba(245,158,11,0.16); color: #fbbf24; border: 1px solid rgba(245,158,11,0.35); }
.chip-teal   { background: rgba(20,184,166,0.16); color: #5eead4; border: 1px solid rgba(20,184,166,0.35); }
.chip-blue   { background: rgba(59,130,246,0.16); color: #93c5fd; border: 1px solid rgba(59,130,246,0.35); }
.chip-slate  { background: rgba(148,163,184,0.14); color: #cbd5e1; border: 1px solid rgba(148,163,184,0.30); }
.chip-blocked-live {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 3px;
    font-size: 11px; font-weight: 700; letter-spacing: 0.4px;
    background: rgba(20,184,166,0.18);
    color: #5eead4;
    border: 1px solid rgba(20,184,166,0.55);
    animation: blocked-glow 3s ease-in-out infinite;
    animation-delay: -1s;
}

.req-card {
    background: #151b23;
    border: 1px solid #2a3441;
    border-left: 3px solid #f59e0b;
    border-radius: 6px;
    padding: 12px 16px;
    margin-bottom: 12px;
    transition: border-color 0.18s ease, box-shadow 0.18s ease, transform 0.15s ease;
}
.req-card:hover {
    border-color: rgba(245,158,11,0.55);
    box-shadow: 0 6px 18px rgba(0,0,0,0.45);
    transform: translateY(-1px);
}
.req-card .meta {
    color: #8693a8;
    font-size: 12px;
    margin-bottom: 4px;
}
.req-card .target {
    color: #e6ecf3;
    font-size: 15px;
    font-weight: 600;
    font-family: 'Consolas', 'Courier New', monospace;
}
.req-card .reason {
    color: #b8c3d1;
    font-size: 12px;
    margin-top: 4px;
    font-style: italic;
}

/* state-machine strip */
.sm-strip {
    display: flex; gap: 4px; align-items: center;
    font-size: 11px; margin: 8px 0 14px 0;
}
.sm-step {
    padding: 3px 10px;
    border-radius: 3px;
    background: #1c2530;
    border: 1px solid #2a3441;
    color: #6b7a90;
    font-weight: 600;
    letter-spacing: 0.4px;
    transition: color 0.25s ease, border-color 0.25s ease;
}
.sm-step.active {
    color: #fbbf24;
    border-color: rgba(245,158,11,0.5);
    background: rgba(245,158,11,0.08);
    animation: sm-step-pulse-amber 3.2s ease-in-out infinite;
    animation-delay: -1.4s;
}
.sm-step.done   { color: #5eead4; border-color: rgba(20,184,166,0.5); background: rgba(20,184,166,0.08); }
.sm-arrow { color: #4b5563; }

/* Active-blocks status banner: calm teal glow tells the admin at a
   glance "the firewall is actively enforcing right now." */
.blocks-banner {
    display: flex; align-items: center; gap: 10px;
    background: #151b23;
    border: 1px solid rgba(20,184,166,0.35);
    border-left: 3px solid #14b8a6;
    border-radius: 6px;
    padding: 8px 12px;
    margin: 6px 0 10px 0;
}
.blocks-banner .count {
    font-size: 18px; font-weight: 700; color: #5eead4;
    font-family: 'Consolas', 'Courier New', monospace;
}
.blocks-banner .label {
    font-size: 11px; letter-spacing: 0.6px; color: #8aa6c4;
    text-transform: uppercase; font-weight: 600;
}

div[data-testid="stAlert"] {
    background: #151b23 !important;
    border-color: #2a3441 !important;
    color: #d4dae3 !important;
    border-radius: 6px;
}

.stButton > button {
    background: #1c2530;
    color: #e6ecf3;
    border: 1px solid #2a3441;
    font-weight: 500;
}
.stButton > button:hover {
    background: #243040;
    border-color: #3b4759;
}

section[data-testid="stSidebar"] {
    background: #0c1218;
    border-right: 1px solid #2a3441;
}
</style>
"""
st.markdown(MIT_CSS, unsafe_allow_html=True)

session = require_login()
if "mitigation.approve" not in session["permissions"]:
    st.error("Admin only — you don't have permission to view this page.")
    st.stop()

st.markdown("<h1>Threat Mitigation</h1>", unsafe_allow_html=True)
st.caption(
    "Two-person workflow: an analyst submits a Request Block; an admin (you) "
    "approves or denies it. Approval triggers a netsh advfirewall rule on the "
    "host. The two-person rule blocks self-approval within 5 seconds."
)


def _state_strip(stage: str) -> str:
    """stage in {"pending","approved","denied"}"""
    pending  = "active" if stage == "pending"  else "done"
    decision = ("active" if stage == "approved"
                else "done" if stage in ("approved",)
                else "" if stage == "pending"
                else "active")  # denied -> highlight decision
    blocked  = ("done" if stage == "approved" else "")
    return (
        '<div class="sm-strip">'
        f'<span class="sm-step {pending}">REQUESTED</span><span class="sm-arrow">→</span>'
        f'<span class="sm-step {decision}">DECIDED</span><span class="sm-arrow">→</span>'
        f'<span class="sm-step {blocked}">BLOCKED</span>'
        '</div>'
    )


# ════════════════════════════════════════════════════════════════
# Workflow legend
# ════════════════════════════════════════════════════════════════
st.markdown("### Workflow")
st.markdown(
    '<div class="sm-strip">'
    '<span class="sm-step active">ANALYST REQUESTS</span><span class="sm-arrow">→</span>'
    '<span class="sm-step active">ADMIN DECIDES</span><span class="sm-arrow">→</span>'
    '<span class="sm-step done">NETSH EXECUTES</span><span class="sm-arrow">→</span>'
    '<span class="sm-step done">AUDIT LOGGED</span>'
    '</div>',
    unsafe_allow_html=True,
)
st.markdown("<hr/>", unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════
# Section 1 — Pending Requests
# ════════════════════════════════════════════════════════════════
st.markdown("### Pending Requests")

code, pending = api_request("GET", "/mitigation/requests?status=pending")
if code != 200 or not isinstance(pending, list):
    st.error(f"Failed to load pending requests (status={code}): {pending}")
    st.stop()

if not pending:
    st.info("No pending mitigation requests.")
else:
    st.caption(
        f"{len(pending)} pending. Two-person rule: an admin who created a "
        "request cannot approve it within 5 s of creation."
    )
    for req in pending:
        rid          = req["id"]
        target_ip    = req["target_ip"]
        requested_by = req.get("requested_by_username") or f"user:{req.get('requested_by')}"
        requested_at = req.get("requested_at", "")
        alert_id     = req.get("alert_id")
        reason       = req.get("reason") or "(no reason given)"
        is_self      = req.get("requested_by") == session.get("user_id")

        st.markdown(
            f'<div class="req-card">'
            f'<div class="meta">'
            f'<span class="chip chip-amber">PENDING</span> &nbsp; '
            f'Request #{rid} · alert #{alert_id} · '
            f'by <b>{html.escape(str(requested_by))}</b> at '
            f'<code style="color:#b8c3d1;">{html.escape(str(requested_at))}</code>'
            f'</div>'
            f'<div class="target">{html.escape(str(target_ip))}</div>'
            f'<div class="reason">"{html.escape(str(reason))}"</div>'
            f'</div>',
            unsafe_allow_html=True,
        )
        st.markdown(_state_strip("pending"), unsafe_allow_html=True)

        if is_self:
            st.caption(
                ":orange[You created this request — two-person rule applies "
                "for the first 5 seconds.]"
            )

        ac, dc = st.columns(2)

        # ── Approve ──
        with ac:
            approve_note = st.text_input(
                "Approval note (optional)",
                key=f"approve_note_{rid}",
            )
            if st.button("Approve & Block", key=f"approve_btn_{rid}"):
                code, body = api_request(
                    "POST", f"/mitigation/requests/{rid}/approve",
                    json={"note": approve_note or None},
                )
                if code == 200:
                    body = body or {}
                    if "warning" in body:
                        action = body.get("action") or {}
                        err = action.get("error_detail") or "unknown error"
                        # Persistent error: do NOT st.rerun(), otherwise the
                        # user only sees the failure as a vanished row.
                        st.error(
                            f"Request {rid} approved, but netsh execution "
                            f"FAILED: {err}. The rule was NOT added. Check "
                            "that the API process is running as administrator. "
                            "See 'Recent Failed Executions' below for the full row."
                        )
                    else:
                        br = body.get("block_result") or {}
                        rule = br.get("rule_name", "(unknown)")
                        st.success(
                            f"Request {rid} approved. Block executed: "
                            f"rule '{rule}' added."
                        )
                        st.rerun()
                elif code == 403:
                    detail = (body or {}).get("detail", "Forbidden")
                    st.error(detail)
                elif code == 409:
                    st.error("Already approved or denied. Refreshing page.")
                    st.rerun()
                elif code == 0:
                    st.error("Could not reach API.")
                else:
                    detail = (body or {}).get("detail", body)
                    st.error(f"Approve failed ({code}): {detail}")

        # ── Deny ──
        with dc:
            deny_note = st.text_input(
                "Denial reason (optional)",
                key=f"deny_note_{rid}",
            )
            if st.button("Deny", key=f"deny_btn_{rid}"):
                code, body = api_request(
                    "POST", f"/mitigation/requests/{rid}/deny",
                    json={"note": deny_note or None},
                )
                if code == 200:
                    st.success(f"Request {rid} denied.")
                    st.rerun()
                elif code == 409:
                    st.error("Already approved or denied. Refreshing page.")
                    st.rerun()
                elif code == 0:
                    st.error("Could not reach API.")
                else:
                    detail = (body or {}).get("detail", body)
                    st.error(f"Deny failed ({code}): {detail}")

        st.markdown("<hr/>", unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════
# Section 2 — Active Blocks
# ════════════════════════════════════════════════════════════════
st.markdown("### Active Blocks")

code, blocked = api_request("GET", "/mitigation/blocked")
if code != 200 or not isinstance(blocked, list):
    st.error(f"Failed to load active blocks (status={code}): {blocked}")
    st.stop()

if not blocked:
    st.info("No IPs currently blocked by the firewall.")
else:
    # Calm-teal live banner: the count glows quietly so it's obvious at
    # a glance that the firewall is actively enforcing. The dataframe
    # below is unchanged (Streamlit's data_editor doesn't honour HTML
    # in cells, so per-row badges aren't viable here — the banner +
    # left-stripe carries the "live" feeling instead).
    plural = "s" if len(blocked) != 1 else ""
    st.markdown(
        f'<div class="blocks-banner">'
        f'<span class="chip-blocked-live">BLOCKED</span>'
        f'<span class="count">{len(blocked)}</span>'
        f'<span class="label">IP{plural} actively enforced by netsh</span>'
        f'</div>',
        unsafe_allow_html=True,
    )
    st.caption(
        "Each was approved by an admin and reflected in the netsh ledger."
    )
    df = pd.DataFrame(blocked)
    cols = [c for c in ("ip", "rule_name", "blocked_at", "request_id", "approved_by_username")
            if c in df.columns]
    st.dataframe(df[cols], hide_index=True, use_container_width=True)

    with st.expander("Unblock an IP", expanded=False):
        ip_choices = ["(choose...)"] + [b["ip"] for b in blocked if b.get("ip")]
        choice = st.selectbox(
            "IP to unblock",
            options=ip_choices,
            key="unblock_ip_select",
        )
        reason = st.text_input("Reason (optional)", key="unblock_reason_input")
        if st.button("Unblock", key="unblock_btn"):
            if choice == "(choose...)":
                st.warning("Pick an IP first.")
            else:
                code, body = api_request(
                    "POST", "/mitigation/unblock",
                    json={"ip": choice, "reason": reason or None},
                )
                if code == 200:
                    body = body or {}
                    action = body.get("action") or {}
                    if action.get("status") == "success":
                        ub = body.get("unblock_result") or {}
                        rule = ub.get("rule_name", "(unknown)")
                        st.success(f"Unblocked {choice}. Rule removed: {rule}.")
                    else:
                        err = action.get("error_detail") or "unknown error"
                        st.warning(
                            f"Unblock recorded but netsh execution failed: {err}."
                        )
                    st.rerun()
                elif code == 400:
                    detail = (body or {}).get("detail", body)
                    st.error(f"Unblock failed: {detail}")
                elif code == 0:
                    st.error("Could not reach API.")
                else:
                    detail = (body or {}).get("detail", body)
                    st.error(f"Unblock failed ({code}): {detail}")


st.markdown("<hr/>", unsafe_allow_html=True)

# ════════════════════════════════════════════════════════════════
# Section 3 — Recent Failed Executions
# ════════════════════════════════════════════════════════════════
# When approve succeeds but netsh fails (e.g. API not elevated), the
# request leaves Pending and the rule is NOT added — Active Blocks
# stays empty. Without this table the admin would only see the truth
# by opening the Audit Log. Surface it here.
st.markdown("### Recent Failed Executions")
st.caption(
    "Netsh add/delete failures. If this table has rows, the request was "
    "decided correctly but the host-level firewall rule did not stick — "
    "almost always because the API is not running elevated."
)

code, failures = api_request("GET", "/mitigation/actions/failures?limit=50")
if code != 200 or not isinstance(failures, list):
    st.error(f"Failed to load failed executions (status={code}): {failures}")
elif not failures:
    st.success("No failed mitigation executions.")
else:
    fdf = pd.DataFrame(failures)
    fcols = [c for c in (
        "executed_at",
        "action_type",
        "target_ip",
        "request_id",
        "executed_by_username",
        "error_detail",
    ) if c in fdf.columns]
    st.dataframe(fdf[fcols], hide_index=True, use_container_width=True)
    st.caption(
        "Stdout/stderr from netsh are stored in the DB "
        "(mitigation_action.netsh_stdout / .netsh_stderr) and surface in "
        "/mitigation/actions/failures for debugging."
    )
