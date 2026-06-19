# AI-IDS Live Demo Script

> 5-minute live attack demonstration. Read top-to-bottom on defense day.
> Each step has: what to do, what to say, what the panel sees, what could
> go wrong.

## Pre-demo checklist (do BEFORE the panel walks in)

Run through this list end-to-end. If any item fails, do not proceed
live — switch to the backup video procedure at the bottom of this
document.

1. [ ] **Disable Avast shields** "until computer restart" (Avast tray
   icon → Avast shields control → Disable until computer restart).
   Critical — without this, netsh blocks are bypassed by the kernel-
   mode filter. See QA_BANK.md Q11 for the technical reason.
2. [ ] Confirm Windows Wi-Fi IP: open Command Prompt and run
   `ipconfig`. Note the IPv4 address (should be on the demo
   subnet, typically `192.168.1.x`).
3. [ ] Confirm Kali IP from the Kali terminal:
   `ip -4 addr show eth0`. Note the address (commonly
   `192.168.1.16` or `.17`, can shift with DHCP).
4. [ ] On Windows, start the target HTTP server. Open Command Prompt
   and run:
   ```
   python -m http.server 80 --bind <YOUR_WINDOWS_IP>
   ```
   Leave that window open. Verify the server is reachable by
   browsing `http://<YOUR_WINDOWS_IP>/` from a second machine on
   the demo network.
5. [ ] Start AI-IDS as administrator: right-click `START.bat` →
   Run as administrator. Wait for both `uvicorn` (port 8000) and
   `streamlit` (port 8501) to print "ready" in the console window.
6. [ ] Confirm admin elevation: in any browser, open
   `http://localhost:8000/health`. The JSON response must contain
   `"admin_elevated": true`. If `false`, STOP. Kill `START.bat`
   and restart it properly as administrator.
7. [ ] Open dashboard in browser tab 1: `http://localhost:8501`.
   Sign in as the admin user you created via
   `tools/bootstrap_admin.py`.
8. [ ] Open dashboard in browser tab 2 (incognito or a different
   browser): `http://localhost:8501`. Sign in as the analyst user.
9. [ ] On the admin tab, use the sidebar **Traffic Source** section.
   Under **Live Capture**, choose the Wi-Fi adapter and click
   **Start**. The friendly NIC label (added in W3-Sub5) tells you
   which physical adapter you're attaching to — pick the one that
   carries the Kali traffic. The top **Live State** strip must show
   **Live Capture = RUNNING**.
10. [ ] **Backup video ready:** `defense/demo_backup.mp4` open in
    VLC, paused on the opening frame. If anything fails live,
    switch to the video without panicking.

If any item fails: STOP. Use the backup video procedure. Do not
improvise live.

## Demo timeline (5 minutes)

Each step has four parts: **[DO]** / **[SAY]** / **[PANEL SEES]** /
**[IF IT BREAKS]**.

### Step 1 (0:00 – 0:30) — Set the scene

**[DO]** Bring the admin dashboard tab to the front. Show the top
**Live State** strip (**Live Capture = RUNNING**), the
**CAPTURE -> DETECT -> REQUEST -> APPROVE -> BLOCK -> AUDIT** flow
strip, and the empty Recent Alerts table.

**[SAY]** "This is the AI-IDS dashboard, signed in as admin. Live
packet capture is running on the Wi-Fi adapter. I'll now run a real
attack from a separate Kali VM, and you'll see the system detect,
alert, and let an analyst request a block."

**[PANEL SEES]** Clean Streamlit SOC console, Live Capture card green
and RUNNING, alerts table empty, and the triage columns visible:
Time, Source IP, Attack Type, Score, Severity, Alert ID, Flow ID.

**[IF IT BREAKS]** Live State shows IDLE → in the sidebar
**Live Capture** control, click **Stop** if needed, then **Start**
again. If the interface dropdown doesn't show the Wi-Fi adapter →
switch to backup video; the GUID-to-friendly-name resolver failed
and there's no quick fix on stage.

### Step 2 (0:30 – 1:30) — Run the attack

**[DO]** On the Kali terminal (already open and visible to the
panel), run:
```
slowhttptest -c 200 -X -i 10 -r 200 -t GET -u http://<WINDOWS_IP>/ -x 24 -p 3
```
Replace `<WINDOWS_IP>` with the value from pre-demo step 2.

**[SAY]** "This is slowhttptest — a slow-read denial-of-service tool.
It opens 200 connections to the target HTTP server and holds them
open, sending partial requests. This is a session-based attack the
model is trained to detect."

**[PANEL SEES]** slowhttptest banner, then a status line
`service available: YES` repeating every second or so, with the
"connected" counter climbing.

**[IF IT BREAKS]** If slowhttptest errors out immediately → check
that `<WINDOWS_IP>` is correct and that the http.server window from
pre-demo step 4 is still running. If `service available: NO`
appears from the very first line → the target server isn't up;
restart `python -m http.server`.

### Step 3 (1:30 – 2:30) — Detection lands

**[DO]** Switch to the admin dashboard tab. Wait for alerts to
populate (typically 30–60 seconds after attack start).

**[SAY]** "These alerts are showing up in real time. The table is
triage-first: time, source IP, attack type, score, severity, alert ID,
and flow ID. The Score chip is the binary head's confidence — above
the F1-optimal threshold of 0.3858 means Attack. Notice the Source IP
column — that's the Kali attacker."

**[PANEL SEES]** Recent Alerts table populating with rows. Source IP
matches Kali. Score chip is above threshold and the row is attack-
tinted. Attack Type is most often `DoS` — note this honestly when
asked (see QA_BANK.md Q8 on multi-class drift).

**[IF IT BREAKS]** No alerts after 90 seconds → first confirm Live
Capture is still on (the Live State card turns IDLE if it crashed).
Second confirm the Kali attack is still running (`service
available: YES` should keep printing). If both are healthy and
nothing has crossed threshold, say "the model is conservative at
the F1-optimal threshold" and switch to backup video for the
remainder.

### Step 4 (2:30 – 3:30) — Analyst requests block

**[DO]** Switch to the analyst dashboard tab. In the Recent Alerts
table, find an attack-tinted row whose Source IP is the Kali
attacker. Open the **Request Block · N pending** expander below the
table. In **Pick an attacker**, choose the Kali IP (deduplicated; one
row per attacker IP after W3-Sub6). Click **Request Block**.

**[SAY]** "Now I'm the analyst — a different role with fewer
privileges than admin. The analyst can request a block on the
attacker IP but cannot execute it. This is the human-in-loop design
we built in Week 3."

**[PANEL SEES]** Expander opens, dropdown lists the Kali IP, Request
Block button enabled, success toast on click. The analyst dashboard
has no Approve / Deny controls anywhere — those are admin-only.

**[IF IT BREAKS]** No **Request Block** expander visible → the
analyst doesn't have the `mitigation.request` permission; check
`src/auth/rbac.py`. Request fails with 403 → check the admin tab's
Audit Log page for the 403 row and explain why.

### Step 5 (3:30 – 4:30) — Admin approves, attack stalls

**[DO]** Switch to the admin dashboard tab → **Mitigation** page
(sidebar). The Pending Requests section should list the analyst's
request. Wait at least 5 seconds (two-person rule). Click
**Approve & Block**.

**[SAY]** "Back on the admin account. The two-person rule means a
user who submitted a request cannot approve it within 5 seconds of
submission — even if they hold both roles. Approving fires netsh
under the hood, which adds a Windows Firewall rule blocking the
attacker IP inbound."

**[PANEL SEES]** Pending request row → Approve & Block button →
success toast → the request moves to Active Blocks. The audit log
gets a `mitigation.request.approve` row and a
`mitigation.block.execute` row immediately after.

**[DO]** Switch to the Kali terminal. Point at the slowhttptest
output.

**[SAY]** "Watch the attack on Kali. The connections counter has
stopped climbing. `service available: NO` lines are appearing
where YES used to be. The block is enforcing at the host firewall."

**[PANEL SEES]** slowhttptest output transitions from
`service available: YES` (with a rising connection count) to
`service available: NO` (connections flat or dropping). Visible
within 5–10 seconds of approval.

**[IF IT BREAKS]**
- Approve button stays disabled past 5 seconds → refresh the page;
  the countdown is rendered client-side and an earlier failed click
  may have left it stuck.
- slowhttptest still shows YES after 30 seconds → Avast may not be
  fully disabled. Confirm shields are off (pre-demo step 1). If
  shields are off and the bypass persists, switch to the backup
  video and call out the AV co-existence issue documented in
  CHANGES.md (Week 3 closeout) and `FUTURE_WORK.md` §7.

### Step 6 (4:30 – 5:00) — Show the audit trail

**[DO]** Admin dashboard → **Audit Log** page. Filter the action
column on `mitigation` or scroll to the most recent rows.

**[SAY]** "Every step of that chain — the analyst's request, the
admin's approval, the netsh execution — is in the audit log. Actor,
timestamp, target IP, success or failure. This is what closes the
third Phase 1 viva question about actual mitigation."

**[PANEL SEES]** Audit Log table with rows like:
- `mitigation.request.create` actor=analyst1 target=request:N status=success
- `mitigation.request.approve` actor=admin1 target=request:N status=success
- `mitigation.block.execute` actor=admin1 target=request:N status=success

**[IF IT BREAKS]** Audit log empty → highly unlikely at this point
(the dashboard you've been using all session writes to it). If it
genuinely is empty, the DB lost its connection; switch to backup
video for the wrap-up.

## After the demo

**[DO]** Stop slowhttptest on Kali (`Ctrl+C`). On the admin tab →
Mitigation page → Active Blocks → **Unblock** the Kali IP.

**[SAY]** "Cleaning up — unblocking the IP so the lab is ready for
the next demo. The unblock is also audit-logged."

**[PANEL SEES]** Active Blocks row removed, success toast. Audit Log
gets a `mitigation.unblock.execute` row.

## Backup video procedure

If anything in Steps 1–5 fails irrecoverably:

1. Don't panic, don't apologize repeatedly. One clean line: "Live
   demo hit an environmental issue — here's the recorded version
   of the same attack."
2. Switch to VLC, play `defense/demo_backup.mp4` from the start.
3. Narrate over the video as if it were happening live. Use the
   same script above.
4. After the video ends, switch back to the dashboard and SHOW the
   real Audit Log from the last successful rehearsal — those rows
   are still in `data/ids.db`. That proves the system is real and
   not a video-only artefact.

## Known fragile points (do not improvise around these)

- **Avast.** If shields re-enable themselves (Windows Update has
  been observed to do this), netsh blocks won't enforce. Pre-demo
  step 1 is non-negotiable; verify the Avast tray icon shows
  shields off immediately before the panel arrives.
- **DHCP shift.** Kali's IP can change between rehearsal and demo
  day. Pre-demo step 3 catches this — if the IP changed, update
  the slowhttptest target URL accordingly.
- **Unblock kernel-state quirk.** After the post-demo Unblock,
  Windows occasionally holds in-kernel filter state for the
  formerly-blocked remote — the rule is gone but the kernel still
  drops. Restart `python -m http.server` to clear it. This is a
  teardown issue, not a demo-time issue; explained in Q12 of
  QA_BANK.md if it surfaces.
- **Streamlit auto-refresh.** Pages auto-refresh every few seconds.
  If you click during a refresh, the click may not register. Wait
  ~3–5 seconds and click again rather than mashing.

## Runbook reference (exact commands)

For the panel's convenience and your muscle memory:

**Windows (target host):**
```
ipconfig
python -m http.server 80 --bind <WINDOWS_IP>
```

**Kali (attacker):**
```
ip -4 addr show eth0
slowhttptest -c 200 -X -i 10 -r 200 -t GET -u http://<WINDOWS_IP>/ -x 24 -p 3
```

**Curl probe (alternative to slowhttptest if needed):**
```
curl -m 5 http://<WINDOWS_IP>/   # should succeed before block, time out after
```

**Re-enable Avast after the demo (Windows tray):**
Avast icon → Avast shields control → Enable all shields.
