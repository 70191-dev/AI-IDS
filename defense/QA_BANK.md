# Defense Q&A Bank

> Anticipated panel questions with prepared answers. Skim the night
> before defense. Each answer points to verifiable evidence in the
> codebase or docs.

## How to use this document

These are not scripts — they are starting points. Answer the panel
in your own voice, but anchored in the specifics here (file paths,
line numbers, the actual numbers from `lab/ATTACK_VALIDATION.md`,
the actual dates from `CHANGES.md`). Generic answers fail on defense
day; "the multi-class head drifts on out-of-distribution attacks at
roughly 25–57% recall, documented in lab/ATTACK_VALIDATION.md"
beats "we observed some accuracy issues."

If a question isn't in this bank, the honest answer
("we documented that as future work, see `FUTURE_WORK.md` §N")
always beats an improvised guess. The bank is organised by
category: **A. Scope and design decisions**, **B. Detection and
ML**, **C. Mitigation**, **D. Architecture and engineering**,
**E. Process and validation**, **F. Open / hostile questions**.

The five mandatory questions from the Week 4 stage brief are Q1
(Streamlit), Q9 (scan/flood), Q11 (Avast), Q13 (two-person rule),
and Q18 (multi-machine). Make sure those four-to-five answers are
in muscle memory.

## Category A: Scope and design decisions

### Q1: Why Streamlit instead of a professional UI like Splunk or Elastic Security?

**Answer.** Three reasons. First, scope: an FYP with a four-week
Phase 2 budget cannot ship a React or Vue SPA at the UX bar that
production SOC tools clear. Streamlit gave us a working dashboard
with auth, RBAC, audit, and the mitigation workflow inside that
budget. Second, deployment alignment: Streamlit runs in one process
on localhost, no separate frontend build, no Node.js dependency —
which fits the standalone-machine constraint the Phase 1 proposal
set (Chapter 2.2.1). Third, the panel can see the signal that
matters — detection working, RBAC enforcing, mitigation chain
executing end-to-end. UX polish is in `FUTURE_WORK.md` §6 at
8–12 engineer-weeks; we chose to spend that effort on detection
and mitigation rigour instead.

**Evidence.** `RECONCILIATION_PHASE2.md` §5 (UI substitution note),
`FUTURE_WORK.md` §6, `_project/HARD_CONSTRAINTS.md` (Streamlit-
stays rule).

### Q2: Why SQLite instead of PostgreSQL?

**Answer.** Single-machine deployment is a Phase 1 proposal
constraint that Phase 2 preserved deliberately. PostgreSQL would
require a separate service, a separate auth surface, a separate
backup story — and it would add nothing the panel can observe.
SQLite is one file at `data/ids.db`, three schema groups (four
ERD tables, three auth tables, two mitigation tables), and is
sufficient at FYP scale. The migration path to Postgres is open
because we use plain SQL through the `db` helper module, not an
ORM-specific dialect.

**Evidence.** `_project/HARD_CONSTRAINTS.md` (no-Postgres rule),
`RECONCILIATION_PHASE2.md` §5 (Storage row), `src/utils/db.py`.

### Q3: Why opaque bearer tokens instead of JWT?

**Answer.** JWT means signed, stateless tokens — useful when you
have multiple services and want to avoid a session-table lookup.
We have one service. We also want admin-disable to revoke an
active session immediately, not at the next token expiry. That
requires server-side session state. Opaque 32-byte tokens in a
`session` table give us atomic revocation for free. We also get
bcrypt cost-12 password hashing, an 8-hour TTL on tokens, and a
read-after-write check on every privileged request.

**Evidence.** `src/auth/sessions.py`, `src/auth/passwords.py`,
`RECONCILIATION_PHASE2.md` §5 (Auth row).

### Q4: Why bcrypt cost 12 specifically?

**Answer.** bcrypt cost 12 is the OWASP recommendation for
current consumer hardware — roughly 250 ms per hash on a modern
CPU. Slow enough to make brute-force expensive, fast enough not
to hurt login UX. We use the same cost factor in the bootstrap
CLI (`tools/bootstrap_admin.py`) and at runtime
(`src/auth/passwords.py`) via passlib's `CryptContext`. If the
cost ever needs to change, passlib's `needs_rehash` will upgrade
hashes transparently on the next successful login.

**Evidence.** `src/auth/passwords.py`, `tools/bootstrap_admin.py`.

### Q5: Why two roles only — admin and analyst? Why not viewer or auditor?

**Answer.** Scope discipline. Each role added doubles the
permission-matrix testing surface, and the Phase 1 viva question
was "anyone can use this dashboard?" — that needs, at minimum,
a privileged-vs-unprivileged split. Two roles answer it directly.
More roles (read-only viewer, dedicated auditor) are sensible
extensions, but the existing `PERMISSIONS` dict in
`src/auth/rbac.py` makes adding them a ten-line change rather
than a refactor. We deliberately did not bake assumptions about
viewer or auditor into the codebase, because we'd rather add
them well when needed than carry dead role-stubs.

**Evidence.** `src/auth/rbac.py:14` (the PERMISSIONS dict),
`_project/HARD_CONSTRAINTS.md` (two-roles-only rule).

## Category B: Detection and ML

### Q6: How do you know the model isn't just memorising CIC-IDS2017?

**Answer.** Two independent signals. First, Week 1 live
validation: we ran real attacks (slowhttptest, medusa SSH brute-
force, nikto) from a Kali VM against the Windows host, and the
binary head detected at 25–57% recall reproducibly across two
runs five hours apart. CIC-IDS2017 doesn't contain those exact
attack instances on those source IPs and destination ports — if
the model were memorising, recall would be at chance. Second,
the failure modes are honest and architectural: `nmap -sS` and
`hping3 --flood` are not detected, and we documented why
(singleton-flow attacks fall outside the per-flow training
distribution). A memorising model would detect everything or
nothing; ours detects exactly what its training distribution
covers and misses exactly what it doesn't.

**Evidence.** `lab/ATTACK_VALIDATION.md`, CHANGES.md
2026-05-23 entry, `RECONCILIATION_PHASE2.md` FR_03 notes.

### Q7: What's your false-positive rate?

**Answer.** Honest answer: we don't have a measured production
FP rate. On the CIC-IDS2017 test set, the F1-optimal threshold
of 0.3858 gives a low FP rate on that distribution, but
test-set numbers are not deployment numbers. In Week 1 live
runs we saw some benign flows cross the threshold during
background browsing, but we did not run a quantified FP study
under sustained legitimate traffic — that would require a
controlled lab with hours of clean traffic and is one of the
extensions in `FUTURE_WORK.md` §8. We document the gap honestly
rather than reporting a number we didn't measure. To be direct
about the trade-off: Week 4 was scoped for security hardening
and defense preparation, and measuring a production-like FP rate
under hours of sustained benign traffic competed for that same
time against closing the CORS, login-lockout, and timing-
equalization gaps surfaced by our own security review — we chose
the hardening, and the FP measurement is the first item we would
run post-submission.

**Evidence.** `models/threshold.txt`,
`RECONCILIATION_PHASE2.md` FR_03 notes, `FUTURE_WORK.md` §8.

### Q8: Why did the multi-class head drift — labelling nikto as DoS?

**Answer.** The binary head and the multi-class head train on the
same dataset, but the multi-class head has the harder problem:
eight categories instead of two. In CIC-IDS2017 the feature
signatures for DoS, Web Attack, and Brute Force overlap more
than, say, Port Scan vs Bot. When we run a real attack like
nikto — a web vulnerability scanner — its per-flow features
overlap with DoS features in the training distribution. The
binary head still correctly says "Attack," but the multi-class
head defaults to its strongest neighbour, which is DoS. Mitigation
triggers off the binary label, so the drift doesn't break the
chain — but it does mean the displayed category label is
imperfect on out-of-distribution attacks. Documented in
`lab/ATTACK_VALIDATION.md`.

**Evidence.** `lab/ATTACK_VALIDATION.md`,
`RECONCILIATION_PHASE2.md` FR_03 notes.

### Q9: What about scan and flood attacks — nmap, hping3?

**Answer.** Not detected. Documented architectural limitation.
The `FlowAggregator` in `src/capture/live_capture.py` emits
flows after a timeout or packet-count threshold. `nmap -sS`
sends one or two packets per target port and moves on — those
packets never accumulate into a flow that matches CIC-IDS2017's
training distribution, which is overwhelmingly session-based.
We diagnosed this in Week 1 by running both attack families and
observing zero detections out of thousands of flows for the
scan/flood family versus 25–57% recall for the session family.
The architectural fix is sketched in `FUTURE_WORK.md` §2: a
parallel burst aggregator running sliding-window counters per
(src_ip, dst_port), emitting synthetic scan events to a
separate classifier head. ~3–4 engineer-weeks, designed-on-
paper.

**Evidence.** `lab/ATTACK_VALIDATION.md`, `FUTURE_WORK.md` §2,
`src/capture/live_capture.py` (FlowAggregator).

### Q10: Why not detect encrypted attacks (HTTPS, SSH)?

**Answer.** Not validated in Phase 2. CIC-IDS2017 contains some
encrypted traffic, but our live validation deliberately used
plaintext attacks so we could observe protocol-level behaviour
end-to-end. The path forward is JA3/JA3S TLS fingerprinting and
cert / SNI metadata features, designed in `FUTURE_WORK.md` §4 at
~4–6 engineer-weeks. The honest answer is "we made detection of
the things we could verify our priority, and called out the gap
explicitly" — that is more defensible than claiming encrypted-
channel coverage we never measured.

**Evidence.** `FUTURE_WORK.md` §4, `lab/ATTACK_VALIDATION.md`.

### Q31: Your multi-class model's per-class F1 for Web Attack is about 0.49 — half of every other class. Why, and how would you fix it?

**Answer.** Two reasons, both visible in the training data. First,
class scarcity: in CIC-IDS2017, Web Attack has far fewer flows than
DoS or DDoS even after our balancing step. Our preprocessing in
`src/data/prep_cic2017.py` oversamples minority classes up to
`MIN_PER_CLASS` with 1% Gaussian noise, but that generates near-
duplicates, not genuinely new variance — so the model sees less true
diversity for Web Attack than its raw count suggests. Second, feature
overlap: Web Attack flows are HTTP-heavy, and so are several DoS
variants in CIC-IDS2017, so their flow-level feature signatures sit
close together in feature space. The result is that the multi-class
head's Web Attack signal is weak, and out-of-distribution HTTP attacks
(like `nikto` in our live tests) collapse toward the strongest HTTP
neighbour, which is DoS. Crucially, this is a *labelling-fidelity*
problem, not a *detection* problem: the binary head still correctly
flags these flows as Attack, and mitigation triggers off the binary
label, so a mislabelled-as-DoS web attack still gets detected and can
still be blocked. The fix would be class-weighted or cost-sensitive
training to penalise Web Attack misclassification more heavily, or
HTTP-specific feature engineering — but both require retraining, which
is frozen under `_project/HARD_CONSTRAINTS.md` for Phase 2 and sketched
in `FUTURE_WORK.md` §8.

**Evidence.** `models/model_meta.json` (per-class F1 values),
`src/data/prep_cic2017.py` (balancing / oversampling logic), Q8
(multi-class drift), `lab/ATTACK_VALIDATION.md` (nikto labelled DoS in
live runs).

## Category C: Mitigation

### Q11: Why doesn't your block work when Avast is running?

**Answer.** Avast — and any AV with kernel-mode network
filtering, including Kaspersky, ESET, and Norton — installs a
Windows Filtering Platform callout or NDIS lightweight filter
driver that sits *below* Windows Defender Firewall in the
kernel network stack. When Avast is active, it intercepts
packets before WF evaluates them, so user-mode firewall rules —
including ones we create via `netsh advfirewall firewall add
rule` — are silently bypassed. We diagnosed this in Week 3
through layered testing: manual rule, TCP+port-specific rule,
"block ALL inbound TCP/80" rule — all three failed with zero
hits in `pfirewall.log`. Disabling Avast shields → rules
immediately enforce. This is a co-existence issue between two
security products, documented Microsoft behaviour, and **not a
defect in any AI-IDS component**. `FUTURE_WORK.md` §7 sketches
a WFP-direct alternative path that would sit at the same kernel
layer.

**Evidence.** CHANGES.md Week 3 closeout (2026-05-25),
`tools/diagnose_round2.ps1`, `FUTURE_WORK.md` §7.

### Q12: Why human-in-loop instead of auto-block on detection?

**Answer.** Three reasons. First, false-positive blast radius:
one mis-classification at high confidence could block a
legitimate user before any human sees the alert. Second, the
Phase 1 proposal explicitly excludes "automatic intrusion
prevention" — `RECONCILIATION_PHASE2.md` §6 quotes the relevant
paragraph from the docx verbatim. Adding a human gate keeps us
on the right side of that line. Third, the audit trail is
cleaner with a human approval recorded — defensible if a block
ever needs to be challenged later. Auto-block on
high-confidence detection is sketched as an opt-in narrow
policy in `FUTURE_WORK.md` §3 at ~2–3 engineer-weeks, but it is
an exception path, not the default.

**Evidence.** `RECONCILIATION_PHASE2.md` §6, `FUTURE_WORK.md` §3.

### Q13: What's the two-person rule? Why 5 seconds?

**Answer.** When a user submits a block request, that same user
cannot approve it within 5 seconds of submission — even if they
hold both the analyst and admin roles. This prevents the trivial
bypass where one person rubber-stamps their own block. Five
seconds is short enough to not be operationally painful
(an admin reading a request, deciding, and clicking Approve
takes well over 5 s normally) and long enough to make the
"click both buttons in the same flow" pattern impossible. The
rule is enforced server-side at
`src/serve/mitigation_routes.py:309` — the `requested_by ==
current_user["user_id"]` check fires before the database update,
so `curl` cannot bypass it either. A failed two-person check is
audit-logged as `mitigation.request.approve` with `status =
failure` and a detail string including the elapsed seconds.

**Evidence.** `src/serve/mitigation_routes.py:309`,
`TWO_PERSON_RULE_SECONDS` constant at `:50`,
`tests/test_mitigation_routes.py` for the regression test.

### Q14: What if the admin account is compromised?

**Answer.** A compromised admin can do damage, but every privileged
action they perform is captured in the `audit_log` table in real time.
The log is append-only by convention — no UPDATE or DELETE statements
against it exist in the codebase — though it is not cryptographically
tamper-evident: an attacker with direct SQLite file access can edit
rows. A per-row hash chain for cryptographic tamper-evidence is the
production-grade next step. For the FYP threat model — single host, two
operators — the practical append-only guarantee plus bcrypt cost 12 plus
the 8-hour session TTL bounding a stolen token is the defence. What we
deliberately don't have: multi-factor authentication, hardware-token
requirement, or admin-action approval by a second admin — all scoped out
in `_project/HARD_CONSTRAINTS.md` (no OAuth, no 2FA, no SSO).

**Evidence.** `_project/HARD_CONSTRAINTS.md`, `src/auth/audit.py`,
`src/utils/db.py:131` (audit_log schema).

### Q15: What if someone deletes `data/ids.db`?

**Answer.** All sessions, audit log, users, and mitigation
history are lost. The trained model files in `models/` survive —
those are not in the DB. Recovery is to rebuild via
`tools/bootstrap_admin.py` to create a fresh admin and accept
the history loss. We treat backup the same way any single-file
SQLite deployment does: file-system backup is the operator's
responsibility. A production deployment would schedule backups;
this is not currently in `FUTURE_WORK.md` because the file-system
backup pattern is well-known and adds about a week to operationalise.

**Evidence.** `_project/HARD_CONSTRAINTS.md` (DB additive-only
rule), `tools/bootstrap_admin.py`.

### Q16: Why not block at the router or switch level?

**Answer.** That is the "network-level" enforcement the Phase 1
proposal explicitly excludes. `RECONCILIATION_PHASE2.md` §6
quotes the relevant docx paragraph verbatim:
"The system does not perform automatic enforcement actions such
as packet blocking, traffic filtering, or intrusion prevention
at the network level." Host-level blocking via `netsh` is a
strictly narrower replacement: it blocks at the Windows host
running AI-IDS, not at the network perimeter. Router-level
blocking would require integration with vendor-specific router
APIs, credentials for the router, and a different threat model
where the router itself is trusted infrastructure. All of that
is out of scope by deliberate design.

**Evidence.** `RECONCILIATION_PHASE2.md` §6, Phase 1 proposal
Chapter 2.1.2.

## Category D: Architecture and engineering

### Q17: How does this compare to Snort or Suricata?

**Answer.** Snort and Suricata are signature- and rule-based —
they match traffic against a curated rule set (Emerging Threats
and the like). Strengths: deterministic, fast, well-understood.
Weakness: they require explicit rules for each attack and need
ongoing rule updates as attack patterns evolve. Our system is
ML-based — the binary RF generalises in principle to attacks
that share statistical features with the CIC-IDS2017 training
distribution. Strength: no hand-written rules per attack.
Weakness: opaque (why exactly did the model say Attack?),
bounded by the training distribution. In a real SOC the two
families are complementary — Suricata catches known signatures,
ML catches novel patterns. We did not try to replicate Suricata;
we built the ML side of that pair.

**Evidence.** Design-philosophy answer; no single file evidence.

### Q18: How would you extend this to multi-machine deployment?

**Answer.** `FUTURE_WORK.md` §1 has the full design. Short
version: lightweight endpoint agents in Python reusing the same
`FlowAggregator` from `src/capture/live_capture.py`, packaged as
a standalone service. Agents extract feature dicts locally and
POST them (not raw packets — bandwidth plus privacy) over mTLS
to a central AI-IDS instance running the existing `/predict`
endpoint. Mitigation requests fan out from the central
dashboard: on approval, the central instance signals the
originating agent to issue `netsh` locally, and the agent
returns the result row. Heartbeat every 30 s for liveness;
agent missing > 90 s surfaces as a "stale endpoint" warning.
~6–8 engineer-weeks for an MVP across Windows and Linux,
roughly doubled with production hardening. The reason it is
not in Phase 2: each week spent on multi-machine is a week not
spent closing one of the three explicit Phase 1 viva
questions.

**Evidence.** `FUTURE_WORK.md` §1.

### Q19: Why don't you use deep learning?

**Answer.** Random Forest was the right tool for the dataset
and the scope. CIC-IDS2017 has tens of thousands to millions of
flows depending on subset, with hand-engineered tabular
features — the domain RF excels at. Deep learning on tabular
data at this scale tends to underperform tree ensembles
(see Shwartz-Ziv & Armon, "Tabular Data: Deep Learning is Not
All You Need," 2022). DL would help if we were doing raw-packet
input — PCAP-to-prediction without feature engineering — which
is a different problem and out of scope. RF also gives us
interpretability via feature importances that DL would not.

**Evidence.** Phase 1 proposal Appendix A (dataset choice),
`src/models/train.py` (RF use).

### Q20: What's in the audit log exactly?

**Answer.** Every privileged action: login success, login
failure (with reason), user create / update / disable, capture
start / stop, replay start / stop, every mitigation request,
every approval or denial (including failed two-person checks),
every `netsh` execution with stdout, every unblock. Plus every
401 and 403 — when an analyst hits an admin-only endpoint via
`curl`, that 403 is logged with the actor (or anonymous) and
the path. The schema is in `src/utils/db.py:131`:
`ts, actor_user_id, actor_username, action, target, status,
detail, ip_address, user_agent`. Admin-only view at
`dashboard/pages/2_Audit_Log.py` with prefix filter and CSV
export.

**Evidence.** `src/utils/db.py:131` (schema),
`src/auth/audit.py` (writer), `dashboard/pages/2_Audit_Log.py`
(reader).

### Q21: How do you handle Streamlit's page navigation exposing admin pages to analysts?

**Answer.** Honest limitation in the underlying framework.
Streamlit's built-in `pages/` navigation shows every page name
to every logged-in user — the Users and Audit Log pages are
visible in the analyst's sidebar. We handle this with a
script-top permission check on each admin page: if the user
lacks the permission, the page calls `st.stop()` immediately
and renders nothing. The click is blocked at the server, not
just hidden in the UI, so a manual URL hit can't bypass it
either. A proper fix would require Streamlit nav
customisation that we judged not worth the time in Week 2;
it is a polish item, not a security defect.

**Evidence.** `dashboard/pages/1_Users.py` (script-top check),
CHANGES.md Week 2 entry ("OPTION X visibility").

### Q22: Why is `/predict` not authenticated?

**Answer.** Because it is restricted to loopback callers
(`127.0.0.1`, `::1`, `localhost`) at the request level. Both
the live capture worker and the replay worker POST to
`/predict` from the same process, machine-to-machine, with no
user involved. Adding bearer-token auth to that path would
mean the workers need to manage tokens — added complexity for
no security benefit, since a process that can already loopback
to localhost can already do anything else on the host. The
loopback check at `src/serve/app.py:300` uses
`request.client.host` (socket-level), not `X-Forwarded-For`,
so header-spoofing does not bypass it.

**Evidence.** `src/serve/app.py:299` (the `/predict` handler),
`LOOPBACK_HOSTS` constant at `:64`.

## Category E: Process and validation

### Q23: How did you validate the system end-to-end?

**Answer.** Three layers. (1) Per-component unit tests in
`tests/` — auth has multiple tests around password hashing,
session validity, RBAC enforcement, and audit logging;
mitigation has tests covering the firewall wrapper and the
endpoint behaviour including the two-person rule and the
private-IP rejection. (2) Live attack validation in Week 1 —
Kali VM running real tools against the Windows host,
reproducibility checked across two separate runs five hours
apart, documented in `lab/ATTACK_VALIDATION.md`. (3) Live
mitigation chain test in Week 3 — manual hypothesis tests
H1 through H10 end-to-end with Kali slowhttptest as the
adversary, documented in CHANGES.md Week 3 closeout. The
combination — unit tests for invariants, live tests for
behaviour — is what we treat as "validated."

**Evidence.** `tests/`, `lab/ATTACK_VALIDATION.md`,
CHANGES.md 2026-05-25 Week 3 closeout entry.

### Q24: What was the hardest bug you fixed?

**Answer.** The Avast bypass. Symptom: a `netsh` rule would be
created, visible in `netsh advfirewall firewall show rule`, and
the attacker traffic would keep flowing. No errors anywhere.
We initially suspected our netsh wrapper. We checked rule
syntax, scope, profile binding (domain / private / public) —
all correct. We tried a manual "block ALL inbound TCP/80"
rule by hand — also bypassed. `pfirewall.log` showed zero
entries for blocked packets. That is when we realised something
in the kernel was intercepting before Windows Firewall saw the
packet, and Avast became the candidate. Disabling shields →
rules immediately enforced. The fix was diagnostic discipline,
not code: we wrote `tools/diagnose_firewall_block.ps1` and
`tools/diagnose_round2.ps1` to capture the evidence, and we
documented the workaround for the demo. The behaviour itself
is documented Microsoft / AV-vendor interaction; no AI-IDS
code change resolves it.

**Evidence.** CHANGES.md Week 3 entries
(`tools/diagnose_round2.ps1`), `FUTURE_WORK.md` §7.

### Q25: What would you do differently if you started over?

**Answer.** Two things. First, validate the AV co-existence
assumption in Week 1 rather than Week 3 — that one finding
shifted what "demo-ready" meant and we found it late. Second,
design the FlowAggregator from day one to handle both
session-based and burst-style attacks; we shipped session-only
because CIC-IDS2017 emphasises sessions, and that cost us
scan / flood detection (documented in
`lab/ATTACK_VALIDATION.md`). Neither is a project-failing
decision in retrospect, but both are calls we would make
differently with the knowledge we have now.

**Evidence.** `lab/ATTACK_VALIDATION.md` (scan/flood limitation),
CHANGES.md Week 3 closeout (Avast finding).

### Q26: What's the smoke test? What does it actually verify?

**Answer.** `tests/test_smoke.py` boots the real FastAPI app
in-process via FastAPI's `TestClient` — the same app code that
runs in production, with the real lifespan that loads the Random
Forest models. It then exercises the full chain in three tests:
(1) app boots and `/health` returns 200, (2) all nine SQLite
tables are present (4 Phase 1 ERD + 3 Week 2 auth + 2 Week 3
mitigation), (3) the end-to-end production path — admin login →
analyst login → POST `/predict` → analyst submits a mitigation
request → admin approves it (the two-person rule is satisfied
legitimately because they are different users) → `firewall.block_ip`
is called → audit log captures every action. `firewall.block_ip`
is patched with `unittest.mock.patch.object` so no real `netsh`
runs. The test runs in roughly 13 seconds — dominated by the
lifespan loading the binary RF model (~4.6 s) and the multi-class
RF model (~0.9 s), with everything else under 1 s. It does not
need admin elevation, a network interface, the Kali VM, or Avast
disabled. It is the safety net for refactors: if it passes, the
wiring from auth through mitigation through audit is intact.

**Evidence.** `tests/test_smoke.py` (277 lines, 3 tests),
CHANGES.md Week 4 W4-Sub4a entry, README.md `## Tests` section.

## Category F: Open / hostile questions

### Q27: Why should we trust this system in production?

**Answer.** You shouldn't, in its current form — and we don't
claim otherwise. It is an FYP demonstrating an architecture and
validating an approach. Production readiness would require:
AV co-existence resolved (`FUTURE_WORK.md` §7), scan / flood
detection added (§2), retraining pipeline (§8), encrypted-
channel coverage (§4), endpoint agent for multi-host (§1), and
a measured false-positive rate under sustained legitimate
traffic. We made a deliberate trade between "ship something
narrow and well-validated" and "ship something broader and
partially-tested." Phase 2 chose narrow because that matches
both the FYP timeline and the panel's stated request to close
the three viva questions.

**Evidence.** `FUTURE_WORK.md` (whole document).

### Q28: This looks like a lot of work for a four-month project. Did your supervisor actually verify all of this?

**Answer.** Phase 1 (Sep–Dec 2025) shipped the detection model,
the dashboard, and the replay demo — defended in Dec 2025.
Phase 2 (Jan–May 2026) is what we are discussing now: real-
attack validation in Week 1, RBAC + audit in Week 2, mitigation
workflow in Week 3, polish and defence prep in Week 4. Every
week's deliverable was checked in to `CHANGES.md` and verified
live before move-on — the supervisor was looped in at each
stage. The full provenance is in the repo: every commit, every
test result, every dated `CHANGES.md` entry. The system runs in
front of you on this laptop; that is the verification you can
do right now.

**Evidence.** `CHANGES.md` (full Phase 2 history), live demo.

### Q29: Your API uses CORS. Can a malicious website hit your endpoints?

**Answer.** No. The CORS config at `src/serve/app.py:215` pins
allowed origins to `["http://localhost:8501", "http://127.0.0.1:8501"]`
— the Streamlit dashboard's origins, nothing else. A malicious page
on another origin can't initiate cross-origin requests against the
API. Combined with the loopback gate on `/predict` (which checks
`request.client.host == 127.0.0.1` and ignores `X-Forwarded-For`),
the API is reachable only from the dashboard running on the same host.
Earlier development used `allow_origins=["*"]` for cross-browser
testing; the production-correct pinning was applied in W4-Sub4d.

**Evidence.** `src/serve/app.py` CORS config; CHANGES.md W4-Sub4d entry.

### Q30: Can I enumerate usernames or brute-force a password?

**Answer.** No, both mitigations are in place. (1) Timing
equalization: at `src/serve/auth_routes.py`, the missing-user code
path now calls a dummy bcrypt verify against a known-bad hash, so
total response time is roughly equal regardless of whether the
username exists. The ~250ms delta that previously enabled timing-
based username enumeration is gone. (2) Account lockout: after 5
failed login attempts against a username, the account is locked for
15 minutes. Lockouts are recorded in the `login_attempts` table and
audit-logged as `auth.login.locked`. Successful logins reset the
counter atomically. Threshold and duration are tunable via constants
in `auth_routes.py`. Per-username (not per-IP) lockout was a
deliberate choice — IP-based adds complexity (proxy support, NAT
considerations) without meaningful threat-model gain for the
single-host two-operator deployment.

**Evidence.** `src/serve/auth_routes.py` (lockout logic),
`src/auth/passwords.py` (dummy hash + verify_dummy_for_timing),
`tests/test_login_lockout.py` (3 tests covering dummy verify invocation,
lockout trigger, counter reset).

### Q32: Put yourself in the attacker's shoes — how would someone bypass this system?

**Answer.** Three honest bypass paths, in order of how hard they are to
close. First, scan and flood attacks: `nmap -sS` and `hping3 --flood`
produce one- or two-packet singleton flows that never accumulate into
the per-flow feature window the classifier needs, so they pass
undetected — we documented zero detections across 6 585 captured flows
in Rounds 1–2 of Week 1 and sketched the fix (a parallel burst
aggregator with sliding-window counters per src_ip/dst_port) in
`FUTURE_WORK.md` §2. Second, encrypted channels: we validated against
plaintext HTTP and SSH attacks; a TLS-wrapped attack would hide its
payload-level behaviour from us, and we did not validate that case
(`FUTURE_WORK.md` §4 covers JA3/SNI metadata-based approaches that
would catch a meaningful slice of it). Third — and this is the hardest
to defend against — adversarial pacing: a competent attacker who knows
this system could deliberately slow and shape their traffic to mimic
the inter-arrival-time and packet-size distributions the model
considers benign, hiding inside the normal-traffic envelope. We name
this explicitly in `lab/ATTACK_VALIDATION.md` §6 (Threats to Validity)
as an unmeasured risk. The honest position is that no single-model
flow-based IDS fully closes the adversarial-pacing gap on its own —
which is exactly why production deployments ensemble ML detection with
signature-based tools like Suricata and with rate / volume anomaly
detectors that catch what per-flow classification misses.

**Evidence.** `lab/ATTACK_VALIDATION.md` (§5 known limitations and §6
threats to validity, including the scan/flood zero-detection finding
and the adversarial-pacing note), Q9 (scan / flood), Q10 (encrypted
channels), `FUTURE_WORK.md` §2 and §4.
