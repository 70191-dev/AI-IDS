# Hard Constraints — DO NOT VIOLATE

These rules are absolute. If a task would require breaking any of them,
stop and ask the user. Never override silently.

## Phase 1 brain — preserved

- DO NOT modify src/models/train.py
- DO NOT modify any file in models/ (trained .joblib files)
- DO NOT change the 50-feature UNIFIED_FEATURES schema in
  src/data/prep_cic2017.py or src/data/mock_data.py
- DO NOT modify models/threshold.txt without (a) explicit user
  approval AND (b) backing up the original to
  models/threshold_phase1.txt first
- DO NOT modify the FlowAggregator logic in
  src/capture/live_capture.py. The L2listen import and the
  src_ip/dst_ip extraction are already fixed; do not refactor.

## Database — additive only

- DO NOT rename or restructure the four ERD tables:
  traffic_flow, detection_result, alert, mitigation_record
- Adding NEW tables (e.g. user, session, audit_log for Week 2) is fine
- DO NOT change column types or drop columns on existing tables
- Foreign keys on existing tables stay intact

## API — additive only

- DO NOT change the /predict request OR response contract
- Adding NEW endpoints is fine
- Adding NEW optional fields to existing request models is fine
  (the IP-fields hotfix is the precedent)

## Stack — do not introduce

For Phase 2 we explicitly stay on the Phase 1 stack. Do NOT introduce:

- PostgreSQL (SQLite is the deliberate choice)
- NiceGUI, React, Vue, or any frontend rewrite (Streamlit stays)
- Endpoint agents (out of scope)
- Docker / docker-compose (out of scope)
- PyInstaller / installers (out of scope)
- Multi-tenant isolation
- OAuth, SSO, 2FA, email verification, password reset flows
- Redis, RabbitMQ, Celery
- Any technology not already in env/requirements.txt unless explicitly
  approved by the user in chat

If unsure whether something counts as "introducing a new stack
component", ASK.

## Scope discipline

- Two roles only: admin and analyst. No viewer, no auditor.
- Single-machine deployment. No multi-machine work.
- Mitigation = netsh advfirewall on Windows. No iptables / Linux
  branches.
- IPs must validate as public before block. Reject private ranges
  (127/8, 10/8, 192.168/16, 172.16/12) unless allow_private=True is
  explicit.
