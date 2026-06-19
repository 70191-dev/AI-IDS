# AI-IDS — Phase 2 Project Memory

This is the always-loaded project context for Claude Code. Keep it
under 100 lines.

## What this project is

AI-Driven Intrusion Detection and Threat Mitigation System for Secure
Networks. FYP Fall-2025-104, University of Lahore. Two students
(Muhammad Usman Tariq, Muhammad Mousa Khan), supervisor Dr. Nadeem
Iqbal. Phase 1 shipped and was defended. We are now building Phase 2
on top of the preserved Phase 1 ML pipeline.

## Where to find the rest

| What you need | Read |
|---|---|
| Hard constraints (what NOT to touch) | _project/HARD_CONSTRAINTS.md |
| The 4-week Phase 2 plan | _project/4_WEEK_PLAN.md |
| How to behave in this project | _project/HOW_TO_WORK_HERE.md |
| Current architecture + state | CURRENT_STATE.md |
| Recent change log | CHANGES.md |
| What stage we're in now | _stages/CURRENT_STAGE.md |
| Stage-specific brief | _stages/week_N_*/CONTEXT.md (where N is current week) |

## How to start any session

1. Read _stages/CURRENT_STAGE.md to find out which week is active
2. Read that week's _stages/week_N_*/CONTEXT.md for the active brief
3. Skim _project/HARD_CONSTRAINTS.md every session — never violate
4. Refer to CURRENT_STATE.md and CHANGES.md only when needed for context

## Behavior rules

- If a task would require violating HARD_CONSTRAINTS.md, STOP and ask
  the user before doing anything. Never silently override.
- Update CHANGES.md (dated section) after non-trivial work.
- Update CURRENT_STATE.md only when the actual project state changes
  meaningfully.
- Prefer minimal-risk targeted edits over refactors. The user is a
  final-year student under deadline pressure.
- Diagnostic-before-fix: when something fails, first write a read-only
  diagnostic, report findings, THEN propose a fix. Don't guess-fix.
