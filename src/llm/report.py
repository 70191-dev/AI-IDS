"""
AI-generated security incident report (advisory, local LLM via Ollama).

Reads an existing alert's stored data and asks a LOCAL Ollama model to write a
professional plain-text incident report. ADVISORY / downstream only: never
affects detection, scoring, mitigation, or the database (read-only on data).
No cloud. If Ollama is unavailable, raises ReportUnavailable and the caller
degrades gracefully.
"""
from __future__ import annotations

import os
import sys
import requests
from typing import List, Optional

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:1b")
OLLAMA_FALLBACK_MODEL = os.environ.get("OLLAMA_FALLBACK_MODEL", "llama3.2:1b")
OLLAMA_TIMEOUT = float(os.environ.get("OLLAMA_TIMEOUT", "120"))


class ReportUnavailable(Exception):
    """Raised when the local LLM service can't be reached or fails."""


def is_available() -> bool:
    try:
        r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=2)
        return r.status_code == 200
    except requests.RequestException:
        return False


def _build_prompt(alert: dict, recommendations: List[str], description: str) -> str:
    rec_block = "\n".join(f"- {r}" for r in recommendations) if recommendations else "- (no specific playbook entries)"
    return f"""You are a SOC analyst writing a formal security incident report. Use ONLY the facts provided. Do not invent IPs, times, tools, vendors, or numbers not given. Do not dispute the detection (it came from a validated ML model).

FACTS:
- Alert ID: {alert.get('alert_id')}
- Attack type: {alert.get('attack_type') or 'Unknown'}
- Attack family description: {description or 'N/A'}
- Severity: {alert.get('severity') or 'Unknown'}
- Detection confidence score: {alert.get('score')}
- Source (attacker) IP: {alert.get('src_ip') or 'unknown'}
- Target port: {alert.get('dst_port') or 'unknown'}
- Detection time: {alert.get('created_at') or 'unknown'}

APPROVED RESPONSE PLAYBOOK (base your recommended actions ONLY on these):
{rec_block}

Write a plain-text incident report with these labelled sections, in this order:
SECURITY INCIDENT REPORT
Summary (2-3 sentences)
Incident Details (attacker IP, target port, severity, confidence, time)
What Happened (plain-English explanation of this attack type)
Severity Justification (1-2 sentences tied to the confidence score)
Recommended Actions (numbered, based on the playbook above)
Evidence (alert id, score)

Do not use markdown symbols like # or *. Plain text only. Keep under 320 words."""


def _call_model(prompt: str, model: str) -> str:
    print(f"[report.llm] POST /api/generate model={model} (timeout={OLLAMA_TIMEOUT}s)…", file=sys.stderr, flush=True)
    resp = requests.post(
        f"{OLLAMA_URL}/api/generate",
        json={"model": model, "prompt": prompt, "stream": False, "keep_alive": "30m", "options": {"temperature": 0.2}},
        timeout=OLLAMA_TIMEOUT,
    )
    if resp.status_code != 200:
        raise ReportUnavailable(f"LLM HTTP {resp.status_code}: {resp.text[:200]}")
    data = resp.json()
    text = (data.get("response") or "").strip()
    if not text:
        raise ReportUnavailable("LLM returned empty response")
    print(f"[report.llm] got {len(text)} chars from {model}", file=sys.stderr, flush=True)
    return text


def generate_report(alert: dict, recommendations: Optional[List[str]] = None, description: str = "") -> str:
    """Return a plain-text incident report, or raise ReportUnavailable."""
    prompt = _build_prompt(alert, recommendations or [], description)
    try:
        return _call_model(prompt, OLLAMA_MODEL)
    except (requests.RequestException, ReportUnavailable) as e:
        print(f"[report.llm] primary model {OLLAMA_MODEL} failed ({e}); trying fallback {OLLAMA_FALLBACK_MODEL}", file=sys.stderr, flush=True)
        try:
            return _call_model(prompt, OLLAMA_FALLBACK_MODEL)
        except (requests.RequestException, ReportUnavailable) as e2:
            raise ReportUnavailable(f"Local LLM failed on both models: {e2}") from e2
