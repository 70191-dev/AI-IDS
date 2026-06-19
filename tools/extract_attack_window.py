"""
extract_attack_window.py
────────────────────────
Pull every detection that landed inside an attack's time window and where the
Kali attacker IP was either source or destination. Writes a per-attack folder
under lab/results/<attack_name>/ with raw_detections.csv + summary.json.

Usage:
    python tools/extract_attack_window.py \
        --attack-name nmap_syn \
        --start "2026-05-22 14:30:00" \
        --end   "2026-05-22 14:35:00" \
        --kali-ip 192.168.56.101 \
        [--db data/ids.db]
"""

from __future__ import annotations

import argparse
import csv
import json
import sqlite3
import statistics
import sys
from datetime import datetime
from pathlib import Path


# ── Project root discovery (same pattern as src/utils/db.py) ──────────
def _find_project_root(start: Path) -> Path:
    p = start.resolve()
    while p != p.parent:
        if (p / "env" / "requirements.txt").exists():
            return p
        p = p.parent
    return Path.cwd()


PROJECT_ROOT = _find_project_root(Path(__file__).parent)
DEFAULT_DB = PROJECT_ROOT / "data" / "ids.db"
RESULTS_ROOT = PROJECT_ROOT / "lab" / "results"


QUERY = """
SELECT t.id, t.ts, t.flow_id, t.src_ip, t.dst_ip, t.src_port,
       t.dst_port, t.protocol, t.duration, t.source_mode,
       d.score, d.label, d.label_text, d.attack_type,
       d.attack_confidence, d.threshold, a.severity, a.status
FROM traffic_flow t
JOIN detection_result d ON d.flow_id = t.id
LEFT JOIN alert a ON a.detection_id = d.id
WHERE t.ts BETWEEN ? AND ?
  AND (t.src_ip = ? OR t.dst_ip = ?)
ORDER BY t.id ASC
"""


def _normalize_ts(s: str) -> str:
    """Accept 'YYYY-MM-DD HH:MM:SS' (CLI input) and return ISO 8601 with 'T'
    separator to match how src/utils/db.py stores ts."""
    dt = datetime.fromisoformat(s.strip())
    return dt.isoformat(timespec="seconds")


def _safe_mean(vals: list[float]) -> float:
    return float(statistics.fmean(vals)) if vals else 0.0


def _safe_median(vals: list[float]) -> float:
    return float(statistics.median(vals)) if vals else 0.0


def _build_summary(
    rows: list[sqlite3.Row],
    attack_name: str,
    start: str,
    end: str,
    kali_ip: str,
) -> dict:
    total = len(rows)
    attack_labeled = sum(1 for r in rows if r["label"] == 1)
    benign_labeled = total - attack_labeled

    attack_type_breakdown: dict[str, int] = {}
    for r in rows:
        if r["label"] == 1 and r["attack_type"]:
            attack_type_breakdown[r["attack_type"]] = (
                attack_type_breakdown.get(r["attack_type"], 0) + 1
            )

    severity_breakdown: dict[str, int] = {}
    for r in rows:
        sev = r["severity"]
        if sev:
            severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1

    scores = [float(r["score"]) for r in rows]
    return {
        "attack_name": attack_name,
        "start": start,
        "end": end,
        "kali_ip": kali_ip,
        "total_flows": total,
        "attack_labeled": attack_labeled,
        "benign_labeled": benign_labeled,
        "attack_type_breakdown": attack_type_breakdown,
        "severity_breakdown": severity_breakdown,
        "score_min": float(min(scores)) if scores else 0.0,
        "score_max": float(max(scores)) if scores else 0.0,
        "score_mean": _safe_mean(scores),
        "score_median": _safe_median(scores),
    }


def _write_csv(rows: list[sqlite3.Row], out_path: Path) -> None:
    columns = [
        "id", "ts", "flow_id", "src_ip", "dst_ip", "src_port", "dst_port",
        "protocol", "duration", "source_mode", "score", "label", "label_text",
        "attack_type", "attack_confidence", "threshold", "severity", "status",
    ]
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(columns)
        for r in rows:
            w.writerow([r[c] for c in columns])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("Usage:")[0].strip())
    ap.add_argument("--attack-name", required=True)
    ap.add_argument("--start", required=True, help='format: "YYYY-MM-DD HH:MM:SS"')
    ap.add_argument("--end", required=True, help='format: "YYYY-MM-DD HH:MM:SS"')
    ap.add_argument("--kali-ip", required=True)
    ap.add_argument("--db", default=str(DEFAULT_DB))
    args = ap.parse_args(argv)

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"ERROR: SQLite DB not found at {db_path}", file=sys.stderr)
        return 2

    try:
        start_iso = _normalize_ts(args.start)
        end_iso = _normalize_ts(args.end)
    except ValueError as e:
        print(f"ERROR: bad timestamp ({e}). Expected 'YYYY-MM-DD HH:MM:SS'.",
              file=sys.stderr)
        return 2

    if end_iso < start_iso:
        print("ERROR: --end is before --start.", file=sys.stderr)
        return 2

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            QUERY, (start_iso, end_iso, args.kali_ip, args.kali_ip)
        ).fetchall()
    finally:
        conn.close()

    out_dir = RESULTS_ROOT / args.attack_name
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "raw_detections.csv"
    json_path = out_dir / "summary.json"

    _write_csv(rows, csv_path)
    summary = _build_summary(rows, args.attack_name, start_iso, end_iso, args.kali_ip)
    json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    if not rows:
        print(f"[{args.attack_name}] no flows found in window "
              f"{start_iso} .. {end_iso} for kali_ip={args.kali_ip}")
    print(json.dumps(summary, indent=2))
    print(f"\nwrote: {csv_path.relative_to(PROJECT_ROOT)}")
    print(f"wrote: {json_path.relative_to(PROJECT_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
