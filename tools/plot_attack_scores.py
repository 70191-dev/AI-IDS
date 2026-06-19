"""
plot_attack_scores.py
─────────────────────
Reads lab/results/<attack_name>/raw_detections.csv and writes:
  - score_histogram.png   (25 bins, threshold marked)
  - attack_type_pie.png   (label=1 rows only)

Usage:
    python tools/plot_attack_scores.py --attack-name nmap_syn
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # headless
import matplotlib.pyplot as plt  # noqa: E402


def _find_project_root(start: Path) -> Path:
    p = start.resolve()
    while p != p.parent:
        if (p / "env" / "requirements.txt").exists():
            return p
        p = p.parent
    return Path.cwd()


PROJECT_ROOT = _find_project_root(Path(__file__).parent)
RESULTS_ROOT = PROJECT_ROOT / "lab" / "results"
THRESHOLD_FILE = PROJECT_ROOT / "models" / "threshold.txt"


def _read_threshold(default: float = 0.5) -> float:
    try:
        return float(THRESHOLD_FILE.read_text().strip())
    except (FileNotFoundError, ValueError):
        return default


def _read_rows(csv_path: Path) -> list[dict]:
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def _plot_histogram(scores: list[float], threshold: float, attack_name: str,
                    out_path: Path) -> None:
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.hist(scores, bins=25, color="#3b82f6", edgecolor="black", alpha=0.85)
    ax.axvline(threshold, color="red", linestyle="--", linewidth=1.5,
               label=f"threshold = {threshold:.4f}")
    ax.set_xlabel("score")
    ax.set_ylabel("flow count")
    ax.set_title(f"Score distribution: {attack_name}")
    ax.set_xlim(0.0, 1.0)
    ax.legend(loc="upper right")
    ax.grid(axis="y", linestyle=":", alpha=0.5)
    fig.tight_layout()
    fig.savefig(out_path, dpi=120)
    plt.close(fig)


def _plot_pie(attack_type_counts: dict[str, int], attack_name: str,
              out_path: Path) -> None:
    fig, ax = plt.subplots(figsize=(7, 7))
    if not attack_type_counts:
        ax.text(0.5, 0.5, "no attack-labeled flows in window",
                ha="center", va="center", fontsize=14, color="#555")
        ax.set_axis_off()
    else:
        labels = list(attack_type_counts.keys())
        sizes = list(attack_type_counts.values())
        ax.pie(sizes, labels=labels, autopct="%1.1f%%", startangle=90,
               textprops={"fontsize": 10})
        ax.axis("equal")
    ax.set_title(f"Predicted attack types: {attack_name}")
    fig.tight_layout()
    fig.savefig(out_path, dpi=120)
    plt.close(fig)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("Usage:")[0].strip())
    ap.add_argument("--attack-name", required=True)
    args = ap.parse_args(argv)

    in_dir = RESULTS_ROOT / args.attack_name
    csv_path = in_dir / "raw_detections.csv"
    if not csv_path.exists():
        print(f"ERROR: {csv_path} not found. "
              f"Run tools/extract_attack_window.py first.", file=sys.stderr)
        return 2

    rows = _read_rows(csv_path)
    if not rows:
        print(f"ERROR: {csv_path} is empty (header only). "
              f"Nothing to plot.", file=sys.stderr)
        return 2

    scores: list[float] = []
    attack_type_counts: dict[str, int] = {}
    for r in rows:
        try:
            scores.append(float(r["score"]))
        except (KeyError, ValueError, TypeError):
            continue
        if r.get("label") == "1" and r.get("attack_type"):
            atype = r["attack_type"]
            attack_type_counts[atype] = attack_type_counts.get(atype, 0) + 1

    if not scores:
        print(f"ERROR: no parseable 'score' values in {csv_path}.",
              file=sys.stderr)
        return 2

    threshold = _read_threshold()

    hist_path = in_dir / "score_histogram.png"
    pie_path = in_dir / "attack_type_pie.png"
    _plot_histogram(scores, threshold, args.attack_name, hist_path)
    _plot_pie(attack_type_counts, args.attack_name, pie_path)

    print(f"wrote: {hist_path.relative_to(PROJECT_ROOT)}")
    print(f"wrote: {pie_path.relative_to(PROJECT_ROOT)}")
    print(f"  scores plotted: {len(scores)}")
    print(f"  attack types  : {dict(attack_type_counts) or '(none)'}")
    print(f"  threshold     : {threshold:.4f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
