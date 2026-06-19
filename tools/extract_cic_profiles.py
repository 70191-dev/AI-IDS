"""
Extract per-class feature profiles from CIC-IDS2017 training data.
Outputs data/cic_profiles.json for use by replay_loop.py.

Usage:  python tools/extract_cic_profiles.py
"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
TRAIN_PATH = ROOT / "data" / "processed" / "train.parquet"
META_PATH = ROOT / "models" / "model_meta.json"
OUT_PATH = ROOT / "data" / "cic_profiles.json"


def main():
    if not TRAIN_PATH.exists():
        print(f"[!] Training data not found: {TRAIN_PATH}")
        sys.exit(1)
    if not META_PATH.exists():
        print(f"[!] Model metadata not found: {META_PATH}")
        sys.exit(1)

    with open(META_PATH) as f:
        meta = json.load(f)
    feature_names = meta["feature_names"]
    class_names = meta["class_names"]

    print(f"[*] Loading {TRAIN_PATH} ...")
    df = pd.read_parquet(TRAIN_PATH)
    print(f"    Rows: {len(df):,}  Columns: {list(df.columns)[:5]}...")

    # Identify label column (prefer attack_type for class names)
    label_col = None
    for candidate in ["attack_type", "attack_class", "label_name", "label", "Label", "class"]:
        if candidate in df.columns:
            # Check it has string class names, not just numeric
            sample = df[candidate].iloc[0]
            if isinstance(sample, str) or candidate == "attack_type":
                label_col = candidate
                break
    if label_col is None:
        print("[!] Could not find label column with class names")
        sys.exit(1)
    print(f"    Label column: {label_col}")
    print(f"    Classes found: {sorted(df[label_col].unique())}")

    profiles = {}
    for cls in class_names:
        subset = df[df[label_col] == cls]
        if len(subset) == 0:
            print(f"    [!] No rows for class '{cls}', skipping")
            continue

        cls_profile = {}
        for feat in feature_names:
            if feat not in df.columns:
                continue
            vals = subset[feat].dropna()
            if len(vals) == 0:
                continue
            q25 = float(np.percentile(vals, 25))
            q75 = float(np.percentile(vals, 75))
            cls_profile[feat] = {
                "median": float(np.median(vals)),
                "q25": q25,
                "q75": q75,
                "mean": float(np.mean(vals)),
                "std": float(np.std(vals)),
                "q05": float(np.percentile(vals, 5)),
                "q95": float(np.percentile(vals, 95)),
            }
        profiles[cls] = cls_profile
        print(f"    {cls}: {len(subset):,} rows, {len(cls_profile)} features profiled")

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_PATH, "w") as f:
        json.dump(profiles, f, indent=2)

    print(f"\n[OK] Saved profiles to {OUT_PATH}")
    print(f"     Classes: {list(profiles.keys())}")
    if profiles:
        print(f"     Features per class: {len(next(iter(profiles.values())))}")
    else:
        print("     WARNING: No profiles extracted!")


if __name__ == "__main__":
    main()
