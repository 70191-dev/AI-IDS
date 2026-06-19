"""
CIC-IDS2017 Dataset Processor
──────────────────────────────
Downloads: https://www.unb.ca/cic/datasets/ids-2017.html

Outputs data in SAME format as mock_data.py (unified feature set).
Both mock and CIC data produce identical columns ->models are interchangeable.

Key improvements over raw CIC data:
  - Strips leading spaces from column names
  - Maps 78 CIC columns to 50 unified snake_case features
  - Stratified class balancing (downsample benign, oversample rare attacks)
  - Handles inf/nan values and duplicate rows

Usage:
    python src/data/prep_cic2017.py
"""

import pandas as pd
import numpy as np
import json
from pathlib import Path

# ── Project root ─────────────────────────────────────────────
_p = Path(__file__).resolve().parent
while _p != _p.parent:
    if (_p / "env" / "requirements.txt").exists():
        break
    _p = _p.parent
else:
    _p = Path.cwd()
PROJECT_ROOT = _p

# Look for CIC data in multiple possible locations
SEARCH_DIRS = [
    PROJECT_ROOT / "data" / "downloads" / "MachineLearningCSV" / "MachineLearningCVE",
    PROJECT_ROOT / "data" / "downloads" / "MachineLearningCSV",
    PROJECT_ROOT / "data" / "downloads",
]
OUT = PROJECT_ROOT / "data" / "processed"
OUT.mkdir(parents=True, exist_ok=True)

# All known CIC-IDS2017 CSV files
ALL_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]

# ── CIC column ->snake_case name mapping ─────────────────────
# Maps CIC-IDS2017 column names to the SAME names used by mock_data.py
CIC_COLUMN_MAP = {
    # Base features (match mock_data.py base features)
    "Flow Duration":        "flow_duration",
    "Tot Fwd Pkts":         "total_fwd_packets",
    "Total Fwd Packets":    "total_fwd_packets",
    "Tot Bwd Pkts":         "total_backward_packets",
    "Total Backward Packets": "total_backward_packets",
    "TotLen Fwd Pkts":      "total_length_of_fwd_packets",
    "Total Length of Fwd Packets": "total_length_of_fwd_packets",
    "TotLen Bwd Pkts":      "total_length_of_bwd_packets",
    "Total Length of Bwd Packets": "total_length_of_bwd_packets",
    "Fwd Pkt Len Mean":     "fwd_packet_length_mean",
    "Fwd Packet Length Mean": "fwd_packet_length_mean",
    "Bwd Pkt Len Mean":     "bwd_packet_length_mean",
    "Bwd Packet Length Mean": "bwd_packet_length_mean",
    "Flow IAT Mean":        "flow_iat_mean",
    "Flow IAT Std":         "flow_iat_std",
    "Fwd IAT Mean":         "fwd_iat_mean",
    "Bwd IAT Mean":         "bwd_iat_mean",
    "SYN Flag Cnt":         "syn_flag_count",
    "SYN Flag Count":       "syn_flag_count",
    "RST Flag Cnt":         "rst_flag_count",
    "RST Flag Count":       "rst_flag_count",
    "PSH Flag Cnt":         "psh_flag_count",
    "PSH Flag Count":       "psh_flag_count",
    "ACK Flag Cnt":         "ack_flag_count",
    "ACK Flag Count":       "ack_flag_count",
    "FIN Flag Cnt":         "fin_flag_count",
    "FIN Flag Count":       "fin_flag_count",
    "URG Flag Cnt":         "urg_flag_count",
    "URG Flag Count":       "urg_flag_count",
    "Dst Port":             "destination_port",
    "Destination Port":     "destination_port",
    "Down/Up Ratio":        "down_up_ratio",
    "Init Fwd Win Byts":    "init_win_bytes_forward",
    "Init_Win_bytes_forward": "init_win_bytes_forward",
    "Init Bwd Win Byts":    "init_win_bytes_backward",
    "Init_Win_bytes_backward": "init_win_bytes_backward",
    "Active Mean":          "active_mean",
    "Idle Mean":            "idle_mean",

    # Derived features — CIC has these natively
    "Fwd Pkt Len Max":      "fwd_packet_length_max",
    "Fwd Packet Length Max": "fwd_packet_length_max",
    "Fwd Pkt Len Std":      "fwd_packet_length_std",
    "Fwd Packet Length Std": "fwd_packet_length_std",
    "Bwd Pkt Len Max":      "bwd_packet_length_max",
    "Bwd Packet Length Max": "bwd_packet_length_max",
    "Bwd Pkt Len Std":      "bwd_packet_length_std",
    "Bwd Packet Length Std": "bwd_packet_length_std",
    "Fwd IAT Std":          "fwd_iat_std",
    "Bwd IAT Std":          "bwd_iat_std",
    "Fwd Seg Size Avg":     "avg_fwd_segment_size",
    "Avg Fwd Segment Size": "avg_fwd_segment_size",
    "Bwd Seg Size Avg":     "avg_bwd_segment_size",
    "Avg Bwd Segment Size": "avg_bwd_segment_size",
    "Subflow Fwd Pkts":     "subflow_fwd_packets",
    "Subflow Fwd Packets":  "subflow_fwd_packets",
    "Subflow Fwd Byts":     "subflow_fwd_bytes",
    "Subflow Fwd Bytes":    "subflow_fwd_bytes",
    "Subflow Bwd Pkts":     "subflow_bwd_packets",
    "Subflow Bwd Packets":  "subflow_bwd_packets",
    "Subflow Bwd Byts":     "subflow_bwd_bytes",
    "Subflow Bwd Bytes":    "subflow_bwd_bytes",
    "Active Std":           "active_std",
    "Idle Std":             "idle_std",

    # Rate features — CIC has these natively
    "Flow Byts/s":          "flow_bytes_per_s",
    "Flow Bytes/s":         "flow_bytes_per_s",
    "Flow Pkts/s":          "flow_packets_per_s",
    "Flow Packets/s":       "flow_packets_per_s",

    # Additional derived features CIC has natively
    "Fwd PSH Flags":        "fwd_psh_flags",
    "Bwd PSH Flags":        "_bwd_psh_flags",
    "Fwd URG Flags":        "fwd_urg_flags",
    "Bwd URG Flags":        "_bwd_urg_flags",
    "Fwd Header Length":    "fwd_header_length",
    "Bwd Header Length":    "bwd_header_length",
    "Fwd Packets/s":        "fwd_packets_per_s",
    "Bwd Packets/s":        "bwd_packets_per_s",
    "Min Packet Length":    "min_packet_length",
    "Max Packet Length":    "max_packet_length",
    "Packet Length Mean":   "packet_length_mean",
    "Packet Length Std":    "packet_length_std",
    "Average Packet Size":  "average_packet_size",
}

# ── Class balancing config ────────────────────────────────────
# Downsample majority, oversample minority for balanced training
MAX_PER_CLASS = 100_000   # Cap for benign and large attack classes
MIN_PER_CLASS = 500       # Minimum samples via oversampling


def map_family(label_str):
    """Map CIC-IDS2017 labels to simplified attack families."""
    x = str(label_str).strip().upper()
    if "BENIGN" in x:
        return "Benign"
    if "DDOS" in x:
        return "DDoS"
    if "DOS" in x:  # must be after DDOS
        return "DoS"
    if "PORTSCAN" in x:
        return "Port Scan"
    if "BRUTE" in x or "FTP" in x or "SSH" in x or "PATATOR" in x:
        return "Brute Force"
    if "WEB" in x or "XSS" in x or "SQL" in x:
        return "Web Attack"
    if "BOT" in x:
        return "Bot"
    if "INFILTRATION" in x or "INFILTERAT" in x:
        return "Infiltration"
    if "HEARTBLEED" in x:
        return "DoS"  # Heartbleed is a DoS variant
    return "Other"


def find_data_dir():
    """Find the CIC-IDS2017 CSV directory."""
    for d in SEARCH_DIRS:
        if d.exists() and list(d.glob("*.csv")):
            return d
    # Try recursive search
    dl = PROJECT_ROOT / "data" / "downloads"
    if dl.exists():
        for csv in dl.rglob("*.csv"):
            return csv.parent
    return None


def balance_classes(df, max_per=MAX_PER_CLASS, min_per=MIN_PER_CLASS):
    """Stratified balancing: downsample large classes, oversample tiny ones."""
    balanced = []
    for cls in df["attack_type"].unique():
        cls_df = df[df["attack_type"] == cls]
        n = len(cls_df)
        if n > max_per:
            # Downsample
            cls_df = cls_df.sample(n=max_per, random_state=42)
            print(f"    {cls:15s} {n:>8,} ->{max_per:>8,} (downsampled)")
        elif n < min_per:
            # Oversample with noise
            repeats = int(np.ceil(min_per / n))
            cls_df = pd.concat([cls_df] * repeats, ignore_index=True).head(min_per)
            # Add small noise to feature columns to avoid exact duplicates
            # Exclude label columns from noise
            numeric_cols = [c for c in cls_df.select_dtypes(include=[np.number]).columns
                           if c not in ("label", "label_multi")]
            noise = np.random.normal(0, 0.01, size=(len(cls_df), len(numeric_cols)))
            cls_df[numeric_cols] = cls_df[numeric_cols].values * (1 + noise)
            print(f"    {cls:15s} {n:>8,} ->{min_per:>8,} (oversampled)")
        else:
            print(f"    {cls:15s} {n:>8,}            (kept)")
        balanced.append(cls_df)
    return pd.concat(balanced, ignore_index=True)


def main():
    print("=" * 60)
    print("CIC-IDS2017 Dataset Processor")
    print("=" * 60)

    base = find_data_dir()
    if base is None:
        print(f"\n  ERROR: CIC-IDS2017 dataset not found.")
        print(f"  Download from: https://www.unb.ca/cic/datasets/ids-2017.html")
        print(f"  Extract CSVs into: data/downloads/MachineLearningCSV/")
        return False

    print(f"  Source: {base}")

    # ── Load CSVs ────────────────────────────────────────────
    dfs = []
    for fname in ALL_FILES:
        fpath = base / fname
        if not fpath.exists():
            # Try case-insensitive/partial match
            stem = fname.split(".")[0].split("-")[-1].lower()
            matches = [p for p in base.glob("*.csv") if stem in p.name.lower()]
            if matches:
                fpath = matches[0]
            else:
                print(f"  SKIP  {fname}")
                continue
        print(f"  Loading {fpath.name}...")
        try:
            chunk = pd.read_csv(fpath, low_memory=False, encoding="utf-8",
                                encoding_errors="replace")
            dfs.append(chunk)
        except Exception as e:
            print(f"    ERROR: {e}")

    if not dfs:
        print("\n  No CSV files loaded.")
        return False

    df = pd.concat(dfs, ignore_index=True)
    print(f"\n  Raw: {len(df):,} rows, {len(df.columns)} columns")

    # ── Normalize column names (strip leading/trailing spaces) ──
    df.columns = [c.strip() for c in df.columns]

    # ── Rename columns to unified names ──────────────────────
    rename_actual = {}
    for cic_name, unified_name in CIC_COLUMN_MAP.items():
        if cic_name in df.columns:
            rename_actual[cic_name] = unified_name

    # Check for Label column
    label_col = None
    for candidate in ["Label", " Label", "label"]:
        if candidate in df.columns:
            label_col = candidate
            break
    if label_col is None:
        print("  ERROR: No 'Label' column found!")
        return False

    df.rename(columns=rename_actual, inplace=True)
    print(f"  Mapped {len(rename_actual)} CIC columns to unified names")

    # Drop internal-only mapped columns
    for col in ["_bwd_psh_flags", "_bwd_urg_flags"]:
        if col in df.columns:
            df.drop(columns=[col], inplace=True)

    # ── Coerce to numeric ────────────────────────────────────
    for c in df.columns:
        if c not in [label_col, "Label", "attack_type"]:
            df[c] = pd.to_numeric(df[c], errors="coerce")

    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    before = len(df)
    # Only drop rows where critical features are ALL NaN
    critical_cols = ["flow_duration", "total_fwd_packets", "total_backward_packets"]
    existing_critical = [c for c in critical_cols if c in df.columns]
    if existing_critical:
        df.dropna(subset=existing_critical, inplace=True)
    # Fill remaining NaN with 0
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df[numeric_cols] = df[numeric_cols].fillna(0)
    print(f"  Cleaned: {len(df):,} rows (dropped {before - len(df):,})")

    # ── Build attack labels ──────────────────────────────────
    if label_col != "Label":
        df.rename(columns={label_col: "Label"}, inplace=True)
    df["attack_type"] = df["Label"].apply(map_family)
    df["label"] = (df["attack_type"] != "Benign").astype(int)

    # Drop "Other" class if present (rare edge cases)
    n_other = (df["attack_type"] == "Other").sum()
    if n_other > 0:
        print(f"  Dropped {n_other} rows with 'Other' label")
        df = df[df["attack_type"] != "Other"]

    # Show raw distribution before balancing
    print(f"\n  Raw class distribution:")
    for cls, count in df["attack_type"].value_counts().sort_index().items():
        pct = count / len(df) * 100
        print(f"    {cls:15s} {count:>8,}  ({pct:5.1f}%)")

    # ── Class balancing ──────────────────────────────────────
    print(f"\n  Balancing classes...")
    df = balance_classes(df)

    class_names = sorted(df["attack_type"].unique().tolist())
    class_map = {name: idx for idx, name in enumerate(class_names)}
    # Recompute labels after balancing (oversampling may corrupt them)
    df["label"] = (df["attack_type"] != "Benign").astype(int)
    df["label_multi"] = df["attack_type"].map(class_map).astype(int)

    df.drop(columns=["Label"], inplace=True, errors="ignore")

    # ── Derive any missing features ──────────────────────────
    # These ensure CIC-trained models work with replay_loop traffic
    eps = 0.001
    dur_s = df.get("flow_duration", pd.Series(0, index=df.index)) / 1e6 + eps
    nf = df.get("total_fwd_packets", pd.Series(1, index=df.index)).clip(lower=1)
    nb = df.get("total_backward_packets", pd.Series(0, index=df.index))
    fm = df.get("fwd_packet_length_mean", pd.Series(0, index=df.index))
    bm = df.get("bwd_packet_length_mean", pd.Series(0, index=df.index))

    # Only derive if not already present from CIC columns
    if "flow_bytes_per_s" not in df.columns:
        fl = df.get("total_length_of_fwd_packets", pd.Series(0, index=df.index))
        bl = df.get("total_length_of_bwd_packets", pd.Series(0, index=df.index))
        df["flow_bytes_per_s"] = (fl + bl) / dur_s
    if "flow_packets_per_s" not in df.columns:
        df["flow_packets_per_s"] = (nf + nb) / dur_s
    if "packet_length_mean" not in df.columns:
        df["packet_length_mean"] = (fm + bm) / 2
    if "packet_length_std" not in df.columns:
        df["packet_length_std"] = np.abs(fm - bm)
    if "min_packet_length" not in df.columns:
        df["min_packet_length"] = np.minimum(fm, bm) * 0.3
    if "max_packet_length" not in df.columns:
        df["max_packet_length"] = np.maximum(fm, bm) * 1.5
    if "average_packet_size" not in df.columns:
        df["average_packet_size"] = (fm + bm) / 2
    if "avg_fwd_segment_size" not in df.columns:
        df["avg_fwd_segment_size"] = fm
    if "avg_bwd_segment_size" not in df.columns:
        df["avg_bwd_segment_size"] = bm
    if "fwd_packets_per_s" not in df.columns:
        df["fwd_packets_per_s"] = nf / dur_s
    if "bwd_packets_per_s" not in df.columns:
        df["bwd_packets_per_s"] = nb / dur_s
    if "fwd_psh_flags" not in df.columns:
        df["fwd_psh_flags"] = df.get("psh_flag_count", pd.Series(0, index=df.index))
    if "fwd_urg_flags" not in df.columns:
        df["fwd_urg_flags"] = df.get("urg_flag_count", pd.Series(0, index=df.index))
    if "fwd_header_length" not in df.columns:
        df["fwd_header_length"] = nf * 20
    if "bwd_header_length" not in df.columns:
        df["bwd_header_length"] = nb * 20

    # Fill any remaining features with 0 if CIC doesn't have them
    for feat in ["psh_flag_count", "urg_flag_count", "destination_port"]:
        if feat not in df.columns:
            df[feat] = 0

    # CIC features that mock derives
    if "fwd_iat_std" not in df.columns:
        df["fwd_iat_std"] = df.get("fwd_iat_mean", pd.Series(0, index=df.index)) * 0.8
    if "bwd_iat_std" not in df.columns:
        df["bwd_iat_std"] = df.get("bwd_iat_mean", pd.Series(0, index=df.index)) * 0.8
    if "subflow_fwd_packets" not in df.columns:
        df["subflow_fwd_packets"] = nf
    if "subflow_fwd_bytes" not in df.columns:
        df["subflow_fwd_bytes"] = df.get("total_length_of_fwd_packets", pd.Series(0, index=df.index))
    if "subflow_bwd_packets" not in df.columns:
        df["subflow_bwd_packets"] = nb
    if "subflow_bwd_bytes" not in df.columns:
        df["subflow_bwd_bytes"] = df.get("total_length_of_bwd_packets", pd.Series(0, index=df.index))
    if "active_std" not in df.columns:
        df["active_std"] = df.get("active_mean", pd.Series(0, index=df.index)) * 0.5
    if "idle_std" not in df.columns:
        df["idle_std"] = df.get("idle_mean", pd.Series(0, index=df.index)) * 0.5

    # ── Keep ONLY the 50 unified features + labels ───────────
    meta_cols = ["label", "label_multi", "attack_type"]
    # Use the same 50 features as mock_data.py
    UNIFIED_FEATURES = [
        "flow_duration", "total_fwd_packets", "total_backward_packets",
        "total_length_of_fwd_packets", "total_length_of_bwd_packets",
        "fwd_packet_length_mean", "bwd_packet_length_mean",
        "flow_iat_mean", "flow_iat_std", "fwd_iat_mean", "bwd_iat_mean",
        "syn_flag_count", "rst_flag_count", "psh_flag_count",
        "ack_flag_count", "fin_flag_count", "urg_flag_count",
        "destination_port", "down_up_ratio",
        "init_win_bytes_forward", "init_win_bytes_backward",
        "active_mean", "idle_mean",
        "flow_bytes_per_s", "flow_packets_per_s",
        "packet_length_mean", "packet_length_std",
        "min_packet_length", "max_packet_length",
        "average_packet_size", "avg_fwd_segment_size", "avg_bwd_segment_size",
        "fwd_packets_per_s", "bwd_packets_per_s",
        "fwd_psh_flags", "fwd_urg_flags",
        "fwd_header_length", "bwd_header_length",
        "fwd_packet_length_max", "fwd_packet_length_std",
        "bwd_packet_length_max", "bwd_packet_length_std",
        "fwd_iat_std", "bwd_iat_std",
        "subflow_fwd_packets", "subflow_fwd_bytes",
        "subflow_bwd_packets", "subflow_bwd_bytes",
        "active_std", "idle_std",
    ]

    # Ensure all 50 features exist
    for feat in UNIFIED_FEATURES:
        if feat not in df.columns:
            df[feat] = 0

    keep_cols = UNIFIED_FEATURES + meta_cols
    df = df[keep_cols]

    # ── Clean infinities ─────────────────────────────────────
    df[UNIFIED_FEATURES] = df[UNIFIED_FEATURES].replace([np.inf, -np.inf], 0).fillna(0)

    # ── Shuffle and save ─────────────────────────────────────
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    try:
        df.to_parquet(OUT / "train.parquet", index=False)
        print(f"\n  Saved: data/processed/train.parquet")
    except ImportError:
        df.to_csv(OUT / "train.csv", index=False)
        print(f"\n  Saved: data/processed/train.csv")

    with open(OUT / "class_map.json", "w", encoding="utf-8") as f:
        json.dump(class_map, f, indent=2)

    # Save metadata about the data source
    data_info = {
        "source": "CIC-IDS2017",
        "total_rows": len(df),
        "n_features": len(UNIFIED_FEATURES),
        "classes": class_names,
        "class_distribution": {cls: int((df["attack_type"] == cls).sum()) for cls in class_names},
        "balanced": True,
        "max_per_class": MAX_PER_CLASS,
        "min_per_class": MIN_PER_CLASS,
    }
    with open(OUT / "data_info.json", "w", encoding="utf-8") as f:
        json.dump(data_info, f, indent=2)

    print(f"  Total: {len(df):,} rows, {len(UNIFIED_FEATURES)} features")
    print(f"  Classes: {class_names}")
    print(f"\n  Final distribution:")
    for cls, count in df["attack_type"].value_counts().sort_index().items():
        pct = count / len(df) * 100
        bar = "#" * int(pct / 2)
        print(f"    {cls:15s} {count:>8,}  ({pct:5.1f}%)  {bar}")

    return True


if __name__ == "__main__":
    success = main()
    if not success:
        print("\n  Falling back to mock data generator...")
        import subprocess, sys
        subprocess.run([sys.executable, str(PROJECT_ROOT / "src" / "data" / "mock_data.py")])
