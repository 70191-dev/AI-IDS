"""
Multi-Class Mock Data Generator
--------------------------------
Generates realistic CIC-IDS2017-style data with multiple attack categories.
Use this if you haven't downloaded the real dataset yet.

Classes: Benign, DoS, DDoS, Port Scan, Brute Force, Web Attack, Bot, Infiltration

Usage:
    python src/data/mock_data.py
"""

import numpy as np
import pandas as pd
import json
from pathlib import Path

# Find project root (works regardless of path nesting or special chars)
_p = Path(__file__).resolve().parent
while _p != _p.parent:
    if (_p / "env" / "requirements.txt").exists():
        break
    _p = _p.parent
else:
    _p = Path.cwd()
PROJECT_ROOT = _p
OUT_DIR = PROJECT_ROOT / "data" / "processed"
OUT_DIR.mkdir(parents=True, exist_ok=True)

np.random.seed(42)

# ── Class definitions with distinct traffic profiles ─────────────

CLASS_PROFILES = {
    "Benign": {
        "count": 5000,
        "flow_duration":            {"dist": "exp",     "params": {"scale": 200000}},
        "total_fwd_packets":        {"dist": "poisson", "params": {"lam": 15}},
        "total_backward_packets":   {"dist": "poisson", "params": {"lam": 12}},
        "total_length_of_fwd_packets":  {"dist": "lognorm", "params": {"mean": 7.5, "sigma": 0.8}},
        "total_length_of_bwd_packets":  {"dist": "lognorm", "params": {"mean": 8.0, "sigma": 0.9}},
        "fwd_packet_length_mean":   {"dist": "normal",  "params": {"loc": 500, "scale": 150}},
        "bwd_packet_length_mean":   {"dist": "normal",  "params": {"loc": 600, "scale": 200}},
        "flow_iat_mean":            {"dist": "exp",     "params": {"scale": 50000}},
        "flow_iat_std":             {"dist": "exp",     "params": {"scale": 30000}},
        "fwd_iat_mean":             {"dist": "exp",     "params": {"scale": 60000}},
        "bwd_iat_mean":             {"dist": "exp",     "params": {"scale": 55000}},
        "syn_flag_count":           {"dist": "choice",  "params": {"a": [0, 1, 1, 0, 0]}},
        "rst_flag_count":           {"dist": "choice",  "params": {"a": [0, 0, 0, 0, 1]}},
        "psh_flag_count":           {"dist": "choice",  "params": {"a": [0, 1, 1, 1, 0]}},
        "ack_flag_count":           {"dist": "choice",  "params": {"a": [1, 1, 1, 1, 0]}},
        "fin_flag_count":           {"dist": "choice",  "params": {"a": [0, 0, 1, 0, 0]}},
        "urg_flag_count":           {"dist": "const",   "params": {"value": 0}},
        "destination_port":         {"dist": "choice",  "params": {"a": [80, 443, 8080, 53, 22, 25, 110, 993, 3306, 5432]}},
        "down_up_ratio":            {"dist": "normal",  "params": {"loc": 1.2, "scale": 0.5}},
        "init_win_bytes_forward":   {"dist": "choice",  "params": {"a": [8192, 16384, 29200, 65535]}},
        "init_win_bytes_backward":  {"dist": "choice",  "params": {"a": [8192, 16384, 29200, 65535]}},
        "active_mean":              {"dist": "exp",     "params": {"scale": 5000}},
        "idle_mean":                {"dist": "exp",     "params": {"scale": 100000}},
    },
    "DoS": {
        "count": 1500,
        "flow_duration":            {"dist": "exp",     "params": {"scale": 5000}},
        "total_fwd_packets":        {"dist": "poisson", "params": {"lam": 150}},
        "total_backward_packets":   {"dist": "poisson", "params": {"lam": 5}},
        "total_length_of_fwd_packets":  {"dist": "lognorm", "params": {"mean": 10.0, "sigma": 1.2}},
        "total_length_of_bwd_packets":  {"dist": "lognorm", "params": {"mean": 4.0, "sigma": 0.8}},
        "fwd_packet_length_mean":   {"dist": "normal",  "params": {"loc": 1300, "scale": 300}},
        "bwd_packet_length_mean":   {"dist": "normal",  "params": {"loc": 50, "scale": 30}},
        "flow_iat_mean":            {"dist": "exp",     "params": {"scale": 500}},
        "flow_iat_std":             {"dist": "exp",     "params": {"scale": 300}},
        "fwd_iat_mean":             {"dist": "exp",     "params": {"scale": 400}},
        "bwd_iat_mean":             {"dist": "exp",     "params": {"scale": 10000}},
        "syn_flag_count":           {"dist": "choice",  "params": {"a": [1, 1, 1, 0]}},
        "rst_flag_count":           {"dist": "choice",  "params": {"a": [0, 0, 1, 0]}},
        "psh_flag_count":           {"dist": "choice",  "params": {"a": [0, 0, 0, 1]}},
        "ack_flag_count":           {"dist": "choice",  "params": {"a": [0, 1, 0, 0]}},
        "fin_flag_count":           {"dist": "const",   "params": {"value": 0}},
        "urg_flag_count":           {"dist": "const",   "params": {"value": 0}},
        "destination_port":         {"dist": "choice",  "params": {"a": [80, 443, 8080]}},
        "down_up_ratio":            {"dist": "normal",  "params": {"loc": 0.1, "scale": 0.05}},
        "init_win_bytes_forward":   {"dist": "choice",  "params": {"a": [512, 1024, 2048]}},
        "init_win_bytes_backward":  {"dist": "const",   "params": {"value": 0}},
        "active_mean":              {"dist": "exp",     "params": {"scale": 200}},
        "idle_mean":                {"dist": "exp",     "params": {"scale": 500}},
    },
    "DDoS": {
        "count": 1200,
        "flow_duration":            {"dist": "exp",     "params": {"scale": 2000}},
        "total_fwd_packets":        {"dist": "poisson", "params": {"lam": 300}},
        "total_backward_packets":   {"dist": "poisson", "params": {"lam": 2}},
        "total_length_of_fwd_packets":  {"dist": "lognorm", "params": {"mean": 11.0, "sigma": 1.0}},
        "total_length_of_bwd_packets":  {"dist": "lognorm", "params": {"mean": 3.5, "sigma": 0.5}},
        "fwd_packet_length_mean":   {"dist": "normal",  "params": {"loc": 1450, "scale": 200}},
        "bwd_packet_length_mean":   {"dist": "normal",  "params": {"loc": 30, "scale": 20}},
        "flow_iat_mean":            {"dist": "exp",     "params": {"scale": 100}},
        "flow_iat_std":             {"dist": "exp",     "params": {"scale": 80}},
        "fwd_iat_mean":             {"dist": "exp",     "params": {"scale": 100}},
        "bwd_iat_mean":             {"dist": "exp",     "params": {"scale": 50000}},
        "syn_flag_count":           {"dist": "choice",  "params": {"a": [1, 1, 1, 1]}},
        "rst_flag_count":           {"dist": "choice",  "params": {"a": [0, 0, 0, 1]}},
        "psh_flag_count":           {"dist": "const",   "params": {"value": 0}},
        "ack_flag_count":           {"dist": "choice",  "params": {"a": [0, 0, 1, 0]}},
        "fin_flag_count":           {"dist": "const",   "params": {"value": 0}},
        "urg_flag_count":           {"dist": "const",   "params": {"value": 0}},
        "destination_port":         {"dist": "choice",  "params": {"a": [80, 443]}},
        "down_up_ratio":            {"dist": "normal",  "params": {"loc": 0.02, "scale": 0.01}},
        "init_win_bytes_forward":   {"dist": "choice",  "params": {"a": [256, 512, 1024]}},
        "init_win_bytes_backward":  {"dist": "const",   "params": {"value": 0}},
        "active_mean":              {"dist": "exp",     "params": {"scale": 50}},
        "idle_mean":                {"dist": "exp",     "params": {"scale": 100}},
    },
    "Port Scan": {
        "count": 1000,
        "flow_duration":            {"dist": "exp",     "params": {"scale": 1000}},
        "total_fwd_packets":        {"dist": "poisson", "params": {"lam": 3}},
        "total_backward_packets":   {"dist": "poisson", "params": {"lam": 2}},
        "total_length_of_fwd_packets":  {"dist": "lognorm", "params": {"mean": 4.0, "sigma": 0.5}},
        "total_length_of_bwd_packets":  {"dist": "lognorm", "params": {"mean": 3.5, "sigma": 0.5}},
        "fwd_packet_length_mean":   {"dist": "normal",  "params": {"loc": 50, "scale": 20}},
        "bwd_packet_length_mean":   {"dist": "normal",  "params": {"loc": 40, "scale": 15}},
        "flow_iat_mean":            {"dist": "exp",     "params": {"scale": 2000}},
        "flow_iat_std":             {"dist": "exp",     "params": {"scale": 1000}},
        "fwd_iat_mean":             {"dist": "exp",     "params": {"scale": 1500}},
        "bwd_iat_mean":             {"dist": "exp",     "params": {"scale": 3000}},
        "syn_flag_count":           {"dist": "choice",  "params": {"a": [1, 1, 1, 1]}},
        "rst_flag_count":           {"dist": "choice",  "params": {"a": [1, 1, 0, 0]}},
        "psh_flag_count":           {"dist": "const",   "params": {"value": 0}},
        "ack_flag_count":           {"dist": "const",   "params": {"value": 0}},
        "fin_flag_count":           {"dist": "const",   "params": {"value": 0}},
        "urg_flag_count":           {"dist": "const",   "params": {"value": 0}},
        "destination_port":         {"dist": "randint",  "params": {"low": 1, "high": 1024}},
        "down_up_ratio":            {"dist": "normal",  "params": {"loc": 0.8, "scale": 0.3}},
        "init_win_bytes_forward":   {"dist": "choice",  "params": {"a": [1024, 2048]}},
        "init_win_bytes_backward":  {"dist": "choice",  "params": {"a": [0, 0, 512]}},
        "active_mean":              {"dist": "exp",     "params": {"scale": 100}},
        "idle_mean":                {"dist": "exp",     "params": {"scale": 300}},
    },
    "Brute Force": {
        "count": 800,
        "flow_duration":            {"dist": "exp",     "params": {"scale": 30000}},
        "total_fwd_packets":        {"dist": "poisson", "params": {"lam": 20}},
        "total_backward_packets":   {"dist": "poisson", "params": {"lam": 18}},
        "total_length_of_fwd_packets":  {"dist": "lognorm", "params": {"mean": 7.0, "sigma": 0.6}},
        "total_length_of_bwd_packets":  {"dist": "lognorm", "params": {"mean": 6.5, "sigma": 0.6}},
        "fwd_packet_length_mean":   {"dist": "normal",  "params": {"loc": 400, "scale": 100}},
        "bwd_packet_length_mean":   {"dist": "normal",  "params": {"loc": 350, "scale": 100}},
        "flow_iat_mean":            {"dist": "exp",     "params": {"scale": 8000}},
        "flow_iat_std":             {"dist": "exp",     "params": {"scale": 5000}},
        "fwd_iat_mean":             {"dist": "exp",     "params": {"scale": 7000}},
        "bwd_iat_mean":             {"dist": "exp",     "params": {"scale": 9000}},
        "syn_flag_count":           {"dist": "choice",  "params": {"a": [1, 1, 0]}},
        "rst_flag_count":           {"dist": "choice",  "params": {"a": [0, 1, 0]}},
        "psh_flag_count":           {"dist": "choice",  "params": {"a": [1, 1, 0]}},
        "ack_flag_count":           {"dist": "choice",  "params": {"a": [1, 1, 1]}},
        "fin_flag_count":           {"dist": "choice",  "params": {"a": [0, 0, 1]}},
        "urg_flag_count":           {"dist": "const",   "params": {"value": 0}},
        "destination_port":         {"dist": "choice",  "params": {"a": [22, 22, 22, 3389, 21, 23]}},
        "down_up_ratio":            {"dist": "normal",  "params": {"loc": 0.9, "scale": 0.2}},
        "init_win_bytes_forward":   {"dist": "choice",  "params": {"a": [8192, 16384, 29200]}},
        "init_win_bytes_backward":  {"dist": "choice",  "params": {"a": [8192, 16384, 29200]}},
        "active_mean":              {"dist": "exp",     "params": {"scale": 3000}},
        "idle_mean":                {"dist": "exp",     "params": {"scale": 20000}},
    },
    "Web Attack": {
        "count": 600,
        "flow_duration":            {"dist": "exp",     "params": {"scale": 50000}},
        "total_fwd_packets":        {"dist": "poisson", "params": {"lam": 30}},
        "total_backward_packets":   {"dist": "poisson", "params": {"lam": 25}},
        "total_length_of_fwd_packets":  {"dist": "lognorm", "params": {"mean": 8.5, "sigma": 1.0}},
        "total_length_of_bwd_packets":  {"dist": "lognorm", "params": {"mean": 9.0, "sigma": 1.0}},
        "fwd_packet_length_mean":   {"dist": "normal",  "params": {"loc": 800, "scale": 300}},
        "bwd_packet_length_mean":   {"dist": "normal",  "params": {"loc": 1200, "scale": 400}},
        "flow_iat_mean":            {"dist": "exp",     "params": {"scale": 15000}},
        "flow_iat_std":             {"dist": "exp",     "params": {"scale": 10000}},
        "fwd_iat_mean":             {"dist": "exp",     "params": {"scale": 12000}},
        "bwd_iat_mean":             {"dist": "exp",     "params": {"scale": 8000}},
        "syn_flag_count":           {"dist": "choice",  "params": {"a": [1, 0]}},
        "rst_flag_count":           {"dist": "const",   "params": {"value": 0}},
        "psh_flag_count":           {"dist": "choice",  "params": {"a": [1, 1, 1]}},
        "ack_flag_count":           {"dist": "choice",  "params": {"a": [1, 1, 1]}},
        "fin_flag_count":           {"dist": "choice",  "params": {"a": [0, 1]}},
        "urg_flag_count":           {"dist": "const",   "params": {"value": 0}},
        "destination_port":         {"dist": "choice",  "params": {"a": [80, 443, 8080, 8443]}},
        "down_up_ratio":            {"dist": "normal",  "params": {"loc": 2.5, "scale": 1.0}},
        "init_win_bytes_forward":   {"dist": "choice",  "params": {"a": [8192, 16384, 29200, 65535]}},
        "init_win_bytes_backward":  {"dist": "choice",  "params": {"a": [8192, 16384, 29200]}},
        "active_mean":              {"dist": "exp",     "params": {"scale": 8000}},
        "idle_mean":                {"dist": "exp",     "params": {"scale": 30000}},
    },
    "Bot": {
        "count": 500,
        "flow_duration":            {"dist": "exp",     "params": {"scale": 100000}},
        "total_fwd_packets":        {"dist": "poisson", "params": {"lam": 40}},
        "total_backward_packets":   {"dist": "poisson", "params": {"lam": 35}},
        "total_length_of_fwd_packets":  {"dist": "lognorm", "params": {"mean": 7.0, "sigma": 0.5}},
        "total_length_of_bwd_packets":  {"dist": "lognorm", "params": {"mean": 8.5, "sigma": 0.7}},
        "fwd_packet_length_mean":   {"dist": "normal",  "params": {"loc": 300, "scale": 100}},
        "bwd_packet_length_mean":   {"dist": "normal",  "params": {"loc": 500, "scale": 150}},
        "flow_iat_mean":            {"dist": "exp",     "params": {"scale": 25000}},
        "flow_iat_std":             {"dist": "exp",     "params": {"scale": 20000}},
        "fwd_iat_mean":             {"dist": "exp",     "params": {"scale": 30000}},
        "bwd_iat_mean":             {"dist": "exp",     "params": {"scale": 20000}},
        "syn_flag_count":           {"dist": "choice",  "params": {"a": [0, 1]}},
        "rst_flag_count":           {"dist": "const",   "params": {"value": 0}},
        "psh_flag_count":           {"dist": "choice",  "params": {"a": [1, 0]}},
        "ack_flag_count":           {"dist": "choice",  "params": {"a": [1, 1]}},
        "fin_flag_count":           {"dist": "choice",  "params": {"a": [0, 1]}},
        "urg_flag_count":           {"dist": "const",   "params": {"value": 0}},
        "destination_port":         {"dist": "choice",  "params": {"a": [80, 443, 6667, 6697, 8080]}},
        "down_up_ratio":            {"dist": "normal",  "params": {"loc": 1.8, "scale": 0.6}},
        "init_win_bytes_forward":   {"dist": "choice",  "params": {"a": [8192, 29200, 65535]}},
        "init_win_bytes_backward":  {"dist": "choice",  "params": {"a": [8192, 29200, 65535]}},
        "active_mean":              {"dist": "exp",     "params": {"scale": 10000}},
        "idle_mean":                {"dist": "exp",     "params": {"scale": 200000}},
    },
    "Infiltration": {
        "count": 400,
        "flow_duration":            {"dist": "exp",     "params": {"scale": 150000}},
        "total_fwd_packets":        {"dist": "poisson", "params": {"lam": 25}},
        "total_backward_packets":   {"dist": "poisson", "params": {"lam": 20}},
        "total_length_of_fwd_packets":  {"dist": "lognorm", "params": {"mean": 7.8, "sigma": 0.9}},
        "total_length_of_bwd_packets":  {"dist": "lognorm", "params": {"mean": 7.5, "sigma": 0.8}},
        "fwd_packet_length_mean":   {"dist": "normal",  "params": {"loc": 550, "scale": 200}},
        "bwd_packet_length_mean":   {"dist": "normal",  "params": {"loc": 450, "scale": 150}},
        "flow_iat_mean":            {"dist": "exp",     "params": {"scale": 40000}},
        "flow_iat_std":             {"dist": "exp",     "params": {"scale": 35000}},
        "fwd_iat_mean":             {"dist": "exp",     "params": {"scale": 50000}},
        "bwd_iat_mean":             {"dist": "exp",     "params": {"scale": 45000}},
        "syn_flag_count":           {"dist": "choice",  "params": {"a": [0, 1]}},
        "rst_flag_count":           {"dist": "const",   "params": {"value": 0}},
        "psh_flag_count":           {"dist": "choice",  "params": {"a": [1, 0, 1]}},
        "ack_flag_count":           {"dist": "choice",  "params": {"a": [1, 1, 0]}},
        "fin_flag_count":           {"dist": "choice",  "params": {"a": [0, 0, 1]}},
        "urg_flag_count":           {"dist": "const",   "params": {"value": 0}},
        "destination_port":         {"dist": "choice",  "params": {"a": [80, 443, 4444, 5555, 8080]}},
        "down_up_ratio":            {"dist": "normal",  "params": {"loc": 1.0, "scale": 0.3}},
        "init_win_bytes_forward":   {"dist": "choice",  "params": {"a": [8192, 16384, 29200, 65535]}},
        "init_win_bytes_backward":  {"dist": "choice",  "params": {"a": [8192, 16384, 29200, 65535]}},
        "active_mean":              {"dist": "exp",     "params": {"scale": 15000}},
        "idle_mean":                {"dist": "exp",     "params": {"scale": 120000}},
    },
}


def sample_feature(spec, n):
    """Sample n values from a feature distribution specification."""
    dist = spec["dist"]
    p = spec["params"]
    if dist == "exp":
        return np.random.exponential(scale=p["scale"], size=n)
    elif dist == "poisson":
        return np.random.poisson(lam=p["lam"], size=n) + 1
    elif dist == "lognorm":
        return np.random.lognormal(mean=p["mean"], sigma=p["sigma"], size=n)
    elif dist == "normal":
        return np.random.normal(loc=p["loc"], scale=p["scale"], size=n).clip(0)
    elif dist == "choice":
        return np.random.choice(p["a"], size=n)
    elif dist == "randint":
        return np.random.randint(p["low"], p["high"], size=n)
    elif dist == "const":
        return np.full(n, p["value"])
    else:
        return np.zeros(n)


def generate_class(class_name, profile):
    """Generate a DataFrame for one attack class."""
    n = profile["count"]
    data = {}
    for feat, spec in profile.items():
        if feat == "count":
            continue
        data[feat] = sample_feature(spec, n)

    df = pd.DataFrame(data)
    df["attack_type"] = class_name
    return df


def main():
    print("=" * 60)
    print("Multi-Class Mock Data Generator")
    print("=" * 60)

    frames = []
    for cls_name, profile in CLASS_PROFILES.items():
        df = generate_class(cls_name, profile)
        frames.append(df)
        print(f"  {cls_name:20s} -> {len(df):>5} samples")

    df = pd.concat(frames, ignore_index=True)

    # ── Derived features ──
    df["flow_bytes_per_s"] = (df["total_length_of_fwd_packets"] + df["total_length_of_bwd_packets"]) / (df["flow_duration"] / 1e6 + 0.001)
    df["flow_packets_per_s"] = (df["total_fwd_packets"] + df["total_backward_packets"]) / (df["flow_duration"] / 1e6 + 0.001)
    df["packet_length_mean"] = (df["fwd_packet_length_mean"] + df["bwd_packet_length_mean"]) / 2
    df["packet_length_std"] = np.abs(df["fwd_packet_length_mean"] - df["bwd_packet_length_mean"])
    df["min_packet_length"] = np.minimum(df["fwd_packet_length_mean"], df["bwd_packet_length_mean"]) * 0.3
    df["max_packet_length"] = np.maximum(df["fwd_packet_length_mean"], df["bwd_packet_length_mean"]) * 1.5
    df["average_packet_size"] = df["packet_length_mean"]
    df["avg_fwd_segment_size"] = df["fwd_packet_length_mean"]
    df["avg_bwd_segment_size"] = df["bwd_packet_length_mean"]
    df["fwd_packets_per_s"] = df["total_fwd_packets"] / (df["flow_duration"] / 1e6 + 0.001)
    df["bwd_packets_per_s"] = df["total_backward_packets"] / (df["flow_duration"] / 1e6 + 0.001)
    df["fwd_psh_flags"] = df["psh_flag_count"]
    df["fwd_urg_flags"] = df["urg_flag_count"]
    df["fwd_header_length"] = df["total_fwd_packets"] * 20
    df["bwd_header_length"] = df["total_backward_packets"] * 20

    # ── CIC-IDS2017 compatible features (so mock-trained models work with CIC data too) ──
    df["fwd_packet_length_max"] = df["fwd_packet_length_mean"] * np.random.uniform(1.5, 3.0, size=len(df))
    df["fwd_packet_length_std"] = df["fwd_packet_length_mean"] * np.random.uniform(0.3, 0.8, size=len(df))
    df["bwd_packet_length_max"] = df["bwd_packet_length_mean"] * np.random.uniform(1.5, 3.0, size=len(df))
    df["bwd_packet_length_std"] = df["bwd_packet_length_mean"] * np.random.uniform(0.3, 0.8, size=len(df))
    df["fwd_iat_std"] = df["fwd_iat_mean"] * np.random.uniform(0.5, 1.5, size=len(df))
    df["bwd_iat_std"] = df["bwd_iat_mean"] * np.random.uniform(0.5, 1.5, size=len(df))
    df["subflow_fwd_packets"] = df["total_fwd_packets"]
    df["subflow_fwd_bytes"] = df["total_length_of_fwd_packets"]
    df["subflow_bwd_packets"] = df["total_backward_packets"]
    df["subflow_bwd_bytes"] = df["total_length_of_bwd_packets"]
    df["active_std"] = df["active_mean"] * np.random.uniform(0.3, 1.0, size=len(df))
    df["idle_std"] = df["idle_mean"] * np.random.uniform(0.3, 1.0, size=len(df))

    # ── Labels ──
    df["label"] = (df["attack_type"] != "Benign").astype(int)
    classes = sorted(df["attack_type"].unique())
    class_map = {c: i for i, c in enumerate(classes)}
    df["label_multi"] = df["attack_type"].map(class_map)

    # Add 3% label noise for realism
    N = len(df)
    noise_idx = np.random.choice(N, size=int(N * 0.03), replace=False)
    for idx in noise_idx:
        df.loc[idx, "attack_type"] = np.random.choice(classes)
        df.loc[idx, "label_multi"] = class_map[df.loc[idx, "attack_type"]]
        df.loc[idx, "label"] = 0 if df.loc[idx, "attack_type"] == "Benign" else 1

    # Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    # ── Save ──
    feature_cols = [c for c in df.columns if c not in ["label", "label_multi", "attack_type"]]

    try:
        df.to_parquet(OUT_DIR / "train.parquet", index=False)
        print(f"\n[OK] Saved data/processed/train.parquet")
    except ImportError:
        df.to_csv(OUT_DIR / "train.csv", index=False)
        print(f"\n[OK] Saved data/processed/train.csv")

    # Save class mapping
    with open(OUT_DIR / "class_map.json", "w", encoding="utf-8") as f:
        json.dump(class_map, f, indent=2)

    print(f"  Total: {len(df)} rows, {len(feature_cols)} features")
    print(f"  Classes: {classes}")
    print(f"\nClass distribution:")
    for cls, count in df["attack_type"].value_counts().sort_index().items():
        pct = count / len(df) * 100
        print(f"  {cls:20s} -> {count:>5} ({pct:.1f}%)")


if __name__ == "__main__":
    main()
