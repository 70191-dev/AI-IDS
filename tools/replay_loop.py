"""
Mixed Traffic Replay -- Multi-Class (CIC-Profile-Driven)
---------------------------------------------------------
Sends a realistic mix of benign and multiple attack type flows,
using real CIC-IDS2017 feature distributions extracted by
tools/extract_cic_profiles.py.

Usage:
    python tools/replay_loop.py [--rate 5] [--attack-ratio 0.45]
"""

import requests
import numpy as np
import time
import sys
import argparse
import uuid
import json
from pathlib import Path

API_URL = "http://127.0.0.1:8000"
np.random.seed(None)

ROOT = Path(__file__).resolve().parent.parent
META_PATH = ROOT / "models" / "model_meta.json"
PROFILES_PATH = ROOT / "data" / "cic_profiles.json"

# Integer features that should be rounded (no fractional values)
INTEGER_FEATURES = {
    "total_fwd_packets", "total_backward_packets",
    "syn_flag_count", "rst_flag_count", "psh_flag_count",
    "ack_flag_count", "fin_flag_count", "urg_flag_count",
    "destination_port", "init_win_bytes_forward", "init_win_bytes_backward",
    "fwd_header_length", "bwd_header_length",
    "subflow_fwd_packets", "subflow_bwd_packets",
    "fwd_psh_flags", "fwd_urg_flags",
}

# Binary flag features (0 or 1)
FLAG_FEATURES = {
    "syn_flag_count", "rst_flag_count", "psh_flag_count",
    "ack_flag_count", "fin_flag_count", "urg_flag_count",
    "fwd_psh_flags", "fwd_urg_flags",
}

# Non-negative features (most network features can't be negative)
NON_NEGATIVE = True  # Applied to all features by default


def load_feature_names():
    try:
        with open(META_PATH) as f:
            return json.load(f).get("feature_names", [])
    except FileNotFoundError:
        return []


def load_profiles():
    """Load CIC feature profiles. Returns dict or None."""
    try:
        with open(PROFILES_PATH) as f:
            return json.load(f)
    except FileNotFoundError:
        return None


# Populated by main() — module-level imports must not trigger model dependency.
CIC_PROFILES = None
FEATURE_NAMES = []


def sample_from_profile(profile, feature_names, aggressive=False):
    """
    Generate a feature dict by sampling around real CIC distributions.

    aggressive=False: median +/- uniform within IQR (normal attack)
    aggressive=True:  push values toward Q95 extremes (high-confidence attack)
    """
    features = {}
    for feat in feature_names:
        if feat not in profile:
            features[feat] = 0.0
            continue

        p = profile[feat]
        median = p["median"]
        q25 = p["q25"]
        q75 = p["q75"]
        iqr = q75 - q25

        if aggressive:
            # Push toward extremes -- sample between Q75 and Q95
            q95 = p["q95"]
            base = q75 + np.random.uniform(0, q95 - q75) if q95 > q75 else q75
            # Add small jitter
            jitter = np.random.uniform(-0.1 * max(iqr, 1e-6), 0.1 * max(iqr, 1e-6))
            value = base + jitter
        else:
            # Normal mode: median +/- within IQR
            if iqr > 0:
                jitter = np.random.uniform(-0.5 * iqr, 0.5 * iqr)
            else:
                # Zero IQR -- use small std-based jitter
                std = p.get("std", 0)
                jitter = np.random.uniform(-0.2 * max(std, 1e-6), 0.2 * max(std, 1e-6))
            value = median + jitter

        # Clamp non-negative
        if NON_NEGATIVE:
            value = max(value, 0.0)

        # Round flags to 0 or 1
        if feat in FLAG_FEATURES:
            value = 1 if value >= 0.5 else 0
        elif feat in INTEGER_FEATURES:
            value = int(round(value))
        else:
            value = round(value, 2)

        features[feat] = value

    return features


# ---- CIC-Profile-Based Generators ------------------------------------------

def gen_from_cic(class_name, aggressive=False):
    """Generate flow features from CIC profile for given class."""
    if CIC_PROFILES is None or class_name not in CIC_PROFILES:
        return None
    return sample_from_profile(CIC_PROFILES[class_name], FEATURE_NAMES, aggressive)


# ---- Fallback Hardcoded Generators (used when no profiles exist) -----------

def _gen_benign_fallback():
    return {
        "flow_duration":            round(np.random.exponential(200000), 2),
        "total_fwd_packets":        int(np.random.poisson(15) + 1),
        "total_backward_packets":   int(np.random.poisson(12) + 1),
        "total_length_of_fwd_packets": round(np.random.lognormal(7.5, 0.8), 2),
        "total_length_of_bwd_packets": round(np.random.lognormal(8.0, 0.9), 2),
        "fwd_packet_length_mean":   round(np.random.normal(500, 150), 2),
        "bwd_packet_length_mean":   round(np.random.normal(600, 200), 2),
        "flow_iat_mean":            round(np.random.exponential(50000), 2),
        "flow_iat_std":             round(np.random.exponential(30000), 2),
        "fwd_iat_mean":             round(np.random.exponential(60000), 2),
        "bwd_iat_mean":             round(np.random.exponential(55000), 2),
        "syn_flag_count":           int(np.random.choice([0, 1, 1, 0, 0])),
        "rst_flag_count":           int(np.random.choice([0, 0, 0, 0, 1])),
        "psh_flag_count":           int(np.random.choice([0, 1, 1, 1, 0])),
        "ack_flag_count":           int(np.random.choice([1, 1, 1, 1, 0])),
        "fin_flag_count":           int(np.random.choice([0, 0, 1, 0, 0])),
        "urg_flag_count":           0,
        "destination_port":         int(np.random.choice([80, 443, 8080, 53, 22])),
        "down_up_ratio":            round(np.random.normal(1.2, 0.5), 2),
        "init_win_bytes_forward":   int(np.random.choice([8192, 16384, 29200, 65535])),
        "init_win_bytes_backward":  int(np.random.choice([8192, 16384, 29200, 65535])),
        "active_mean":              round(np.random.exponential(5000), 2),
        "idle_mean":                round(np.random.exponential(100000), 2),
    }


def _gen_attack_fallback():
    """Generic attack fallback -- biased toward brute force patterns."""
    return {
        "flow_duration":            round(np.random.exponential(30000), 2),
        "total_fwd_packets":        int(np.random.poisson(50) + 3),
        "total_backward_packets":   int(np.random.poisson(5) + 1),
        "total_length_of_fwd_packets": round(np.random.lognormal(9.0, 1.0), 2),
        "total_length_of_bwd_packets": round(np.random.lognormal(5.0, 0.8), 2),
        "fwd_packet_length_mean":   round(np.random.normal(800, 300), 2),
        "bwd_packet_length_mean":   round(max(np.random.normal(100, 50), 0), 2),
        "flow_iat_mean":            round(np.random.exponential(2000), 2),
        "flow_iat_std":             round(np.random.exponential(1500), 2),
        "fwd_iat_mean":             round(np.random.exponential(1500), 2),
        "bwd_iat_mean":             round(np.random.exponential(10000), 2),
        "syn_flag_count":           int(np.random.choice([1, 1, 0])),
        "rst_flag_count":           int(np.random.choice([0, 1, 0])),
        "psh_flag_count":           int(np.random.choice([0, 1])),
        "ack_flag_count":           int(np.random.choice([0, 1])),
        "fin_flag_count":           0,
        "urg_flag_count":           0,
        "destination_port":         int(np.random.choice([80, 443, 22, 8080])),
        "down_up_ratio":            round(max(np.random.normal(0.3, 0.2), 0), 2),
        "init_win_bytes_forward":   int(np.random.choice([1024, 2048, 8192])),
        "init_win_bytes_backward":  int(np.random.choice([0, 512, 1024])),
        "active_mean":              round(np.random.exponential(500), 2),
        "idle_mean":                round(np.random.exponential(1000), 2),
    }


FALLBACK_GENERATORS = {
    "DoS":          _gen_attack_fallback,
    "DDoS":         _gen_attack_fallback,
    "Port Scan":    _gen_attack_fallback,
    "Brute Force":  _gen_attack_fallback,
    "Web Attack":   _gen_attack_fallback,
    "Bot":          _gen_attack_fallback,
    "Infiltration": _gen_attack_fallback,
}


# ---- Unified generator interface -------------------------------------------

def gen_benign():
    """Generate a benign flow from CIC profile or fallback."""
    result = gen_from_cic("Benign")
    if result is not None:
        return result
    return _gen_benign_fallback()


def gen_attack(attack_type):
    """Generate an attack flow with 20% chance of aggressive mode."""
    aggressive = np.random.random() < 0.20
    result = gen_from_cic(attack_type, aggressive=aggressive)
    if result is not None:
        return result
    # Fallback
    fb = FALLBACK_GENERATORS.get(attack_type, _gen_attack_fallback)
    return fb()


ATTACK_TYPES = ["DoS", "DDoS", "Port Scan", "Brute Force", "Web Attack", "Bot", "Infiltration"]

# ---- Simulated source IP pools (for realistic flow IDs) ----------------------
# Internal/benign hosts — a small corporate network
BENIGN_IPS = [
    "192.168.1.10", "192.168.1.25", "192.168.1.42", "192.168.1.87",
    "192.168.1.103", "192.168.2.15", "192.168.2.50", "10.0.0.5",
    "10.0.0.22", "10.0.1.10", "10.0.1.55", "172.16.0.8",
]
# External/attacker hosts — varied subnets to show distinct sources
ATTACK_IPS = [
    "45.33.32.156", "185.220.101.34", "91.219.236.80", "23.129.64.210",
    "198.51.100.77", "203.0.113.42", "103.25.17.9", "77.247.181.163",
    "62.210.105.116", "185.56.83.200", "104.248.30.5", "138.68.11.92",
    "46.166.139.111", "212.71.253.80", "89.248.174.22",
]


def add_derived(f):
    """Add derived features -- only fills in missing ones from the profile."""
    # If using CIC profiles, most derived features are already set.
    # Only compute if missing.
    dur_s = f.get("flow_duration", 1) / 1e6 + 0.001
    total_pkts = f.get("total_fwd_packets", 1) + f.get("total_backward_packets", 1)
    fwd_len = f.get("total_length_of_fwd_packets", 0)
    bwd_len = f.get("total_length_of_bwd_packets", 0)
    fm = f.get("fwd_packet_length_mean", 0)
    bm = f.get("bwd_packet_length_mean", 0)

    defaults = {
        "flow_bytes_per_s":     round((fwd_len + bwd_len) / dur_s, 2),
        "flow_packets_per_s":   round(total_pkts / dur_s, 2),
        "packet_length_mean":   round((fm + bm) / 2, 2),
        "packet_length_std":    round(abs(fm - bm), 2),
        "min_packet_length":    round(min(fm, bm) * 0.3, 2),
        "max_packet_length":    round(max(fm, bm) * 1.5, 2),
        "average_packet_size":  round((fm + bm) / 2, 2),
        "avg_fwd_segment_size": fm,
        "avg_bwd_segment_size": bm,
        "fwd_packets_per_s":    round(f.get("total_fwd_packets", 1) / dur_s, 2),
        "bwd_packets_per_s":    round(f.get("total_backward_packets", 1) / dur_s, 2),
        "fwd_psh_flags":        f.get("psh_flag_count", 0),
        "fwd_urg_flags":        f.get("urg_flag_count", 0),
        "fwd_header_length":    f.get("total_fwd_packets", 1) * 20,
        "bwd_header_length":    f.get("total_backward_packets", 1) * 20,
        "fwd_packet_length_max":  round(fm * np.random.uniform(1.5, 3.0), 2),
        "fwd_packet_length_std":  round(fm * np.random.uniform(0.3, 0.8), 2),
        "bwd_packet_length_max":  round(bm * np.random.uniform(1.5, 3.0), 2),
        "bwd_packet_length_std":  round(bm * np.random.uniform(0.3, 0.8), 2),
        "fwd_iat_std":            round(f.get("fwd_iat_mean", 0) * np.random.uniform(0.5, 1.5), 2),
        "bwd_iat_std":            round(f.get("bwd_iat_mean", 0) * np.random.uniform(0.5, 1.5), 2),
        "subflow_fwd_packets":    f.get("total_fwd_packets", 1),
        "subflow_fwd_bytes":      fwd_len,
        "subflow_bwd_packets":    f.get("total_backward_packets", 1),
        "subflow_bwd_bytes":      bwd_len,
        "active_std":             round(f.get("active_mean", 0) * np.random.uniform(0.3, 1.0), 2),
        "idle_std":               round(f.get("idle_mean", 0) * np.random.uniform(0.3, 1.0), 2),
    }

    # Only fill missing features (CIC profile already provides most)
    for k, v in defaults.items():
        if k not in f:
            f[k] = v

    return f


def send(api, flow_id, features):
    try:
        r = requests.post(f"{api}/predict", json={"flow_id": flow_id, "features": features}, timeout=5)
        return r.json()
    except requests.ConnectionError:
        return None
    except Exception as e:
        return {"error": str(e)}


def main():
    parser = argparse.ArgumentParser(description="AI-IDS Mixed Traffic Replay")
    parser.add_argument("--rate", type=float, default=5.0, help="Flows per second")
    parser.add_argument("--api", type=str, default=API_URL)
    parser.add_argument("--attack-ratio", type=float, default=0.45, help="Fraction of attack traffic")
    args = parser.parse_args()

    delay = 1.0 / args.rate

    # Lazy-load at runtime so importing this module never depends on training output.
    global CIC_PROFILES, FEATURE_NAMES
    CIC_PROFILES = load_profiles()
    FEATURE_NAMES = load_feature_names()

    if not FEATURE_NAMES:
        print("ERROR: models/model_meta.json not found (or empty feature_names).")
        print("  Run training first: python src/models/train.py")
        sys.exit(1)

    using_profiles = CIC_PROFILES is not None
    mode_str = "CIC-profile" if using_profiles else "fallback (no profiles)"

    print("=" * 55)
    print(f"  AI-IDS Mixed Traffic Replay")
    print(f"  Mode: {mode_str}")
    print(f"  Rate: {args.rate} flows/sec")
    print(f"  Attack ratio: {args.attack_ratio*100:.0f}%")
    print(f"  Attack types: {', '.join(ATTACK_TYPES)}")
    if using_profiles:
        print(f"  Profiles loaded: {list(CIC_PROFILES.keys())}")
        print(f"  Aggressive mode: 20% of attacks")
    print("=" * 55)
    print("Press Ctrl+C to stop.\n")

    count = attacks = benign_ct = 0

    try:
        while True:
            is_attack = np.random.random() < args.attack_ratio
            if is_attack:
                atype = np.random.choice(ATTACK_TYPES)
                features = gen_attack(atype)
                src_ip = np.random.choice(ATTACK_IPS)
            else:
                features = gen_benign()
                src_ip = np.random.choice(BENIGN_IPS)

            # Fill in any missing derived features
            features = add_derived(features)

            flow_id = f"{src_ip}-{uuid.uuid4().hex[:8]}"
            result = send(args.api, flow_id, features)
            count += 1

            if result is None:
                print(f"  [!] API unavailable - retrying in 3s...")
                time.sleep(3)
                continue

            label = result.get("label_text", "?")
            score = result.get("score", 0)
            attack_type = result.get("attack_type", "")
            severity = result.get("severity", "")

            if label == "Attack":
                attacks += 1
                icon = "[ATK]"
                detail = f" [{attack_type}]" if attack_type else ""
                detail += f" [{severity}]" if severity and severity != "None" else ""
            else:
                benign_ct += 1
                icon = "[ OK]"
                detail = ""

            print(f"  {icon} {flow_id} -> {label} (score={score:.3f}){detail}  "
                  f"[{count} total | {attacks} atk | {benign_ct} ben]")

            time.sleep(delay)

    except KeyboardInterrupt:
        print(f"\n{'='*55}")
        print(f"  Stopped. Total: {count} | Attacks: {attacks} | Benign: {benign_ct}")
        print(f"{'='*55}")


if __name__ == "__main__":
    main()
