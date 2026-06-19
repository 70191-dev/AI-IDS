"""
DoS Flood Simulator — High-frequency stress test.

Usage:
    python tools/replay_dos.py --rate 15 --duration 30
"""

import requests
import numpy as np
import time
import argparse
import uuid
import sys

sys.path.insert(0, ".")
from tools.replay_loop import gen_attack, add_derived, ATTACK_IPS

API_URL = "http://127.0.0.1:8000"
np.random.seed(None)


def gen_ddos():
    """Generate DDoS-style flow (even more aggressive than DoS)."""
    return {
        "flow_duration":            round(np.random.exponential(2000), 2),
        "total_fwd_packets":        int(np.random.poisson(300) + 50),
        "total_backward_packets":   int(np.random.poisson(2) + 1),
        "total_length_of_fwd_packets": round(np.random.lognormal(11.0, 1.0), 2),
        "total_length_of_bwd_packets": round(np.random.lognormal(3.5, 0.5), 2),
        "fwd_packet_length_mean":   round(np.random.normal(1450, 200), 2),
        "bwd_packet_length_mean":   round(max(np.random.normal(30, 20), 0), 2),
        "flow_iat_mean":            round(np.random.exponential(100), 2),
        "flow_iat_std":             round(np.random.exponential(80), 2),
        "fwd_iat_mean":             round(np.random.exponential(100), 2),
        "bwd_iat_mean":             round(np.random.exponential(50000), 2),
        "syn_flag_count":           1,
        "rst_flag_count":           int(np.random.choice([0, 0, 0, 1])),
        "psh_flag_count":           0,
        "ack_flag_count":           int(np.random.choice([0, 0, 1, 0])),
        "fin_flag_count":           0,
        "urg_flag_count":           0,
        "destination_port":         int(np.random.choice([80, 443])),
        "down_up_ratio":            round(max(np.random.normal(0.02, 0.01), 0), 4),
        "init_win_bytes_forward":   int(np.random.choice([256, 512, 1024])),
        "init_win_bytes_backward":  0,
        "active_mean":              round(np.random.exponential(50), 2),
        "idle_mean":                round(np.random.exponential(100), 2),
    }


def main():
    parser = argparse.ArgumentParser(description="AI-IDS DoS Flood Simulation")
    parser.add_argument("--rate", type=float, default=10.0, help="Flows/sec")
    parser.add_argument("--duration", type=int, default=30, help="Seconds")
    parser.add_argument("--api", type=str, default=API_URL)
    parser.add_argument("--ddos", action="store_true", help="Use DDoS profile")
    args = parser.parse_args()

    delay = 1.0 / args.rate
    end_time = time.time() + args.duration
    gen_fn = (lambda: gen_attack("DDoS")) if args.ddos else (lambda: gen_attack("DoS"))
    label = "DDoS" if args.ddos else "DoS"

    print("=" * 50)
    print(f"  {label} FLOOD SIMULATION")
    print(f"  Rate: {args.rate} flows/sec")
    print(f"  Duration: {args.duration}s")
    print("=" * 50 + "\n")

    sent = detected = 0

    try:
        while time.time() < end_time:
            features = add_derived(gen_fn())
            src_ip = np.random.choice(ATTACK_IPS)
            flow_id = f"{src_ip}-{uuid.uuid4().hex[:6]}"

            try:
                r = requests.post(f"{args.api}/predict",
                                  json={"flow_id": flow_id, "features": features}, timeout=5)
                result = r.json()
                sent += 1
                if result.get("label_text") == "Attack":
                    detected += 1

                if sent % 10 == 0:
                    elapsed = args.duration - (end_time - time.time())
                    rate = detected / sent * 100 if sent > 0 else 0
                    print(f"  [{sent}] sent | {detected} detected ({rate:.0f}%) | {elapsed:.0f}s")

            except requests.ConnectionError:
                print("  [!] API down - retrying...")
                time.sleep(2)

            time.sleep(delay)

    except KeyboardInterrupt:
        pass

    rate = detected / sent * 100 if sent > 0 else 0
    print(f"\n{'='*55}")
    print(f"  {label} Flood Complete: {sent} sent | {detected} detected | {rate:.1f}%")
    print(f"{'='*55}")


if __name__ == "__main__":
    main()
