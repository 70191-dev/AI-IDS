"""
Attack-Only Replay — Tests detection accuracy per attack type.

Usage:
    python tools/replay_attack.py --type dos --rate 2
    python tools/replay_attack.py --type portscan --count 50
    python tools/replay_attack.py   (random mix of all types)
"""

import requests
import numpy as np
import time
import argparse
import uuid

API_URL = "http://127.0.0.1:8000"
np.random.seed(None)

# Import generators from replay_loop
import sys
sys.path.insert(0, ".")
from tools.replay_loop import gen_attack, add_derived, ATTACK_IPS

GENERATORS = {
    "dos":        "DoS",
    "ddos":       "DDoS",
    "portscan":   "Port Scan",
    "bruteforce": "Brute Force",
    "webattack":  "Web Attack",
    "bot":        "Bot",
    "infiltration": "Infiltration",
}


def main():
    parser = argparse.ArgumentParser(description="AI-IDS Attack-Only Replay")
    parser.add_argument("--rate", type=float, default=2.0, help="Flows per second")
    parser.add_argument("--count", type=int, default=0, help="Total flows (0 = infinite)")
    parser.add_argument("--api", type=str, default=API_URL)
    parser.add_argument("--type", type=str, default=None,
                        choices=list(GENERATORS.keys()),
                        help="Specific attack type")
    args = parser.parse_args()

    delay = 1.0 / args.rate
    type_label = GENERATORS[args.type] if args.type else "Random Mix"

    print("=" * 50)
    print(f"  AI-IDS Attack-Only Replay")
    print(f"  Type: {type_label}")
    print(f"  Rate: {args.rate} flows/sec")
    print("=" * 50 + "\n")

    sent = detected = 0

    try:
        while True:
            if args.count > 0 and sent >= args.count:
                break

            if args.type:
                name = GENERATORS[args.type]
            else:
                key = np.random.choice(list(GENERATORS.keys()))
                name = GENERATORS[key]

            features = add_derived(gen_attack(name))
            src_ip = np.random.choice(ATTACK_IPS)
            flow_id = f"{src_ip}-{uuid.uuid4().hex[:8]}"

            try:
                r = requests.post(f"{args.api}/predict",
                                  json={"flow_id": flow_id, "features": features}, timeout=5)
                result = r.json()
                sent += 1

                label = result.get("label_text", "?")
                score = result.get("score", 0)
                det_type = result.get("attack_type", "")
                severity = result.get("severity", "")
                is_det = label == "Attack"
                if is_det:
                    detected += 1

                icon = "[DET]" if is_det else "[---]"
                det_rate = detected / sent * 100 if sent > 0 else 0
                match = "OK" if det_type == name else f"->{det_type}" if det_type else ""
                print(f"  {icon} [{name:>12}] {flow_id} -> {label} "
                      f"(score={score:.3f}, sev={severity}) {match}  "
                      f"[det: {det_rate:.0f}%]")

            except requests.ConnectionError:
                print("  [!] API unavailable - retrying...")
                time.sleep(3)
                continue

            time.sleep(delay)

    except KeyboardInterrupt:
        pass

    det_rate = detected / sent * 100 if sent > 0 else 0
    print(f"\n{'='*55}")
    print(f"  Sent: {sent} | Detected: {detected} | Rate: {det_rate:.1f}%")
    print(f"{'='*55}")


if __name__ == "__main__":
    main()
