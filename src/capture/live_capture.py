"""
Live Packet Capture Module
--------------------------
Captures live network packets using Scapy, aggregates them into flows,
extracts features, and sends them to the API for classification.

Requirements:
    pip install scapy
    Run with admin/root privileges for live capture.

Usage:
    python src/capture/live_capture.py [--iface eth0] [--api http://127.0.0.1:8000]

Note: This requires administrator/root privileges to capture packets.
On Windows, also requires Npcap (https://npcap.com/).
"""

import sys
import time
import argparse
import uuid
import json
import threading
from collections import defaultdict
from datetime import datetime

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)

# ── Flow aggregation ─────────────────────────────────────────────
# We collect packets into flows based on (src_ip, dst_ip, src_port, dst_port, protocol)
# and periodically flush completed flows to the API.

FLOW_TIMEOUT = 5.0     # seconds before a flow is considered complete
FLUSH_INTERVAL = 3.0   # how often to check for expired flows

API_URL = "http://127.0.0.1:8000"


class FlowAggregator:
    """Aggregates packets into network flows and extracts features."""

    def __init__(self):
        self.flows = defaultdict(lambda: {
            "start_time": None,
            "last_time": None,
            "fwd_packets": [],
            "bwd_packets": [],
            "fwd_lengths": [],
            "bwd_lengths": [],
            "fwd_iats": [],
            "bwd_iats": [],
            "flags": defaultdict(int),
            "src_ip": "",
            "dst_ip": "",
            "src_port": 0,
            "dst_port": 0,
            "protocol": 0,
        })
        self.lock = threading.Lock()

    def add_packet(self, src_ip, dst_ip, src_port, dst_port, protocol,
                   pkt_len, flags_dict, timestamp):
        """Add a packet to the appropriate flow."""
        # Flow key: bidirectional
        fwd_key = (src_ip, dst_ip, src_port, dst_port, protocol)
        bwd_key = (dst_ip, src_ip, dst_port, src_port, protocol)

        with self.lock:
            # Check if this is forward or backward
            if fwd_key in self.flows:
                flow = self.flows[fwd_key]
                is_fwd = True
            elif bwd_key in self.flows:
                flow = self.flows[bwd_key]
                is_fwd = False
            else:
                # New flow
                flow = self.flows[fwd_key]
                flow["src_ip"] = src_ip
                flow["dst_ip"] = dst_ip
                flow["src_port"] = src_port
                flow["dst_port"] = dst_port
                flow["protocol"] = protocol
                is_fwd = True

            now = timestamp
            if flow["start_time"] is None:
                flow["start_time"] = now

            if is_fwd:
                if flow["fwd_packets"]:
                    iat = (now - flow["fwd_packets"][-1]) * 1e6  # microseconds
                    flow["fwd_iats"].append(iat)
                flow["fwd_packets"].append(now)
                flow["fwd_lengths"].append(pkt_len)
            else:
                if flow["bwd_packets"]:
                    iat = (now - flow["bwd_packets"][-1]) * 1e6
                    flow["bwd_iats"].append(iat)
                flow["bwd_packets"].append(now)
                flow["bwd_lengths"].append(pkt_len)

            for flag, val in flags_dict.items():
                flow["flags"][flag] += val

            flow["last_time"] = now

    def flush_expired(self, timeout=FLOW_TIMEOUT):
        """Return and remove flows that have timed out."""
        now = time.time()
        expired = []

        with self.lock:
            keys_to_remove = []
            for key, flow in self.flows.items():
                if flow["last_time"] and (now - flow["last_time"]) > timeout:
                    expired.append(self._extract_features(flow))
                    keys_to_remove.append(key)
            for key in keys_to_remove:
                del self.flows[key]

        return expired

    def flush_all(self):
        """Flush all active flows."""
        expired = []
        with self.lock:
            for key, flow in self.flows.items():
                if flow["start_time"] is not None:
                    expired.append(self._extract_features(flow))
            self.flows.clear()
        return expired

    def _extract_features(self, flow):
        """Extract the 50 unified features the model expects.

        Schema parity with src/data/mock_data.py and src/data/prep_cic2017.py:
          - For features both files compute identically (subflow_*,
            fwd/bwd_header_length, fwd_psh_flags, fwd_urg_flags), use the
            same identity formulas here.
          - For features that mock_data fabricates with random multipliers
            but CIC-IDS2017 provides natively (packet_length_max/std,
            iat_std), compute the REAL value from the captured packets —
            this matches the CIC half of training, which the model relies on.
          - active_std / idle_std: live capture does not track active/idle
            burst periods the way CICFlowMeter does, so we use the same
            missing-column fill formula prep_cic2017.py uses: mean * 0.5.
            Documented in CHANGES.md.
        """
        import numpy as np

        fwd_lens = flow["fwd_lengths"] or [0]
        bwd_lens = flow["bwd_lengths"] or [0]
        all_lens = fwd_lens + bwd_lens

        fwd_iats = flow["fwd_iats"] or [0]
        bwd_iats = flow["bwd_iats"] or [0]
        all_iats = fwd_iats + bwd_iats

        duration = 0
        if flow["start_time"] and flow["last_time"]:
            duration = (flow["last_time"] - flow["start_time"]) * 1e6  # microseconds

        n_fwd = len(flow["fwd_packets"])
        n_bwd = len(flow["bwd_packets"])
        total_pkts = n_fwd + n_bwd
        duration_sec = duration / 1e6 + 0.001

        fwd_mean = float(np.mean(fwd_lens))
        bwd_mean = float(np.mean(bwd_lens))
        fwd_iat_mean = float(np.mean(fwd_iats))
        bwd_iat_mean = float(np.mean(bwd_iats))
        active_mean = duration / (total_pkts + 1)
        idle_mean = float(np.mean(all_iats)) if all_iats else 0

        features = {
            # ── Base (38) ─────────────────────────────────────
            "flow_duration":                duration,
            "total_fwd_packets":            n_fwd,
            "total_backward_packets":       n_bwd,
            "total_length_of_fwd_packets":  sum(fwd_lens),
            "total_length_of_bwd_packets":  sum(bwd_lens),
            "fwd_packet_length_mean":       fwd_mean,
            "bwd_packet_length_mean":       bwd_mean,
            "flow_iat_mean":                float(np.mean(all_iats)),
            "flow_iat_std":                 float(np.std(all_iats)),
            "fwd_iat_mean":                 fwd_iat_mean,
            "bwd_iat_mean":                 bwd_iat_mean,
            "syn_flag_count":               flow["flags"].get("SYN", 0),
            "rst_flag_count":               flow["flags"].get("RST", 0),
            "psh_flag_count":               flow["flags"].get("PSH", 0),
            "ack_flag_count":               flow["flags"].get("ACK", 0),
            "fin_flag_count":               flow["flags"].get("FIN", 0),
            "urg_flag_count":               flow["flags"].get("URG", 0),
            "destination_port":             flow["dst_port"],
            "down_up_ratio":                sum(bwd_lens) / (sum(fwd_lens) + 1),
            "init_win_bytes_forward":       8192,  # approximation; not visible from packet stream
            "init_win_bytes_backward":      8192,
            "active_mean":                  active_mean,
            "idle_mean":                    idle_mean,
            "flow_bytes_per_s":             (sum(fwd_lens) + sum(bwd_lens)) / duration_sec,
            "flow_packets_per_s":           total_pkts / duration_sec,
            "packet_length_mean":           float(np.mean(all_lens)),
            "packet_length_std":            float(np.std(all_lens)),
            "min_packet_length":            float(min(all_lens)) if all_lens else 0,
            "max_packet_length":            float(max(all_lens)) if all_lens else 0,
            "average_packet_size":          float(np.mean(all_lens)),
            "avg_fwd_segment_size":         fwd_mean,
            "avg_bwd_segment_size":         bwd_mean,
            "fwd_packets_per_s":            n_fwd / duration_sec,
            "bwd_packets_per_s":            n_bwd / duration_sec,
            "fwd_psh_flags":                flow["flags"].get("PSH", 0),
            "fwd_urg_flags":                flow["flags"].get("URG", 0),
            "fwd_header_length":            n_fwd * 20,
            "bwd_header_length":            n_bwd * 20,
            # ── Schema-parity additions (12) — see method docstring ──
            "fwd_packet_length_max":        float(max(fwd_lens)) if fwd_lens else 0.0,
            "fwd_packet_length_std":        float(np.std(fwd_lens)),
            "bwd_packet_length_max":        float(max(bwd_lens)) if bwd_lens else 0.0,
            "bwd_packet_length_std":        float(np.std(bwd_lens)),
            "fwd_iat_std":                  float(np.std(fwd_iats)),
            "bwd_iat_std":                  float(np.std(bwd_iats)),
            "subflow_fwd_packets":          n_fwd,
            "subflow_fwd_bytes":            sum(fwd_lens),
            "subflow_bwd_packets":          n_bwd,
            "subflow_bwd_bytes":            sum(bwd_lens),
            "active_std":                   active_mean * 0.5,
            "idle_std":                     idle_mean * 0.5,
        }

        meta = {
            "src_ip": flow["src_ip"],
            "dst_ip": flow["dst_ip"],
            "src_port": flow["src_port"],
            "dst_port": flow["dst_port"],
            "protocol": flow["protocol"],
        }

        return features, meta


def scapy_capture(iface, aggregator, stop_event):
    """Capture packets using Scapy."""
    try:
        from scapy.all import sniff, IP, TCP, UDP, ICMP
    except ImportError:
        print("[!] Scapy not installed. Install it: pip install scapy")
        print("  On Windows, also install Npcap: https://npcap.com/")
        stop_event.set()
        return

    def process_packet(pkt):
        if stop_event.is_set():
            return

        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        protocol = ip.proto
        pkt_len = len(pkt)
        timestamp = float(pkt.time)

        src_port = 0
        dst_port = 0
        flags_dict = {}

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            flags_dict = {
                "SYN": 1 if tcp.flags & 0x02 else 0,
                "ACK": 1 if tcp.flags & 0x10 else 0,
                "FIN": 1 if tcp.flags & 0x01 else 0,
                "RST": 1 if tcp.flags & 0x04 else 0,
                "PSH": 1 if tcp.flags & 0x08 else 0,
                "URG": 1 if tcp.flags & 0x20 else 0,
            }
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            src_port = udp.sport
            dst_port = udp.dport

        aggregator.add_packet(
            src_ip, dst_ip, src_port, dst_port, protocol,
            pkt_len, flags_dict, timestamp
        )

    print(f"  Starting capture on {iface or 'default'}...")
    print(f"  (Requires admin/root privileges)")

    try:
        sniff(
            iface=iface,
            prn=process_packet,
            store=False,
            stop_filter=lambda p: stop_event.is_set(),
        )
    except PermissionError:
        print("\n[!] Permission denied. Run as administrator/root.")
        stop_event.set()
    except Exception as e:
        print(f"\n[!] Capture error: {e}")
        stop_event.set()


def flush_and_send(aggregator, api_url, stop_event):
    """Periodically flush flows and send to API."""
    total_sent = 0
    total_attacks = 0

    while not stop_event.is_set():
        time.sleep(FLUSH_INTERVAL)
        flows = aggregator.flush_expired()

        for features, meta in flows:
            flow_id = f"live-{uuid.uuid4().hex[:8]}"
            payload = {
                "flow_id": flow_id,
                "features": features,
                "src_ip":   meta.get("src_ip"),
                "dst_ip":   meta.get("dst_ip"),
                "src_port": meta.get("src_port"),
                "dst_port": meta.get("dst_port"),
                "protocol": meta.get("protocol"),
            }

            try:
                r = requests.post(f"{api_url}/predict", json=payload, timeout=5)
                result = r.json()
                total_sent += 1

                label = result.get("label_text", "?")
                score = result.get("score", 0)
                attack_type = result.get("attack_type", "")
                severity = result.get("severity", "")

                if label == "Attack":
                    total_attacks += 1
                    icon = "[ATK]"
                    detail = f" [{attack_type}] [{severity}]" if attack_type else f" [{severity}]"
                else:
                    icon = "[ OK]"
                    detail = ""

                src = f"{meta['src_ip']}:{meta['src_port']}"
                dst = f"{meta['dst_ip']}:{meta['dst_port']}"
                print(f"  {icon} {src} -> {dst} | {label} (score={score:.3f}){detail}")

            except Exception as e:
                pass  # API might be temporarily unavailable

    # Flush remaining flows on stop
    remaining = aggregator.flush_all()
    print(f"\n  Flushed {len(remaining)} remaining flows")
    print(f"  Total: {total_sent} flows analyzed | {total_attacks} attacks detected")


def run_in_thread(iface, api_url=API_URL):
    """Start capture + flush as background threads. Returns (supervisor_thread, stop_event).

    Raises ImportError if Scapy is not installed.
    Raises PermissionError if the OS denies raw socket access (the API turns
    this into a 'run as administrator' toast).
    """
    # Synchronous import so the caller sees ImportError immediately
    from scapy.all import conf as _scapy_conf

    # Probe privileges synchronously so PermissionError surfaces here, not
    # asynchronously inside the sniff thread. `L2listen` is not exported as
    # a top-level symbol from scapy.all on 2.5+/2.7 — use the class reference
    # on `conf.L2listen` (the libpcap/Npcap listen socket on Windows).
    try:
        L2listen = _scapy_conf.L2listen
        probe = L2listen(iface=iface) if iface else L2listen()
        try:
            probe.close()
        except Exception:
            pass
    except PermissionError:
        raise
    except OSError as e:
        # Windows raises WSA error 10013 for permission-denied raw sockets
        msg = str(e).lower()
        if "10013" in msg or "permission" in msg or "operation not permitted" in msg:
            raise PermissionError(str(e))
        # Other OSErrors (interface missing, etc.) bubble up as-is.
        raise

    aggregator = FlowAggregator()
    stop_event = threading.Event()

    flush_thread = threading.Thread(
        target=flush_and_send,
        args=(aggregator, api_url, stop_event),
        daemon=True,
        name="ids-flush",
    )
    sniff_thread = threading.Thread(
        target=scapy_capture,
        args=(iface, aggregator, stop_event),
        daemon=True,
        name="ids-sniff",
    )

    def supervisor():
        sniff_thread.start()
        flush_thread.start()
        sniff_thread.join()
        # Once sniffing ends (stop_event or error), signal flush to drain and exit.
        stop_event.set()
        flush_thread.join(timeout=5)

    sup = threading.Thread(target=supervisor, daemon=True, name="ids-capture-supervisor")
    sup.start()
    return sup, stop_event


def list_interfaces():
    """List available network interfaces."""
    try:
        from scapy.all import get_if_list
        ifaces = get_if_list()
        print("Available network interfaces:")
        for i, iface in enumerate(ifaces):
            print(f"  [{i}] {iface}")
        return ifaces
    except ImportError:
        print("Install scapy to list interfaces: pip install scapy")
        return []


def main():
    parser = argparse.ArgumentParser(description="AI-IDS Live Packet Capture")
    parser.add_argument("--iface", type=str, default=None, help="Network interface name")
    parser.add_argument("--api", type=str, default=API_URL, help="API URL")
    parser.add_argument("--list", action="store_true", help="List available interfaces")
    parser.add_argument("--timeout", type=float, default=FLOW_TIMEOUT, help="Flow timeout (seconds)")
    args = parser.parse_args()

    if args.list:
        list_interfaces()
        return

    print("=" * 44)
    print("  AI-IDS LIVE PACKET CAPTURE")
    print(f"  Interface: {args.iface or 'auto'}")
    print(f"  API: {args.api}")
    print(f"  Flow timeout: {args.timeout}s")
    print("=" * 44 + "\n")

    aggregator = FlowAggregator()
    stop_event = threading.Event()

    # Start flush thread
    flush_thread = threading.Thread(
        target=flush_and_send,
        args=(aggregator, args.api, stop_event),
        daemon=True,
    )
    flush_thread.start()

    # Start capture (blocks)
    try:
        scapy_capture(args.iface, aggregator, stop_event)
    except KeyboardInterrupt:
        print("\n\nStopping capture...")
        stop_event.set()
        flush_thread.join(timeout=5)
        print("Done.")


if __name__ == "__main__":
    main()
