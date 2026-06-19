#!/usr/bin/env python
"""Resource benchmark for POST /predict  (read-only, additive tool).

Measures end-to-end /predict latency (p50/p95/p99 over N calls) and the
serving process's memory footprint by booting the real FastAPI app
in-process via FastAPI's TestClient -- the exact pattern proven in
tests/test_smoke.py.

What it does NOT touch:
  * models/, src/models/train.py, the 50-feature schema, threshold.txt,
    the FlowAggregator, and the /predict request/response contract are
    all left exactly as-is. This script only POSTs to /predict and reads
    the JSON response.
  * data/ids.db is never written: IDS_DB_PATH is redirected to a throwaway
    tempfile (deleted at the end) BEFORE the app is imported.

No new dependencies: fastapi/starlette TestClient (already installed),
numpy for percentiles, and the Windows psapi API via stdlib ctypes for
the working-set memory read (psutil is not installed; ctypes needs nothing).

Usage:
    .venv\\Scripts\\python.exe tools\\bench_predict.py
    BENCH_N=2000 .venv\\Scripts\\python.exe tools\\bench_predict.py
"""
import os
import sys
import json
import time
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# --- Redirect the DB to a throwaway file BEFORE importing the app -----------
_tmp = tempfile.NamedTemporaryFile(prefix="bench_ids_", suffix=".db", delete=False)
_tmp.close()
os.environ["IDS_DB_PATH"] = _tmp.name
os.environ.pop("MITIGATION_ALLOW_PRIVATE", None)

N = int(os.environ.get("BENCH_N", "1000"))
WARMUP = int(os.environ.get("BENCH_WARMUP", "25"))


def working_set():
    """(current_ws, peak_ws) bytes for THIS process via Windows psapi.

    Returns (None, None) off Windows or on any failure. stdlib only.
    """
    try:
        import ctypes
        from ctypes import wintypes

        class PMC(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        # Explicit signatures so the 64-bit process pseudo-handle (-1) is not
        # truncated to a 32-bit int (which made the call fail silently).
        k32.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(PMC), wintypes.DWORD
        ]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL

        c = PMC()
        c.cb = ctypes.sizeof(c)
        h = k32.GetCurrentProcess()
        if not psapi.GetProcessMemoryInfo(h, ctypes.byref(c), c.cb):
            return (None, None)
        return (c.WorkingSetSize, c.PeakWorkingSetSize)
    except Exception:
        return (None, None)


def mb(x):
    return None if x is None else round(x / (1024 * 1024), 1)


def load_payload():
    """A representative /predict body. Reuses the repo's sample_request.json
    feature dict (build_feature_df zero-fills the rest of the 50 features).
    flow_id 'bench-demo' -> source_mode 'manual'."""
    sample = ROOT / "sample_request.json"
    feats = {}
    if sample.exists():
        feats = json.loads(sample.read_text()).get("features", {})
    return {"flow_id": "bench-demo", "features": feats, "src_ip": "203.0.113.7"}


def main():
    import numpy as np
    from fastapi.testclient import TestClient
    from src.serve.app import app  # imported AFTER IDS_DB_PATH is set

    payload = load_payload()

    # client=("127.0.0.1", 0) satisfies the /predict loopback gate.
    with TestClient(app, client=("127.0.0.1", 0)) as client:
        ws_after_load, _ = working_set()

        r0 = client.post("/predict", json=payload)
        if r0.status_code != 200:
            print(f"ABORT: /predict returned {r0.status_code}: {r0.text[:300]}")
            return
        j0 = r0.json()

        for _ in range(WARMUP):
            client.post("/predict", json=payload)

        lat = np.empty(N, dtype=np.float64)
        t_all0 = time.perf_counter()
        for i in range(N):
            t0 = time.perf_counter()
            client.post("/predict", json=payload)
            lat[i] = (time.perf_counter() - t0) * 1000.0  # ms
        wall = time.perf_counter() - t_all0

        ws_after_run, peak = working_set()

    is_attack = j0.get("label") == 1
    p = lambda q: float(np.percentile(lat, q))

    print("=" * 60)
    print(" AI-IDS  POST /predict  resource benchmark")
    print("=" * 60)
    print(f" python            : {sys.version.split()[0]}")
    print(f" timed calls       : {N}  (+{WARMUP} warmup)")
    print(f" payload           : {len(payload['features'])} feature keys "
          f"(zero-filled to 50 by build_feature_df)")
    print(f" response          : {j0.get('label_text')}  "
          f"(label={j0.get('label')}, score={j0.get('score'):.4f})")
    print(f" code path         : binary head"
          + (" + multi-class head + alert+mitigation write"
             if is_attack else " + flow/detection write (benign path)"))
    print(f" backend version   : {getattr(app, 'version', '?')}")
    print(f" DB                : tempfile (data/ids.db untouched)")
    print("-" * 60)
    print(" latency  (ms, in-process; excludes HTTP/network overhead)")
    print(f"   min   : {lat.min():8.3f}")
    print(f"   p50   : {p(50):8.3f}")
    print(f"   p95   : {p(95):8.3f}")
    print(f"   p99   : {p(99):8.3f}")
    print(f"   max   : {lat.max():8.3f}")
    print(f"   mean  : {lat.mean():8.3f}")
    print(f"   stdev : {lat.std():8.3f}")
    print(f"   throughput : {N / wall:7.1f} req/s  ({wall:.2f}s wall)")
    print("-" * 60)
    print(" memory  (serving process working set; model loaded in-process)")
    print(f"   after model load   : {mb(ws_after_load)} MB")
    print(f"   after {N} calls : {mb(ws_after_run)} MB")
    print(f"   peak working set   : {mb(peak)} MB")
    print("=" * 60)

    # tidy up the throwaway DB (+ WAL/SHM sidecars)
    for suffix in ("", "-wal", "-shm"):
        f = os.environ["IDS_DB_PATH"] + suffix
        try:
            if os.path.exists(f):
                os.unlink(f)
        except OSError:
            pass


if __name__ == "__main__":
    main()
