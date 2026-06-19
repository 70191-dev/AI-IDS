"""
AI-IDS FastAPI Backend (v2.2)
─────────────────────────────
Endpoints:
  GET  /health                         → API + traffic-source status
  POST /predict                        → Classify a flow (binary + multi-class)
  GET  /alerts                         → Recent alerts (hot cache, seeded from SQL)
  GET  /stats                          → Aggregate stats (SQL is source of truth)
  GET  /mitigation/{type}/{severity}   → Mitigation recommendations

Control:
  GET  /capture/interfaces             → List Scapy network interfaces
  POST /capture/start  {iface}         → Start live capture (admin required)
  POST /capture/stop                   → Stop live capture
  GET  /capture/status                 → Capture thread status
  POST /replay/start   {rate, attack_ratio}  → Start replay subprocess
  POST /replay/stop                    → Stop replay
  GET  /replay/status                  → Replay subprocess status

Persistence: all detections write to data/ids.db (traffic_flow → detection_result
→ alert → mitigation_record) in a single transaction. logs/alerts.csv is kept
as a backup with 5 MB rotation.
"""

import sys
import os
import subprocess
import threading
from contextlib import asynccontextmanager
from pathlib import Path

# Find project root
_p = Path(__file__).resolve().parent
while _p != _p.parent:
    if (_p / "env" / "requirements.txt").exists():
        break
    _p = _p.parent
else:
    _p = Path.cwd()
PROJECT_ROOT = _p
if not (PROJECT_ROOT / "src").is_dir():
    PROJECT_ROOT = Path.cwd()
sys.path.insert(0, str(PROJECT_ROOT))

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import pandas as pd
import numpy as np
import joblib
import json
from datetime import datetime
from collections import deque, Counter

from src.utils.helpers import get_severity, get_mitigation, log_alert
from src.utils import db
from src.auth.rbac import require_permission
from src.auth.audit import log_audit
from src.serve.auth_routes import router as auth_router
from src.serve.mitigation_routes import router as mitigation_router
from src.serve.report_routes import router as report_router
from src.mitigation.firewall import is_admin

LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}

# ── Config ───────────────────────────────────────────────────
MODEL_DIR = PROJECT_ROOT / "models"
META_PATH = MODEL_DIR / "model_meta.json"
PYTHON_EXE = sys.executable


# ── Threshold Loading ────────────────────────────────────────
def load_threshold():
    """Priority: env var → model_meta.json → threshold.txt → 0.5"""
    env_t = os.getenv("THRESHOLD")
    if env_t is not None:
        try:
            return float(env_t)
        except ValueError:
            pass
    if META_PATH.exists():
        try:
            with open(META_PATH, encoding="utf-8") as f:
                meta = json.load(f)
            t = meta.get("threshold")
            if t is not None:
                return float(t)
        except Exception:
            pass
    thr_path = MODEL_DIR / "threshold.txt"
    if thr_path.exists():
        try:
            return float(thr_path.read_text().strip())
        except Exception:
            pass
    return 0.5


def load_model(primary_name, *fallback_names):
    for name in [primary_name] + list(fallback_names):
        path = MODEL_DIR / name
        if path.exists():
            return joblib.load(str(path)), name
    return None, None


# ── State ────────────────────────────────────────────────────
model_binary = None
model_multi = None
feature_names = None
class_names = None
reverse_class_map = None
THRESHOLD = 0.5
MODEL_VERSION = None

data_source = "unknown"
# Hot cache of recent detections, seeded from SQL at startup.
# Source of truth is data/ids.db.
recent_alerts = deque(maxlen=1000)

_capture_state = {
    "thread": None,
    "stop_event": None,
    "iface": None,
    "started_at": None,
    "error": None,
}
_capture_lock = threading.Lock()

_replay_state = {
    "proc": None,
    "started_at": None,
    "rate": None,
    "attack_ratio": None,
}
_replay_lock = threading.Lock()


# ── Lifespan ─────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global model_binary, model_multi, feature_names, class_names
    global reverse_class_map, THRESHOLD, data_source, MODEL_VERSION

    THRESHOLD = load_threshold()
    print(f"  Decision threshold: {THRESHOLD:.4f}")

    model_binary, bin_name = load_model("rf_cic_binary.joblib", "rf_binary.joblib", "rf.joblib")
    if model_binary is not None:
        print(f"  Binary model: {bin_name}")
        MODEL_VERSION = bin_name
    else:
        print(f"  ERROR: No binary model found in {MODEL_DIR}")
        raise FileNotFoundError("No binary model found")

    model_multi, multi_name = load_model("rf_cic_multi.joblib", "rf_multi.joblib")
    if model_multi is not None:
        print(f"  Multi-class model: {multi_name}")
    else:
        print(f"  NOTE: No multi-class model - binary-only mode")

    if META_PATH.exists():
        try:
            with open(META_PATH, encoding="utf-8") as f:
                meta = json.load(f)
            feature_names = meta.get("feature_names")
            class_names = meta.get("class_names")
            reverse_class_map = {int(k): v for k, v in meta.get("reverse_class_map", {}).items()}
            data_source = meta.get("data_source", "unknown")
            print(f"  Metadata: {len(feature_names)} features, {len(class_names or [])} classes")
            print(f"  Data source: {data_source}")
        except Exception as e:
            print(f"  WARNING: Could not load metadata: {e}")
    else:
        print("  NOTE: No model_meta.json found")

    # Initialize SQLite (idempotent) and seed the hot cache from the DB.
    db.init_db()
    print(f"  SQLite ready at: {db.DB_PATH}")
    try:
        rows = db.fetch_recent_alerts(limit=recent_alerts.maxlen)
        # fetch returns newest-first; appendleft preserves that order in the deque
        for r in reversed(rows):
            recent_alerts.appendleft({
                "time":        r["time"],
                "flow_id":     r["flow_id"],
                "alert_id":    r["alert_id"],
                "src_ip":      r["src_ip"] or "",
                "score":       round(float(r["score"]), 4),
                "label":       r["label"],
                "attack_type": r["attack_type"] or "",
                "severity":    r["severity"] or "None",
                "dst_port":    r["dst_port"] or "",
            })
        print(f"  Hydrated {len(recent_alerts)} alerts from SQL")
    except Exception as e:
        print(f"  WARNING: Could not hydrate cache from SQL: {e}")

    print(f"\n  AI-IDS API ready (threshold={THRESHOLD:.4f})")
    yield
    # Shutdown: stop capture/replay so threads/subprocesses don't outlive us.
    _stop_capture_silent()
    _stop_replay_silent()


app = FastAPI(
    title="AI-IDS Detection API",
    description="ML-based intrusion detection with multi-class classification, "
                "SQLite persistence, and live capture / replay control.",
    version="2.2.0",
    lifespan=lifespan,
)
# C2 fix: pinned to Streamlit origin (was "*"); W4-Sub4d
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501", "http://127.0.0.1:8501"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(auth_router)
app.include_router(mitigation_router)
app.include_router(report_router)


# ── Schemas ──────────────────────────────────────────────────
class Flow(BaseModel):
    flow_id: str
    features: dict
    # Optional flow-identity fields. Live capture extracts these from the
    # packet stream and sends them explicitly; replay omits them and the DB
    # layer falls back to flow_id-prefix parsing.
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[int] = None


class PredictionResult(BaseModel):
    flow_id: str
    score: float
    label: int
    label_text: str
    attack_type: str
    attack_confidence: float
    severity: str
    mitigation: dict
    timestamp: str


class CaptureStartReq(BaseModel):
    iface: Optional[str] = None


class ReplayStartReq(BaseModel):
    rate: float = 5.0
    attack_ratio: float = 0.45


# ── Feature alignment ────────────────────────────────────────
def build_feature_df(features: dict) -> pd.DataFrame:
    if feature_names:
        row = {fn: features.get(fn, 0) for fn in feature_names}
    else:
        row = features
    df = pd.DataFrame([row])
    df.replace([np.inf, -np.inf], 0, inplace=True)
    df.fillna(0, inplace=True)
    return df


def _infer_source_mode(flow_id: str) -> str:
    if isinstance(flow_id, str) and flow_id.startswith("live-"):
        return "live"
    if isinstance(flow_id, str) and flow_id.startswith("demo-"):
        return "manual"
    return "replay"


# ── Endpoints: read ──────────────────────────────────────────
@app.get("/health")
def health():
    return {
        "status": "ok",
        "model_binary": model_binary is not None,
        "model_multi": model_multi is not None,
        "model_version": MODEL_VERSION,
        "threshold": THRESHOLD,
        "data_source": data_source,
        "model_path": str(MODEL_DIR),
        "db_path": str(db.DB_PATH),
        "flows_processed": db.table_counts().get("detection_result", 0),
        "classes": class_names,
        "n_features": len(feature_names) if feature_names else 0,
        "capture_running": _capture_state["thread"] is not None and _capture_state["thread"].is_alive(),
        "replay_running": _replay_state["proc"] is not None and _replay_state["proc"].poll() is None,
        "admin_elevated": is_admin(),
    }


@app.post("/predict", response_model=PredictionResult)
def predict(flow: Flow, request: Request):
    # /predict is the only un-authed endpoint (replay + live capture POST to it
    # M2M). Restrict to loopback callers to compensate. We deliberately read
    # request.client.host (socket-level), not X-Forwarded-For, so a remote
    # caller cannot spoof loopback by setting a header.
    client_host = request.client.host if request.client else None
    if client_host not in LOOPBACK_HOSTS:
        raise HTTPException(
            status_code=403,
            detail="Predict endpoint is loopback-only",
        )

    if model_binary is None:
        raise HTTPException(status_code=503, detail="Model not loaded")

    X = build_feature_df(flow.features)

    score = float(model_binary.predict_proba(X)[:, 1][0])
    label = int(score >= THRESHOLD)
    label_text = "Attack" if label == 1 else "Benign"

    attack_type = ""
    attack_confidence = 0.0
    if label == 1 and model_multi is not None:
        multi_proba = model_multi.predict_proba(X)[0]
        multi_pred = int(model_multi.predict(X)[0])
        attack_type = reverse_class_map.get(multi_pred, f"Class-{multi_pred}") if reverse_class_map else f"Class-{multi_pred}"
        attack_confidence = float(max(multi_proba))
        if attack_type == "Benign" and reverse_class_map:
            for idx, prob in sorted(enumerate(multi_proba), key=lambda x: -x[1]):
                name = reverse_class_map.get(idx, "")
                if name != "Benign":
                    attack_type = name
                    attack_confidence = float(prob)
                    break

    severity = get_severity(score) if label == 1 else "None"
    mitigation = get_mitigation(attack_type, severity) if label == 1 else {}
    timestamp = datetime.now().isoformat(timespec="seconds")
    source_mode = _infer_source_mode(flow.flow_id)

    # Primary store: SQLite (single transaction across 2–4 tables).
    db_ids: dict = {}
    try:
        db_ids = db.insert_flow_result(
            flow_id=flow.flow_id,
            features=flow.features,
            score=score,
            label=label,
            label_text=label_text,
            attack_type=attack_type,
            attack_confidence=attack_confidence,
            severity=severity,
            mitigation=mitigation,
            model_version=MODEL_VERSION,
            threshold=THRESHOLD,
            source_mode=source_mode,
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
        ) or {}
    except Exception as e:
        # Don't fail the request on a DB hiccup — log and continue with CSV+cache.
        print(f"  [db] insert failed: {e}")

    # Backup store: CSV (auto-rotates at 5 MB).
    log_alert(flow.flow_id, score, label, attack_type, severity, flow.features)

    # Hot cache for the dashboard. alert_id + src_ip are needed by the
    # Streamlit "Request block" panel; they're None/"" for benign rows.
    recent_alerts.appendleft({
        "time": timestamp,
        "flow_id": flow.flow_id,
        "alert_id": db_ids.get("alert_pk"),
        "src_ip": flow.src_ip or "",
        "score": round(score, 4),
        "label": label_text,
        "attack_type": attack_type,
        "severity": severity,
        "dst_port": flow.features.get("destination_port", flow.features.get("dst_port", "")),
    })

    return PredictionResult(
        flow_id=flow.flow_id,
        score=round(score, 4),
        label=label,
        label_text=label_text,
        attack_type=attack_type,
        attack_confidence=round(attack_confidence, 4),
        severity=severity,
        mitigation=mitigation,
        timestamp=timestamp,
    )


@app.get("/alerts")
def get_alerts(limit: int = Query(default=100, le=1000)):
    """Hot cache slice. Cache is seeded from SQL at startup and updated
    on every /predict. For historical queries beyond the cache, query SQL directly."""
    return {"alerts": list(recent_alerts)[:limit]}


@app.get("/stats")
def get_stats():
    """Aggregate stats from SQL — source of truth, survives restarts."""
    s = db.fetch_stats()
    s["threshold"] = THRESHOLD
    return s


@app.get("/mitigation/{attack_type}/{severity}")
def mitigation_lookup(attack_type: str, severity: str):
    return get_mitigation(attack_type, severity)


def _audit_action(request: Request, current_user: dict, *,
                  action: str, target: Optional[str], detail: Optional[str]):
    """Helper: write a success audit row for capture/replay control endpoints."""
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")
    conn = db.get_conn()
    try:
        log_audit(
            conn,
            actor_user_id=current_user["user_id"],
            actor_username=current_user["username"],
            action=action,
            target=target,
            status="success",
            detail=detail,
            ip=ip, ua=ua,
        )
    finally:
        conn.close()


# ── Endpoints: capture control ───────────────────────────────
def _normalize_npf_iface(name):
    """Normalize a Windows interface name to libpcap's required form.

    scapy.get_if_list() on this Npcap setup returns bare GUID strings like
    '{6BBC0B16-...}'. libpcap requires the '\\Device\\NPF_' prefix and rejects
    the bare form with Windows error 123 (ERROR_INVALID_NAME). Pad bare GUIDs
    here; leave already-prefixed names (incl. '\\Device\\NPF_Loopback') alone.
    """
    if isinstance(name, str) and name.startswith("{") and name.endswith("}"):
        return f"\\Device\\NPF_{name}"
    return name


@app.get("/capture/interfaces")
def capture_interfaces():
    """List Scapy interfaces with friendly labels.

    Each entry is {id, name, description}. `id` is the NPF device path
    that /capture/start expects (unchanged from the previous string-only
    response). `name` and `description` come from scapy's
    get_windows_if_list() matched by GUID. Both fall back to "" for the
    loopback adapter, on non-Windows, or if scapy's Windows helper isn't
    available -- in which case the dashboard falls back to showing the
    raw id, so the page never breaks on a missing label.
    """
    try:
        from scapy.all import get_if_list
    except ImportError:
        return {"interfaces": [], "error": "scapy not installed"}
    except Exception as e:
        return {"interfaces": [], "error": str(e)}

    try:
        raw_ids = [_normalize_npf_iface(x) for x in get_if_list()]
    except Exception as e:
        return {"interfaces": [], "error": str(e)}

    # Build a GUID -> {name, description} map from the Windows helper.
    # Any failure here is non-fatal -- we just return id-only entries.
    win_map: dict = {}
    try:
        from scapy.arch.windows import get_windows_if_list
        for entry in get_windows_if_list() or []:
            guid = entry.get("guid")
            if isinstance(guid, str) and guid:
                win_map[guid.upper()] = {
                    "name":        entry.get("name", "") or "",
                    "description": entry.get("description", "") or "",
                }
    except Exception:
        pass

    out = []
    for iface_id in raw_ids:
        name = ""
        description = ""
        if "{" in iface_id and "}" in iface_id:
            try:
                guid_part = "{" + iface_id.split("{", 1)[1].split("}", 1)[0] + "}"
                meta = win_map.get(guid_part.upper())
                if meta:
                    name = meta["name"]
                    description = meta["description"]
            except Exception:
                pass
        out.append({"id": iface_id, "name": name, "description": description})

    return {"interfaces": out}


@app.post("/capture/start")
def capture_start(
    req: CaptureStartReq,
    request: Request,
    current_user: dict = Depends(require_permission("capture.control")),
):
    with _capture_lock:
        if _capture_state["thread"] is not None and _capture_state["thread"].is_alive():
            raise HTTPException(status_code=409, detail="Capture already running")

        try:
            from src.capture.live_capture import run_in_thread
        except ImportError as e:
            raise HTTPException(status_code=500, detail=f"Capture module import failed: {e}")

        # Defense in depth: normalize bare-GUID iface strings even if some
        # caller didn't go through /capture/interfaces.
        iface = _normalize_npf_iface(req.iface) if req.iface else req.iface
        try:
            thread, stop_event = run_in_thread(iface, "http://127.0.0.1:8000")
        except PermissionError:
            # Structured error so the dashboard can render a toast (adjustment #1).
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "admin_required",
                    "message": "Live capture requires running the API as Administrator. "
                               "Close and relaunch START.bat with admin rights.",
                },
            )
        except ImportError as e:
            raise HTTPException(
                status_code=500,
                detail={
                    "error": "scapy_missing",
                    "message": f"Scapy is not installed: {e}. Run: pip install scapy. "
                               "On Windows also install Npcap (https://npcap.com/).",
                },
            )

        _capture_state.update({
            "thread": thread,
            "stop_event": stop_event,
            "iface": iface,
            "started_at": datetime.now().isoformat(timespec="seconds"),
            "error": None,
        })

        _audit_action(
            request, current_user,
            action="capture.start",
            target=f"iface:{iface}" if iface else None,
            detail=f"started capture on {iface or 'auto'}",
        )
        return {"status": "started", "iface": iface or "auto"}


def _stop_capture_silent():
    """Used at shutdown; never raises."""
    with _capture_lock:
        ev = _capture_state.get("stop_event")
        th = _capture_state.get("thread")
        if ev is not None:
            ev.set()
        if th is not None:
            try:
                th.join(timeout=5)
            except Exception:
                pass
        _capture_state.update({"thread": None, "stop_event": None, "iface": None, "started_at": None})


@app.post("/capture/stop")
def capture_stop(
    request: Request,
    current_user: dict = Depends(require_permission("capture.control")),
):
    if _capture_state["thread"] is None or not _capture_state["thread"].is_alive():
        return {"status": "not_running"}
    iface = _capture_state.get("iface")
    _stop_capture_silent()
    _audit_action(
        request, current_user,
        action="capture.stop",
        target=f"iface:{iface}" if iface else None,
        detail=None,
    )
    return {"status": "stopped"}


@app.get("/capture/status")
def capture_status():
    th = _capture_state["thread"]
    running = th is not None and th.is_alive()
    return {
        "running": running,
        "iface": _capture_state["iface"] if running else None,
        "started_at": _capture_state["started_at"] if running else None,
        "error": _capture_state["error"],
    }


# ── Endpoints: replay control ────────────────────────────────
@app.post("/replay/start")
def replay_start(
    req: ReplayStartReq,
    request: Request,
    current_user: dict = Depends(require_permission("replay.control")),
):
    with _replay_lock:
        if _replay_state["proc"] is not None and _replay_state["proc"].poll() is None:
            raise HTTPException(status_code=409, detail="Replay already running")

        script = PROJECT_ROOT / "tools" / "replay_loop.py"
        if not script.exists():
            raise HTTPException(status_code=500, detail=f"Replay script missing: {script}")

        log_path = PROJECT_ROOT / "logs" / "replay.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_fh = open(log_path, "a", encoding="utf-8")

        proc = subprocess.Popen(
            [PYTHON_EXE, str(script),
             "--rate", str(req.rate),
             "--attack-ratio", str(req.attack_ratio)],
            stdout=log_fh, stderr=subprocess.STDOUT,
            cwd=str(PROJECT_ROOT),
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )
        _replay_state.update({
            "proc": proc,
            "started_at": datetime.now().isoformat(timespec="seconds"),
            "rate": req.rate,
            "attack_ratio": req.attack_ratio,
        })
        _audit_action(
            request, current_user,
            action="replay.start",
            target=None,
            detail=f"rate={req.rate} attack_ratio={req.attack_ratio}",
        )
        return {"status": "started", "pid": proc.pid, "rate": req.rate, "attack_ratio": req.attack_ratio}


def _stop_replay_silent():
    with _replay_lock:
        proc = _replay_state.get("proc")
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        _replay_state.update({"proc": None, "started_at": None, "rate": None, "attack_ratio": None})


@app.post("/replay/stop")
def replay_stop(
    request: Request,
    current_user: dict = Depends(require_permission("replay.control")),
):
    proc = _replay_state["proc"]
    if proc is None or proc.poll() is not None:
        return {"status": "not_running"}
    _stop_replay_silent()
    _audit_action(
        request, current_user,
        action="replay.stop",
        target=None,
        detail=None,
    )
    return {"status": "stopped"}


@app.get("/replay/status")
def replay_status():
    proc = _replay_state["proc"]
    running = proc is not None and proc.poll() is None
    return {
        "running": running,
        "pid": proc.pid if running else None,
        "rate": _replay_state["rate"] if running else None,
        "attack_ratio": _replay_state["attack_ratio"] if running else None,
        "started_at": _replay_state["started_at"] if running else None,
    }
