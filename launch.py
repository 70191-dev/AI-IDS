"""
AI-IDS Launcher — starts API + dashboard with one command.
  1. FastAPI backend  (port 8000)
  2. Streamlit UI     (opens in browser)

Replay is OFF by default — start it from the dashboard sidebar (or POST
/replay/start manually). Live capture is also opt-in via the sidebar; or
use tools/dev_up.bat to auto-start capture on the VMnet8 interface.

Usage: python launch.py
"""

import subprocess
import sys
import time
import os
from pathlib import Path

ROOT = Path(__file__).parent.resolve()
os.chdir(str(ROOT))
PYTHON = str(ROOT / ".venv" / "Scripts" / "python.exe")
if not Path(PYTHON).exists():
    PYTHON = sys.executable

API_BASE = "http://127.0.0.1:8000"
processes = []
LOG_DIR = ROOT / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)


def start(name, cmd, wait=0, log_file=None):
    """Start a background process with optional log file for stderr."""
    print(f"  Starting {name}...")
    stderr_target = None
    log_fh = None
    if log_file:
        log_fh = open(LOG_DIR / log_file, "w", encoding="utf-8")
        stderr_target = log_fh
    p = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=stderr_target or subprocess.STDOUT,
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
    )
    processes.append((name, p, log_fh))
    if wait:
        time.sleep(wait)
    return p


def wait_for_api(timeout=30):
    """Poll /health until it responds or timeout."""
    import requests
    deadline = time.time() + timeout
    last_err = None
    while time.time() < deadline:
        try:
            r = requests.get(f"{API_BASE}/health", timeout=2)
            if r.ok:
                return r.json()
        except Exception as e:
            last_err = e
        time.sleep(0.5)
    raise RuntimeError(f"API did not come up within {timeout}s (last error: {last_err})")


def cleanup():
    """Terminate all background processes."""
    print("\n  Shutting down...")
    # Ask the API to stop replay/capture first so they exit cleanly.
    try:
        import requests
        requests.post(f"{API_BASE}/replay/stop", timeout=2)
        requests.post(f"{API_BASE}/capture/stop", timeout=2)
    except Exception:
        pass

    for entry in processes:
        name, p = entry[0], entry[1]
        log_fh = entry[2] if len(entry) > 2 else None
        try:
            p.terminate()
            p.wait(timeout=3)
            print(f"    Stopped {name}")
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
        if log_fh:
            try:
                log_fh.close()
            except Exception:
                pass
    print("  Done.\n")


def main():
    print()
    print("  AI-IDS  Intrusion Detection System")
    print("  " + "=" * 38)
    print()

    # 1. Start FastAPI
    start("FastAPI API server", [
        PYTHON, "-m", "uvicorn", "src.serve.app:app",
        "--host", "127.0.0.1", "--port", "8000",
        "--log-level", "warning",
    ], log_file="fastapi.log")

    # 2. Wait for the API to be reachable. (Replay is no longer auto-started;
    #    it's an opt-in toggle in the dashboard sidebar — see comment in module
    #    docstring. We still block on /health so Streamlit doesn't load against
    #    an unhealthy backend.)
    try:
        info = wait_for_api()
        print(f"  API ready: {info.get('flows_processed', 0)} flows in DB, "
              f"classes={info.get('classes', [])}")
    except Exception as e:
        print(f"  WARNING: {e}")
        print("  Streamlit will still launch but the API is not responding.\n")

    print("  Replay is OFF by default. Use the dashboard sidebar to start "
          "replay traffic, or POST to /replay/start manually.")

    # 3. Streamlit (foreground)
    print()
    print("  Opening dashboard in browser...")
    print("  Live capture: enable from the sidebar (requires admin).")
    print("  Press Ctrl+C to stop everything.\n")
    print("  " + "-" * 38)
    print()

    # Streamlit runs in headless mode (no auto-browser) because the desktop
    # window wrapper (desktop_app.py) is the primary UI. The server is still
    # reachable at http://localhost:8501 as a browser fallback if the window
    # is closed or fails to open.
    streamlit_proc = subprocess.Popen([
        PYTHON, "-m", "streamlit", "run", "dashboard/app.py",
        "--server.port", "8501",
        "--server.headless", "true",
        "--browser.gatherUsageStats", "false",
        "--theme.base", "dark",
    ])

    # Open the native desktop window once Streamlit is reachable. The window
    # poller inside desktop_app.py handles the wait — we just spawn it
    # detached so closing the window doesn't kill the backend stack.
    desktop_script = ROOT / "desktop_app.py"
    desktop_proc = None
    if desktop_script.exists():
        try:
            print("  Opening desktop window (pywebview)...")
            desktop_proc = subprocess.Popen([PYTHON, str(desktop_script)])
            processes.append(("Desktop window", desktop_proc, None))
        except Exception as e:
            print(f"  WARNING: could not launch desktop window ({e}). "
                  f"Fallback: open http://localhost:8501 in a browser.")
    else:
        print("  desktop_app.py not found — open http://localhost:8501 in a browser.")

    try:
        streamlit_proc.wait()
    except KeyboardInterrupt:
        pass
    finally:
        streamlit_proc.terminate()
        cleanup()


if __name__ == "__main__":
    main()
