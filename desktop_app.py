"""
AI-IDS desktop window — pywebview wrapper around the Streamlit SOC dashboard.

Responsibilities:
  * Wait until the Streamlit server at http://localhost:8501 answers HTTP.
  * Open a single native OS window pointing at it (custom icon, custom title).
  * Exit when the window is closed. The backend keeps running so the user can
    fall back to the browser at http://localhost:8501, or relaunch this script.

This script assumes the FastAPI backend and Streamlit are ALREADY running. It
does NOT start them. Orchestration lives in launch.py (which now spawns this
file once Streamlit is reachable).

Usage:
  .venv\\Scripts\\python.exe desktop_app.py
"""

import sys
import time
from pathlib import Path

import requests
import webview

ROOT = Path(__file__).parent.resolve()
ICON_PATH = ROOT / "assets" / "icon.ico"
STREAMLIT_URL = "http://localhost:8501"
WAIT_TIMEOUT_SEC = 60
WAIT_INTERVAL_SEC = 0.5


def wait_for_streamlit(url: str = STREAMLIT_URL, timeout: int = WAIT_TIMEOUT_SEC) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=2)
            if r.status_code < 500:
                return True
        except Exception:
            pass
        time.sleep(WAIT_INTERVAL_SEC)
    return False


def main() -> int:
    print(f"[desktop_app] Waiting for Streamlit at {STREAMLIT_URL} (up to {WAIT_TIMEOUT_SEC}s)...")
    if not wait_for_streamlit():
        print(
            f"[desktop_app] ERROR: Streamlit not reachable at {STREAMLIT_URL} within "
            f"{WAIT_TIMEOUT_SEC}s. Is the backend running? Try START.bat.",
            file=sys.stderr,
        )
        return 2
    print("[desktop_app] Streamlit is up. Opening native window...")

    webview.create_window(
        "AI-IDS — Intrusion Detection & Threat Mitigation",
        STREAMLIT_URL,
        width=1500,
        height=950,
        min_size=(1200, 800),
    )

    # pywebview's icon kwarg is supported on the EdgeChromium (Windows) backend
    # from 4.x onward; it sets the window/taskbar icon. If the running backend
    # doesn't honour it (e.g. older GTK/Cocoa), webview.start still works and we
    # fall back to the default pywebview icon.
    icon_arg = str(ICON_PATH) if ICON_PATH.exists() else None
    try:
        if icon_arg:
            webview.start(icon=icon_arg)
        else:
            webview.start()
    except TypeError:
        # Older pywebview without icon= kwarg
        webview.start()
    return 0


if __name__ == "__main__":
    sys.exit(main())
