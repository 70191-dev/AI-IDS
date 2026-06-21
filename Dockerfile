# AI-IDS — Tier 1 cloud (analysis plane) image — Hugging Face Spaces (Docker SDK)
# =============================================================================
# One Linux container: FastAPI (loopback) + Streamlit (public) + SQLite + auth +
# mitigation workflow + replay. Capture / netsh / Ollama / pywebview are absent and
# degrade gracefully (see defense/DEPLOYMENT_REALITY.md) — they do NOT crash startup.
#
# ADDITIVE ONLY. No frozen file is modified. The gitignored models are GENERATED at
# build time from the synthetic pipeline (mock_data.py -> train.py).
#
# NOTE: HF Spaces (Docker SDK) builds the Dockerfile that sits at the REPO ROOT.
#       Copy this file to ./Dockerfile before deploying (see deploy/README.md).
# =============================================================================
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app \
    HOME=/app \
    IDS_DB_PATH=/app/data/ids.db

WORKDIR /app

# 1) Dependencies first (layer caching). Drop ONLY pywebview — the single
#    Windows/desktop-only dep: never imported by the cloud entrypoint, no headless
#    backend on Linux. scapy is KEPT (install-safe on Linux; capture endpoints degrade
#    gracefully). Full rationale in deploy/README.md.
COPY env/requirements.txt /tmp/requirements.txt
RUN grep -iv pywebview /tmp/requirements.txt > /tmp/requirements.cloud.txt \
 && pip install --upgrade pip \
 && pip install -r /tmp/requirements.cloud.txt

# 2) Application source — SELECTIVE COPY. Never copy .venv/, data/downloads/ (844 MB),
#    or data/ids.db (71 MB, ephemeral). Only what the analysis plane needs at runtime.
COPY src/                     ./src/
COPY dashboard/               ./dashboard/
COPY tools/                   ./tools/
COPY assets/                  ./assets/
COPY .streamlit/              ./.streamlit/
COPY data/cic_profiles.json   ./data/cic_profiles.json
COPY deploy/                  ./deploy/

# 3) BAKE THE MODELS at build time (they are gitignored, so the image must make them).
#    mock_data.py writes synthetic CIC-style data; train.py emits rf_binary/rf_multi/
#    rf.joblib + model_meta.json + threshold.txt. app.py loads these via its fallback
#    names (rf_cic_* -> rf_* -> rf). Resolves the "missing models = crash" blocker. ~2-3 min.
RUN python src/data/mock_data.py \
 && python src/models/train.py

# 4) Non-root runtime user + writable dirs (HF runs non-root; data/ + logs/ must be
#    writable). Normalize entrypoint line endings in case it was authored on Windows.
RUN sed -i 's/\r$//' deploy/entrypoint.sh \
 && chmod +x deploy/entrypoint.sh \
 && useradd -m -u 1000 appuser \
 && mkdir -p /app/data /app/logs \
 && chown -R appuser:appuser /app
USER appuser

# HF Spaces serves the port declared as `app_port` in the README metadata (7860).
EXPOSE 7860

ENTRYPOINT ["bash", "deploy/entrypoint.sh"]
