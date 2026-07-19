# JMD Security Suite — unified website + REST API in one container.
#
#   docker build -t jmd-security-suite .
#   docker run --rm -p 8000:8000 jmd-security-suite
#   → website  http://localhost:8000
#   → API docs http://localhost:8000/docs
#
# PhishGuard lives in a separate repo and is NOT bundled; the suite degrades
# gracefully (its module simply reports offline). To include it, mount the repo
# and point PHISHGUARD_ROOT at it:
#   docker run -p 8000:8000 -e PHISHGUARD_ROOT=/phishguard \
#              -v ~/jmd_phishguard:/phishguard jmd-security-suite
FROM python:3.14-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install deps first so the layer caches across code changes.
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# App code (a .dockerignore keeps .venv/.git/caches out of the image).
COPY . .

# Ensure the synthetic breach corpus exists (no-op if already committed).
RUN python breachradar/data/generate_breaches.py

# Run as a non-root user.
RUN useradd --create-home appuser && chown -R appuser /app
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import os,urllib.request,sys; p=os.environ.get('PORT','8000'); sys.exit(0 if urllib.request.urlopen(f'http://localhost:{p}/health').status==200 else 1)"

# Honour $PORT when the host injects one (Render/Railway/Fly), else default 8000.
CMD ["sh", "-c", "uvicorn api.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
