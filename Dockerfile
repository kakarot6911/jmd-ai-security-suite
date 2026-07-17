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
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health').status==200 else 1)"

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
