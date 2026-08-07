# Deploying the JMD Security Suite

Two independent deployables ship from this one repo:

| What | Serves | Recommended host | Files used |
|------|--------|------------------|------------|
| **Website + REST API** | `web/` single-page site + FastAPI on `/…` and `/docs` | **Render** (Docker, free) | `Dockerfile`, `render.yaml`, `Procfile` |
| **Premium console** | Streamlit multi-tool dashboard | **Streamlit Community Cloud** (free) | `console/app.py`, `requirements.txt`, `.streamlit/config.toml` |

PhishGuard lives in a separate repo and is **not** bundled — the suite degrades
gracefully and reports it offline. See the bottom of this doc to include it.

---

## 1. Website + API on Render (primary shareable URL)

Render builds the `Dockerfile` and injects `$PORT`, which the container already
honours. `render.yaml` describes the whole service, so it's a Blueprint deploy —
no manual field-filling.

1. Make sure the repo is pushed to GitHub (it is: `kakarot6911/jmd-ai-security-suite`).
2. Go to **https://dashboard.render.com → New → Blueprint**.
3. Connect GitHub and pick the `jmd-ai-security-suite` repo.
4. Render reads `render.yaml`, builds the image, and hands you a public URL like
   `https://jmd-security-suite.onrender.com`.
   - Website: `/`
   - Interactive API docs: `/docs`
   - Health: `/health`  ·  Version/metadata: `/version`
5. **The public demo ships with auth OFF** so the built-in website works for anyone who
   opens the link — rate limiting, security headers and body caps are still active.

   ```bash
   curl -X POST https://<your-app>.onrender.com/linkguard/analyze \
     -H "Content-Type: application/json" \
     -d '{"url":"https://jmdcaremaker.com/login"}'
   ```

6. **To lock the API down**, uncomment the `JMD_API_KEY` block in `render.yaml` (Render
   mints a random key) or add `JMD_API_KEY` yourself in the service's **Environment** tab.
   The analysis endpoints then require the key; metadata routes (`/health`, `/version`,
   `/tools`) and the static site stay open:

   ```bash
   curl -X POST https://<your-app>.onrender.com/linkguard/analyze \
     -H "Content-Type: application/json" \
     -H "X-API-Key: <your-key>" \
     -d '{"url":"https://jmdcaremaker.com/login"}'
   ```

   To keep the shipped website working with auth on, inject the key into the page via a
   `<meta name="jmd-api-key" content="…">` tag (the frontend reads it automatically).

> **Free-tier note:** Render free web services sleep after ~15 min idle; the
> first request after sleeping takes ~30–50 s to wake. Fine for a demo link.

### Any other Docker/Procfile host (Railway, Fly.io, Koyeb…)
The image is host-agnostic. `Procfile` covers buildpack hosts; the `Dockerfile`
covers container hosts. Set the same `JMD_*` env vars to enable auth/limits.

---

## 2. Console on Streamlit Community Cloud

1. Go to **https://share.streamlit.io → Create app → From existing repo**.
2. Repo `kakarot6911/jmd-ai-security-suite`, branch `main`,
   **Main file path** `console/app.py`.
3. Deploy. Streamlit installs `requirements.txt` and applies `.streamlit/config.toml`
   (the dark premium theme) automatically.

> **Python version:** this repo is verified on Python 3.14. Streamlit Cloud pins
> its own interpreter — if a build fails on a pinned dependency, add a
> `runtime.txt` with a supported version (e.g. `python-3.13`) and loosen the
> exact pins in `requirements.txt` to `>=`. The Render/Docker path above is not
> affected (it uses the `python:3.14-slim` base image).

---

## 3. Local one-liners (no host needed)

```bash
./run.sh web       # website + API  → http://localhost:8000  (/docs for Swagger)
./run.sh console   # premium Streamlit console → http://localhost:8501
./run.sh docker    # build the image and run it on :8000 (needs Docker installed)
```

To enable auth locally, export a key before launching:

```bash
JMD_API_KEY=my-local-key ./run.sh web
```

---

## Environment variables (all optional)

| Var | Default | Effect |
|-----|---------|--------|
| `JMD_API_KEY` | *(unset)* | Comma-separated keys. **Unset ⇒ auth disabled.** Set ⇒ analysis endpoints require `X-API-Key`. |
| `JMD_RATE_LIMIT` | `60` | Max requests per window per caller (keyed by API key, else IP). |
| `JMD_RATE_WINDOW` | `60` | Rate-limit window, seconds. |
| `JMD_CORS_ORIGINS` | `*` | Comma-separated allowed origins. |
| `JMD_MAX_BODY_BYTES` | `65536` | Reject request bodies larger than this (413). |
| `JMD_SCAN_ALLOWLIST` | *(unset)* | Comma-separated domains SiteGuard may **live-scan**. Unset ⇒ live scanning is disabled via the API (demo mode still works). Internal, loopback and cloud-metadata addresses are refused even when allowlisted. |
| `PORT` | `8000` | Injected by the host; the container binds to it. |
| `PHISHGUARD_ROOT` | `~/jmd_phishguard` | Path to the PhishGuard repo (see below). |

## Including PhishGuard (optional)

PhishGuard is a separate repo. To light it up in a container, mount it and point
`PHISHGUARD_ROOT` at the mount:

```bash
docker run -p 8000:8000 \
  -e PHISHGUARD_ROOT=/phishguard \
  -v ~/jmd_phishguard:/phishguard \
  jmd-security-suite
```

Without it, `/health` reports `phishguard: false` and its endpoint returns 503 —
every other tool works normally.
