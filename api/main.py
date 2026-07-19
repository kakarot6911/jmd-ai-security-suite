"""
JMD Security Suite — unified REST API for all four tools.

Run:  uvicorn api.main:app --reload --port 8000
Docs: http://localhost:8000/docs
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from console import integrations as ig  # noqa: E402
from api import security as sec  # noqa: E402

VERSION = "1.1.0"

app = FastAPI(
    title="JMD Security Suite API",
    version=VERSION,
    description="Unified endpoint for PhishGuard, ResumeShield, SiteGuard, LinkGuard and BreachRadar.",
)
WEB_DIR = ROOT / "web"

# Analysis endpoints that require an API key (when JMD_API_KEY is set) and are
# rate-limited. GET metadata routes (/health, /version, /tools) and the static
# site stay open.
PROTECTED_PREFIXES = (
    "/phishguard", "/resumeshield", "/siteguard", "/linkguard", "/breachradar",
)
_limiter = sec.rate_limiter_from_env()

app.add_middleware(
    CORSMiddleware,
    allow_origins=sec.cors_origins(),
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key"],
)


@app.middleware("http")
async def harden(request: Request, call_next):
    """Body-size cap → API-key auth → rate limit → security headers."""
    path = request.url.path

    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > sec.max_body_bytes():
        return JSONResponse({"detail": "request body too large"}, status_code=413)

    if path.startswith(PROTECTED_PREFIXES):
        api_key = request.headers.get("x-api-key")
        if sec.auth_enabled() and not sec.key_is_valid(api_key, sec.configured_api_keys()):
            return JSONResponse(
                {"detail": "invalid or missing API key"},
                status_code=401,
                headers={"WWW-Authenticate": "API-Key"},
            )
        client_ip = request.client.host if request.client else None
        ok, retry_after = _limiter.allow(sec.client_id_for(client_ip, api_key))
        if not ok:
            return JSONResponse(
                {"detail": "rate limit exceeded"},
                status_code=429,
                headers={"Retry-After": str(int(retry_after) + 1)},
            )

    response = await call_next(request)
    for name, value in sec.SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    return response


# ---- Schemas --------------------------------------------------------------
class PhishIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=20_000, description="Recruitment email / job-offer body.")
    sender_email: str = Field("", max_length=320)
    claimed_company: str = Field("", max_length=200)


class ResumeIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=100_000)
    keep_last: int = Field(0, ge=0, le=4)


class SiteIn(BaseModel):
    url: str = Field("", max_length=2_048)
    authorized: bool = False
    demo: Optional[str] = Field(None, description="hardened | vulnerable (offline)")


class LinkIn(BaseModel):
    url: str = Field(..., min_length=1, max_length=2_048, description="The link to analyse (scheme optional).")


class EmailIn(BaseModel):
    email: str = Field(..., min_length=3, max_length=320)


# ---- Routes ---------------------------------------------------------------
@app.get("/health")
def health():
    return {"status": "ok", "modules": {t["key"]: t["available"] for t in ig.TOOLS}}


@app.get("/version")
def version():
    return {
        "name": "JMD Security Suite API",
        "version": VERSION,
        "auth_required": sec.auth_enabled(),
        "tools": [t["key"] for t in ig.TOOLS],
    }


@app.get("/tools")
def tools():
    return ig.TOOLS


@app.post("/phishguard/analyze")
def phishguard(inp: PhishIn):
    try:
        return ig.phishguard_analyze(inp.text, inp.sender_email, inp.claimed_company)
    except RuntimeError as e:
        raise HTTPException(503, str(e))


@app.post("/resumeshield/redact")
def resumeshield(inp: ResumeIn):
    return ig.resumeshield_redact(inp.text, keep_last=inp.keep_last)


@app.post("/siteguard/scan")
def siteguard(inp: SiteIn):
    if inp.demo and inp.demo not in ig.SITEGUARD_DEMOS:
        raise HTTPException(400, f"demo must be one of {list(ig.SITEGUARD_DEMOS)}")
    try:
        return ig.siteguard_scan(inp.url, authorized=inp.authorized, demo=inp.demo)
    except PermissionError as e:
        raise HTTPException(403, str(e))


@app.post("/linkguard/analyze")
def linkguard(inp: LinkIn):
    return ig.linkguard_analyze(inp.url)


@app.post("/breachradar/check")
def breachradar_check(inp: EmailIn):
    return ig.breachradar_check(inp.email)


@app.get("/breachradar/scan-org")
def breachradar_org():
    return ig.breachradar_scan_org()


# ---- Static web frontend (mounted LAST so API routes take precedence) -----
if WEB_DIR.exists():
    app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="web")
