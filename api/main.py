"""
JMD Security Suite — unified REST API for all four tools.

Run:  uvicorn api.main:app --reload --port 8000
Docs: http://localhost:8000/docs
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from console import integrations as ig  # noqa: E402

app = FastAPI(
    title="JMD Security Suite API",
    version="1.0.0",
    description="Unified endpoint for PhishGuard, ResumeShield, SiteGuard and BreachRadar.",
)


# ---- Schemas --------------------------------------------------------------
class PhishIn(BaseModel):
    text: str = Field(..., description="Recruitment email / job-offer body.")
    sender_email: str = ""
    claimed_company: str = ""


class ResumeIn(BaseModel):
    text: str
    keep_last: int = Field(0, ge=0, le=4)


class SiteIn(BaseModel):
    url: str = ""
    authorized: bool = False
    demo: Optional[str] = Field(None, description="hardened | vulnerable (offline)")


class EmailIn(BaseModel):
    email: str


# ---- Routes ---------------------------------------------------------------
@app.get("/health")
def health():
    return {"status": "ok", "modules": {t["key"]: t["available"] for t in ig.TOOLS}}


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


@app.post("/breachradar/check")
def breachradar_check(inp: EmailIn):
    return ig.breachradar_check(inp.email)


@app.get("/breachradar/scan-org")
def breachradar_org():
    return ig.breachradar_scan_org()
