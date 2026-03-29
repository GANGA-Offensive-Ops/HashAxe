# ==========================================================================================
# 🔥💀 HASHAXE — Multi-Format Password Cracker 💀🔥
# ==========================================================================================
#
# 💣💣 FILE DESCRIPTION: hashaxe/api.py
#  Headless FastAPI REST Server for C2 integration and remote cracking.
#  Allows hash submission, progress polling, and password retrieval via HTTP JSON.
#
# 🔗 ARCHITECTS:
#   - Bhanu Guragain (Shadow@Bh4nu) | Lead Developer  🏴 GANGA Offensive Ops 🔥
#   - Team Members:
#       • Shrijesh Pokharel
#       • Aashish Panthi
#
# ⚠️ WARNING:
#   ACCESS RESTRICTED. Authorized use only — pentesting, CTF, security research.
#   Unauthorized access to protected systems is illegal.
# ==========================================================================================
# ⚠️ Version 1.0.0 — Production Release 💀
# ==========================================================================================
"""
hashaxe.api — Headless FastAPI REST Server (C2 Integration).

Allows Hashaxe to run as a background service on dedicated cracking rigs.
Integrating tools (Sliver, Cobalt Strike, CI/CD) can submit hashes,
poll for progress, and retrieve cracked passwords autonomously via HTTP JSON.

Usage (Run local API server):
  uvicorn hashaxe.api:app --host 127.0.0.1 --port 8080
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import BackgroundTasks, FastAPI, HTTPException
from pydantic import BaseModel

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Hashaxe REST API",
    description="Headless C2 Integration for Autonomous OffSec",
    version="1.0.0",
)

# Ephemeral in-memory job registry (non-persistent)
_JOBS: dict[str, dict[str, Any]] = {}
_RESULTS: dict[str, str | None] = {}


class CrackRequest(BaseModel):
    target: str
    target_type: str = "hash"  # "hash", "ssh_key", "zip"
    hash_algorithm: str = "auto"
    attack_mode: str = "auto_pwn"  # "wordlist", "osint", "ai", "auto_pwn"
    wordlist: str = ""
    threads: int = 0
    osint_target: str | None = None
    max_duration_sec: int = 3600


class JobStatusResponse(BaseModel):
    job_id: str
    status: str
    progress_percent: float
    hash_rate: float
    found: bool
    password: str | None


@app.get("/")
def read_root():
    return {"status": "Hashaxe API active v1.0.0", "docs": "/docs"}


def _background_cracker_task(job_id: str, req: CrackRequest):
    """Execute the core cracker engine in the background."""
    from hashaxe.cracker import hashaxe

    try:
        _JOBS[job_id]["status"] = "running"
        _JOBS[job_id]["progress"] = 0.0

        key_path = req.target if req.target_type != "hash" else None
        raw_hash = req.target if req.target_type == "hash" else None

        # Execute the attack synchronously in this background worker thread
        passphrase = hashaxe(
            key_path=key_path,
            raw_hash=raw_hash,
            wordlist=req.wordlist,
            threads=req.threads,
            attack_mode_override=req.attack_mode,
            quiet=True,  # Suppress stdout/TUI for headless operation
            use_tui=False,
        )

        _JOBS[job_id]["progress"] = 100.0

        if passphrase is not None:
            _JOBS[job_id]["status"] = "completed"
            _JOBS[job_id]["found"] = True
            _RESULTS[job_id] = passphrase
        else:
            _JOBS[job_id]["status"] = "exhausted"
            _JOBS[job_id]["found"] = False
            _RESULTS[job_id] = None

    except Exception as e:
        logger.error(f"Background cracker task failed: {e}", exc_info=True)
        if job_id in _JOBS:
            _JOBS[job_id]["status"] = f"failed: {e}"


@app.post("/jobs", response_model=dict, status_code=202)
def submit_job(req: CrackRequest, background_tasks: BackgroundTasks):
    """Submit a new cracking job."""
    import uuid

    job_id = str(uuid.uuid4())

    _JOBS[job_id] = {
        "status": "queued",
        "progress": 0.0,
        "hash_rate": 0.0,
        "found": False,
        "request": req.model_dump(),
    }

    background_tasks.add_task(_background_cracker_task, job_id, req)
    return {"job_id": job_id, "status": "queued"}


@app.get("/jobs/{job_id}", response_model=JobStatusResponse)
def get_job_status(job_id: str):
    """Poll job status and cracked results."""
    if job_id not in _JOBS:
        raise HTTPException(status_code=404, detail="Job not found")

    job = _JOBS[job_id]
    return JobStatusResponse(
        job_id=job_id,
        status=job["status"],
        progress_percent=job.get("progress", 0.0),
        hash_rate=job.get("hash_rate", 0.0),
        found=job.get("found", False),
        password=_RESULTS.get(job_id),
    )


@app.delete("/jobs/{job_id}")
def cancel_job(job_id: str):
    """Cancel a running job."""
    if job_id in _JOBS:
        _JOBS[job_id]["status"] = "cancelled"
        return {"status": "cancelled"}
    raise HTTPException(status_code=404, detail="Job not found")
