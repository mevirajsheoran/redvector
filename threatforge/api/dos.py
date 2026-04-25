"""
threatforge/api/dos.py

FastAPI endpoints for DoS Simulation module.

ENDPOINTS:
POST /api/dos/http-flood         - HTTP GET flood
POST /api/dos/http-post-flood    - HTTP POST flood
POST /api/dos/syn-flood          - TCP SYN flood
POST /api/dos/slowloris          - Slowloris attack
POST /api/dos/credential-stuff   - Credential stuffing
POST /api/dos/baseline           - Generate normal baseline traffic
GET  /api/dos/status             - Module status
"""

import asyncio
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Optional

from threatforge.core.dos_simulation.http_flood import http_get_flood, http_post_flood
from threatforge.core.dos_simulation.syn_flood import syn_flood, simulate_syn_flood_impact
from threatforge.core.dos_simulation.slowloris import run_slowloris
from threatforge.core.dos_simulation.credential_stuff import CredentialStuffer
from threatforge.core.traffic_patterns.normal_baseline import generate_normal_traffic
from threatforge.core.traffic_patterns.flood_emulator import generate_attack_pattern

router = APIRouter(prefix="/api/dos", tags=["DoS Simulation"])

# Allowed targets
ALLOWED_TARGETS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://172.25.0.10",
    "http://172.25.0.11",
    "http://172.25.0.12",
    "http://172.25.0.13",
    "http://172.25.0.10:8080",
    "http://172.25.0.11:8080",
    "http://172.25.0.12:80",
    "http://172.25.0.13:8080",
    "http://localhost:8000",     # Sentinel/Vigil
    "http://127.0.0.1:8000",
]

def validate_dos_target(url: str) -> bool:
    """Only allow whitelisted targets for ethical compliance."""
    return any(url.startswith(allowed) for allowed in ALLOWED_TARGETS)


class HTTPFloodRequest(BaseModel):
    target_url: str = Field(..., example="http://172.25.0.12")
    requests_per_second: int = Field(50, ge=1, le=500)
    duration_seconds: int = Field(30, ge=5, le=120)


class SYNFloodRequest(BaseModel):
    target_ip: str = Field(..., example="172.25.0.12")
    target_port: int = Field(80, ge=1, le=65535)
    duration_seconds: int = Field(15, ge=5, le=60)
    packets_per_second: int = Field(100, ge=1, le=1000)


class SlowlorisRequest(BaseModel):
    target_host: str = Field(..., example="172.25.0.12")
    target_port: int = Field(80, ge=1, le=65535)
    max_connections: int = Field(50, ge=1, le=200)
    duration_seconds: int = Field(30, ge=10, le=60)


class CredentialStuffRequest(BaseModel):
    target_url: str = Field(..., example="http://172.25.0.10")
    login_path: str = Field("/login", example="/login")
    attempts_per_second: int = Field(5, ge=1, le=20)
    duration_seconds: int = Field(30, ge=10, le=60)


class BaselineRequest(BaseModel):
    target_url: str = Field(..., example="http://172.25.0.12")
    duration_seconds: int = Field(60, ge=10, le=300)
    avg_requests_per_minute: int = Field(10, ge=1, le=60)


@router.get("/status")
async def dos_module_status():
    """Check DoS module capabilities."""
    try:
        from scapy.all import IP
        scapy_ok = True
    except ImportError:
        scapy_ok = False

    return {
        "module": "dos_simulation",
        "status": "operational",
        "capabilities": {
            "http_flood": True,
            "syn_flood": scapy_ok,
            "slowloris": True,
            "credential_stuffing": True,
            "baseline_generation": True
        },
        "note": "SYN flood requires Scapy + root privileges" if not scapy_ok else "All features available"
    }


@router.post("/http-flood")
async def run_http_flood(request: HTTPFloodRequest):
    """
    Execute HTTP GET flood against whitelisted target.
    Demonstrates application-layer DoS attack pattern.
    """
    if not validate_dos_target(request.target_url):
        raise HTTPException(
            status_code=403,
            detail=f"Target {request.target_url} not in whitelist"
        )

    result = await http_get_flood(
        target_url=request.target_url,
        requests_per_second=request.requests_per_second,
        duration_seconds=request.duration_seconds
    )
    return result


@router.post("/http-post-flood")
async def run_http_post_flood(request: HTTPFloodRequest):
    """Execute HTTP POST flood."""
    if not validate_dos_target(request.target_url):
        raise HTTPException(status_code=403, detail="Target not in whitelist")

    result = await http_post_flood(
        target_url=request.target_url,
        requests_per_second=min(request.requests_per_second, 200),
        duration_seconds=request.duration_seconds
    )
    return result


@router.post("/syn-flood")
async def run_syn_flood(request: SYNFloodRequest):
    """
    Execute TCP SYN flood.
    Requires Scapy and root privileges.
    Falls back to impact assessment if unavailable.
    """
    allowed_ips = ["172.25.0.10", "172.25.0.11", "172.25.0.12",
                   "172.25.0.13", "127.0.0.1"]
    if request.target_ip not in allowed_ips:
        raise HTTPException(status_code=403, detail="Target IP not in whitelist")

    try:
        from scapy.all import IP
        result = syn_flood(
            target_ip=request.target_ip,
            target_port=request.target_port,
            duration_seconds=request.duration_seconds,
            packets_per_second=request.packets_per_second
        )
    except ImportError:
        result = simulate_syn_flood_impact(request.target_ip, request.target_port)

    return result


@router.post("/slowloris")
async def run_slowloris_attack(request: SlowlorisRequest):
    """Execute Slowloris connection exhaustion attack."""
    allowed_ips = ["172.25.0.10", "172.25.0.11", "172.25.0.12",
                   "172.25.0.13", "127.0.0.1"]
    if request.target_host not in allowed_ips:
        raise HTTPException(status_code=403, detail="Target not in whitelist")

    result = await run_slowloris(
        target_host=request.target_host,
        target_port=request.target_port,
        max_connections=request.max_connections,
        duration_seconds=request.duration_seconds
    )
    return result


@router.post("/credential-stuff")
async def run_credential_stuffing(request: CredentialStuffRequest):
    """Execute credential stuffing simulation."""
    if not validate_dos_target(request.target_url):
        raise HTTPException(status_code=403, detail="Target not in whitelist")

    stuffer = CredentialStuffer(request.target_url, request.login_path)
    result = await stuffer.run(
        attempts_per_second=request.attempts_per_second,
        duration_seconds=request.duration_seconds
    )
    return result


@router.post("/baseline")
async def generate_baseline_traffic(request: BaselineRequest):
    """
    Generate normal baseline traffic for IDS comparison.
    Run this BEFORE attack tests to establish normal behavior.
    """
    if not validate_dos_target(request.target_url):
        raise HTTPException(status_code=403, detail="Target not in whitelist")

    result = await generate_normal_traffic(
        base_url=request.target_url,
        duration_seconds=request.duration_seconds,
        avg_requests_per_minute=request.avg_requests_per_minute
    )
    return result


@router.post("/compare-patterns")
async def compare_traffic_patterns(
    target_url: str = "http://172.25.0.12"
):
    """
    Run both normal and attack traffic, compare results.
    Academic demonstration of why IDS needs baseline comparison.
    """
    if not validate_dos_target(target_url):
        raise HTTPException(status_code=403, detail="Target not in whitelist")

    # 30 second baseline
    baseline = await generate_normal_traffic(target_url, 30, 10)

    # 30 second attack
    attack = await generate_attack_pattern(target_url, "http_flood", 30)

    return {
        "comparison": {
            "baseline": {
                "rpm": baseline["average_rpm"],
                "pattern": "human_like",
                "ids_should_flag": False
            },
            "attack": {
                "rpm": attack["actual_rpm"],
                "pattern": "automated_flood",
                "ids_should_flag": True
            }
        },
        "baseline_details": baseline,
        "attack_details": attack,
        "academic_insight": (
            f"Baseline: {baseline['average_rpm']} RPM (human-like). "
            f"Attack: {attack['actual_rpm']} RPM (automated). "
            f"IDS should trigger at ~{baseline['average_rpm'] * 5:.0f} RPM threshold."
        )
    }
