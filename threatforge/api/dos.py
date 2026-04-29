"""
threatforge/api/dos.py
DoS simulation endpoints with corrected target whitelist
"""
import asyncio
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional

from threatforge.core.dos_simulation.http_flood import http_get_flood, http_post_flood
from threatforge.core.dos_simulation.syn_flood import syn_flood, simulate_syn_flood_impact
from threatforge.core.dos_simulation.slowloris import run_slowloris
from threatforge.core.dos_simulation.credential_stuff import CredentialStuffer
from threatforge.core.traffic_patterns.normal_baseline import generate_normal_traffic
from threatforge.core.traffic_patterns.flood_emulator import generate_attack_pattern

router = APIRouter(prefix="/api/dos", tags=["DoS Simulation"])

# Allowed HTTP URL targets
ALLOWED_URL_TARGETS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://172.25.0.10",   # DVWA
    "http://172.25.0.11",   # WebGoat
    "http://172.25.0.12",   # nginx
    "http://172.25.0.13",   # Python HTTP server
    "http://172.28.64.1:8000",  # Vigil on Windows
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]

# Allowed IP targets (for SYN flood, slowloris)
ALLOWED_IP_TARGETS = [
    "127.0.0.1",
    "172.25.0.10",
    "172.25.0.11",
    "172.25.0.12",
    "172.25.0.13",
    "172.28.64.1",
]

def validate_url(url: str) -> bool:
    return any(url.startswith(t) for t in ALLOWED_URL_TARGETS)

def validate_ip(ip: str) -> bool:
    return ip in ALLOWED_IP_TARGETS


class HTTPFloodRequest(BaseModel):
    target_url: str = Field(..., example="http://172.25.0.13")
    requests_per_second: int = Field(50, ge=1, le=500)
    duration_seconds: int = Field(20, ge=5, le=120)


class SYNFloodRequest(BaseModel):
    target_ip: str = Field(..., example="172.25.0.13")
    target_port: int = Field(80, ge=1, le=65535)
    duration_seconds: int = Field(15, ge=5, le=60)
    packets_per_second: int = Field(100, ge=1, le=1000)


class SlowlorisRequest(BaseModel):
    target_host: str = Field(..., example="172.25.0.13")
    target_port: int = Field(80, ge=1, le=65535)
    max_connections: int = Field(50, ge=1, le=200)
    duration_seconds: int = Field(30, ge=10, le=60)


class CredentialStuffRequest(BaseModel):
    target_url: str = Field(..., example="http://172.28.64.1:8000")
    login_path: str = Field("/v1/analyze", example="/v1/analyze")
    attempts_per_second: int = Field(5, ge=1, le=20)
    duration_seconds: int = Field(30, ge=10, le=60)


class BaselineRequest(BaseModel):
    target_url: str = Field(..., example="http://172.25.0.13")
    duration_seconds: int = Field(30, ge=10, le=300)
    avg_requests_per_minute: int = Field(10, ge=1, le=60)


@router.get("/status")
async def dos_module_status():
    try:
        from scapy.all import IP
        scapy_ok = True
    except ImportError:
        scapy_ok = False

    return {
        "module": "dos_simulation",
        "status": "operational",
        "allowed_targets": ALLOWED_URL_TARGETS,
        "capabilities": {
            "http_flood": True,
            "syn_flood": scapy_ok,
            "slowloris": True,
            "credential_stuffing": True,
            "baseline_generation": True
        }
    }


@router.post("/http-flood")
async def run_http_flood(request: HTTPFloodRequest):
    if not validate_url(request.target_url):
        raise HTTPException(
            status_code=403,
            detail=f"Target {request.target_url} not in whitelist. Allowed: {ALLOWED_URL_TARGETS}"
        )
    result = await http_get_flood(
        target_url=request.target_url,
        requests_per_second=request.requests_per_second,
        duration_seconds=request.duration_seconds
    )
    return result


@router.post("/http-post-flood")
async def run_http_post_flood(request: HTTPFloodRequest):
    if not validate_url(request.target_url):
        raise HTTPException(status_code=403, detail="Target not in whitelist")
    result = await http_post_flood(
        target_url=request.target_url,
        requests_per_second=min(request.requests_per_second, 200),
        duration_seconds=request.duration_seconds
    )
    return result


@router.post("/syn-flood")
async def run_syn_flood(request: SYNFloodRequest):
    if not validate_ip(request.target_ip):
        raise HTTPException(status_code=403, detail=f"IP {request.target_ip} not in whitelist")
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
    if not validate_ip(request.target_host):
        raise HTTPException(status_code=403, detail=f"Host {request.target_host} not in whitelist")
    result = await run_slowloris(
        target_host=request.target_host,
        target_port=request.target_port,
        max_connections=request.max_connections,
        duration_seconds=request.duration_seconds
    )
    return result


@router.post("/credential-stuff")
async def run_credential_stuffing(request: CredentialStuffRequest):
    if not validate_url(request.target_url):
        raise HTTPException(status_code=403, detail="Target not in whitelist")
    stuffer = CredentialStuffer(request.target_url, request.login_path)
    result = await stuffer.run(
        attempts_per_second=request.attempts_per_second,
        duration_seconds=request.duration_seconds
    )
    return result


@router.post("/baseline")
async def generate_baseline_traffic(request: BaselineRequest):
    if not validate_url(request.target_url):
        raise HTTPException(status_code=403, detail="Target not in whitelist")
    result = await generate_normal_traffic(
        base_url=request.target_url,
        duration_seconds=request.duration_seconds,
        avg_requests_per_minute=request.avg_requests_per_minute
    )
    return result
