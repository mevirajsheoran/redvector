"""
threatforge/api/recon.py

FastAPI endpoints for Network Reconnaissance module.

ENDPOINTS:
POST /api/recon/scan/tcp        - TCP SYN/Connect port scan
POST /api/recon/scan/udp        - UDP port scan
POST /api/recon/banner          - Banner grabbing
POST /api/recon/os              - OS fingerprinting
POST /api/recon/stealth         - Stealth scan modes
POST /api/recon/full            - Full reconnaissance pipeline
GET  /api/recon/targets         - List allowed targets
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field, field_validator
from typing import List, Optional

from threatforge.core.recon.syn_scanner import (
    scan_ports, quick_scan, PORT_GROUPS, COMMON_PORTS
)
from threatforge.core.recon.udp_scanner import udp_scan, COMMON_UDP_PORTS
from threatforge.core.recon.banner_grab import grab_multiple_banners, grab_banner
from threatforge.core.recon.os_fingerprint import fingerprint_os
from threatforge.core.recon.stealth_modes import (
    slow_scan, randomized_port_scan,
    fragmented_syn_scan, compare_stealth_vs_normal
)

router = APIRouter(prefix="/api/recon", tags=["Reconnaissance"])

# ─────────────────────────────────────────
# WHITELISTED TARGETS ONLY
# Ethics: Only allow scanning known lab IPs
# ─────────────────────────────────────────
ALLOWED_TARGETS = [
    "127.0.0.1",
    "localhost",
    "172.25.0.10",   # DVWA
    "172.25.0.11",   # WebGoat
    "172.25.0.12",   # nginx
    "172.25.0.13",   # http_target
    "10.0.0.0/24",   # Docker networks
]

def validate_target(host: str) -> bool:
    """Ensure target is in whitelist."""
    allowed = [
        "127.0.0.1", "localhost",
        "172.25.0.10", "172.25.0.11",
        "172.25.0.12", "172.25.0.13"
    ]
    return host in allowed


# ─────────────────────────────────────────
# Request Models
# ─────────────────────────────────────────

class TCPScanRequest(BaseModel):
    host: str = Field(..., description="Target IP address", example="172.25.0.12")
    port_group: str = Field("top_20", description="Port group: top_20, top_100, web, database")
    custom_ports: Optional[List[int]] = Field(None, description="Custom port list")
    timing: str = Field("normal", description="Timing: fast, normal, slow, paranoid")
    method: str = Field("auto", description="Scan method: auto, syn, connect")


class UDPScanRequest(BaseModel):
    host: str = Field(..., example="172.25.0.12")
    ports: Optional[List[int]] = Field(None, description="Custom UDP ports (defaults to common)")


class BannerRequest(BaseModel):
    host: str = Field(..., example="172.25.0.12")
    ports: List[int] = Field(..., description="Open ports to grab banners from", example=[80, 22, 3306])


class OSFingerprintRequest(BaseModel):
    host: str = Field(..., example="172.25.0.12")
    open_port: Optional[int] = Field(None, description="Known open port for TCP analysis")


class StealthScanRequest(BaseModel):
    host: str = Field(..., example="172.25.0.12")
    mode: str = Field("slow", description="Stealth mode: slow, randomized, fragmented, compare")
    ports: Optional[List[int]] = Field(None, description="Ports to scan")
    port: Optional[int] = Field(None, description="Single port for fragmented scan")


class FullReconRequest(BaseModel):
    host: str = Field(..., description="Target IP for full reconnaissance pipeline")


# ─────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────

@router.get("/targets")
async def list_allowed_targets():
    """List all whitelisted scan targets."""
    return {
        "allowed_targets": ALLOWED_TARGETS,
        "note": "ThreatForge only scans whitelisted lab targets for ethical compliance",
        "lab_setup": "Run docker compose up -d to start targets"
    }


@router.post("/scan/tcp")
async def tcp_port_scan(request: TCPScanRequest):
    """
    Perform TCP port scan on whitelisted target.

    Demonstrates nmap -sS (SYN scan) equivalent.
    Compares results with nmap ground truth.
    """
    if not validate_target(request.host):
        raise HTTPException(
            status_code=403,
            detail=f"Target {request.host} is not in whitelist. See /api/recon/targets"
        )

    # Determine ports to scan
    if request.custom_ports:
        ports = request.custom_ports
    elif request.port_group in PORT_GROUPS:
        ports = PORT_GROUPS[request.port_group]
    else:
        ports = PORT_GROUPS["top_20"]

    result = scan_ports(
        host=request.host,
        ports=ports,
        timing=request.timing,
        method=request.method
    )

    return result


@router.post("/scan/udp")
async def udp_port_scan(request: UDPScanRequest):
    """
    Perform UDP port scan on whitelisted target.
    Demonstrates nmap -sU equivalent.
    """
    if not validate_target(request.host):
        raise HTTPException(status_code=403, detail="Target not in whitelist")

    ports = request.ports or COMMON_UDP_PORTS
    result = udp_scan(host=request.host, ports=ports)
    return result


@router.post("/banner")
async def banner_grabbing(request: BannerRequest):
    """
    Grab service banners from open ports.
    Demonstrates nmap -sV (service version detection).
    """
    if not validate_target(request.host):
        raise HTTPException(status_code=403, detail="Target not in whitelist")

    result = grab_multiple_banners(
        host=request.host,
        open_ports=request.ports
    )
    return result


@router.post("/os")
async def os_fingerprint(request: OSFingerprintRequest):
    """
    Attempt OS fingerprinting.
    Demonstrates nmap -O (OS detection).
    """
    if not validate_target(request.host):
        raise HTTPException(status_code=403, detail="Target not in whitelist")

    result = fingerprint_os(
        host=request.host,
        open_port=request.open_port
    )
    return result


@router.post("/stealth")
async def stealth_scan(request: StealthScanRequest):
    """
    Demonstrate stealth scanning techniques.
    Shows how attackers evade IDS detection.
    """
    if not validate_target(request.host):
        raise HTTPException(status_code=403, detail="Target not in whitelist")

    ports = request.ports or list(PORT_GROUPS["top_20"])

    if request.mode == "slow":
        return slow_scan(request.host, ports[:10])
    elif request.mode == "randomized":
        return randomized_port_scan(request.host, ports[:10])
    elif request.mode == "fragmented":
        port = request.port or 80
        return fragmented_syn_scan(request.host, port)
    elif request.mode == "compare":
        return compare_stealth_vs_normal(request.host, ports[:10])
    else:
        raise HTTPException(status_code=400, detail="Mode must be: slow, randomized, fragmented, compare")


@router.post("/full")
async def full_recon_pipeline(request: FullReconRequest):
    """
    Complete reconnaissance pipeline:
    1. TCP port scan (top 20 ports)
    2. UDP scan (common ports)
    3. Banner grabbing (open ports)
    4. OS fingerprinting

    This is the full workflow a real attacker uses.
    Equivalent to: nmap -sS -sU -sV -O target
    """
    if not validate_target(request.host):
        raise HTTPException(status_code=403, detail="Target not in whitelist")

    host = request.host
    pipeline_results = {}

    # Step 1: TCP Scan
    tcp_result = scan_ports(host, PORT_GROUPS["top_20"], timing="normal")
    pipeline_results["tcp_scan"] = tcp_result

    # Step 2: UDP Scan (quick)
    udp_result = udp_scan(host, COMMON_UDP_PORTS[:8])
    pipeline_results["udp_scan"] = udp_result

    # Step 3: Banner grab open ports
    open_tcp_ports = tcp_result.get("open_ports", [])
    if open_tcp_ports:
        banner_result = grab_multiple_banners(host, open_tcp_ports[:5])
        pipeline_results["banners"] = banner_result

    # Step 4: OS fingerprint
    first_open = open_tcp_ports[0] if open_tcp_ports else None
    os_result = fingerprint_os(host, open_port=first_open)
    pipeline_results["os_fingerprint"] = os_result

    # Summary
    pipeline_results["summary"] = {
        "target": host,
        "open_tcp_ports": open_tcp_ports,
        "open_udp_ports": udp_result.get("open_ports", []),
        "os_guess": os_result.get("best_guess", "Unknown"),
        "services_found": [
            b["service_identified"]
            for b in pipeline_results.get("banners", {}).get("banner_details", [])
            if b.get("service_identified")
        ],
        "attack_surface_rating": (
            "HIGH" if len(open_tcp_ports) > 5
            else "MEDIUM" if len(open_tcp_ports) > 2
            else "LOW"
        )
    }

    return pipeline_results
