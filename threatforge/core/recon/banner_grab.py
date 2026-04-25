"""
threatforge/core/recon/banner_grab.py

Banner Grabbing - Service Version Detection

SYLLABUS: Unit 8 - Network Reconnaissance Tools
COVERAGE: CO3

THEORY:
When you connect to a network service, many servers immediately send
a "banner" - a text string identifying the software and version.

This information is gold for attackers:
- Identifies exact software version
- Allows searching for known CVEs (Common Vulnerabilities and Exposures)
- Reveals OS information

EXAMPLE ATTACK CHAIN FROM BANNER:
1. Banner: "SSH-2.0-OpenSSH_7.4"
2. Search: CVE-2018-15473 (OpenSSH 7.4 username enumeration)
3. Exploit: Enumerate valid usernames without authentication
4. Result: Know which accounts exist, then attempt credential attacks

EQUIVALENT NMAP COMMAND: nmap -sV target (service version detection)
"""

import socket
import time
import re
from typing import Dict, Any, List, Optional


# Protocol-specific greeting messages
# Some services need you to send something before they respond
PROTOCOL_GREETINGS: Dict[int, bytes] = {
    80:  b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n",
    443: b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n",
    8080: b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n",
    8443: b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n",
    21:  b"",        # FTP sends banner immediately
    22:  b"",        # SSH sends banner immediately
    25:  b"EHLO threatforge.local\r\n",
    110: b"",        # POP3 sends banner immediately
    143: b"",        # IMAP sends banner immediately
    3306: b"",       # MySQL sends banner immediately
}

# Patterns for identifying services from banners
# These regex patterns extract service name and version
SERVICE_PATTERNS: List[Dict[str, Any]] = [
    {
        "name": "OpenSSH",
        "pattern": r"SSH-\d+\.\d+-OpenSSH_([\d.]+)",
        "risk": "Check for CVE-2018-15473 (versions < 7.7)"
    },
    {
        "name": "Apache HTTP",
        "pattern": r"Apache/([\d.]+)",
        "risk": "Check Apache CVE database for version"
    },
    {
        "name": "nginx",
        "pattern": r"nginx/([\d.]+)",
        "risk": "Check nginx CVE database for version"
    },
    {
        "name": "OpenSSL",
        "pattern": r"OpenSSL ([\d.]+[a-z]*)",
        "risk": "Heartbleed if < 1.0.1g, check for POODLE, BEAST"
    },
    {
        "name": "MySQL",
        "pattern": r"([\d.]+)-MySQL",
        "risk": "Check for authentication bypass CVEs"
    },
    {
        "name": "ProFTPD",
        "pattern": r"ProFTPD ([\d.]+)",
        "risk": "CVE-2010-4221 if < 1.3.3c"
    },
    {
        "name": "vsftpd",
        "pattern": r"vsftpd ([\d.]+)",
        "risk": "vsftpd 2.3.4 backdoor (CVE-2011-2523)"
    },
    {
        "name": "Postfix",
        "pattern": r"ESMTP Postfix",
        "risk": "Usually safe, check version for specific CVEs"
    },
]


def grab_banner(
    host: str,
    port: int,
    timeout: float = 3.0
) -> Dict[str, Any]:
    """
    Grab service banner from a single port.

    ALGORITHM:
    1. Connect to host:port via TCP
    2. If service needs a greeting, send it
    3. Read response (the banner)
    4. Try to identify service from banner patterns
    5. Report version and known vulnerabilities

    Args:
        host: Target IP or hostname
        port: Port to grab banner from
        timeout: Connection timeout in seconds

    Returns:
        Banner information including raw data and parsed service info
    """
    start_time = time.perf_counter()

    result: Dict[str, Any] = {
        "host": host,
        "port": port,
        "banner_raw": None,
        "banner_clean": None,
        "service_identified": None,
        "version": None,
        "risk_notes": None,
        "response_time_ms": 0,
        "success": False
    }

    try:
        # Create TCP connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Send greeting if needed for this port
        greeting = PROTOCOL_GREETINGS.get(port)
        if greeting:
            sock.send(greeting)

        # Read response
        banner_bytes = b""
        try:
            while True:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                banner_bytes += chunk
                # Stop after getting reasonable banner size
                if len(banner_bytes) > 2048:
                    break
                # Short timeout for additional data
                sock.settimeout(0.5)
        except socket.timeout:
            pass  # Timeout on recv is normal - we have what we need

        sock.close()

        if banner_bytes:
            # Decode banner
            try:
                banner_clean = banner_bytes.decode('utf-8', errors='replace').strip()
            except Exception:
                banner_clean = repr(banner_bytes)

            result["banner_raw"] = banner_bytes.hex()
            result["banner_clean"] = banner_clean[:500]  # Limit length
            result["success"] = True

            # Try to identify service
            identified = _identify_service(banner_clean, port)
            if identified:
                result["service_identified"] = identified["name"]
                result["version"] = identified.get("version")
                result["risk_notes"] = identified.get("risk")

    except socket.timeout:
        result["error"] = "Connection timed out"
    except ConnectionRefusedError:
        result["error"] = "Connection refused (port closed)"
    except Exception as e:
        result["error"] = str(e)

    result["response_time_ms"] = round((time.perf_counter() - start_time) * 1000, 2)
    return result


def _identify_service(banner: str, port: int) -> Optional[Dict[str, Any]]:
    """
    Try to identify service and version from banner text.

    Args:
        banner: Raw banner text
        port: Port number (used as hint)

    Returns:
        Service identification dict or None
    """
    for pattern_info in SERVICE_PATTERNS:
        match = re.search(pattern_info["pattern"], banner, re.IGNORECASE)
        if match:
            return {
                "name": pattern_info["name"],
                "version": match.group(1) if match.lastindex else None,
                "risk": pattern_info["risk"]
            }

    # Port-based fallback identification
    port_services = {
        22: "SSH", 21: "FTP", 25: "SMTP",
        80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 3306: "MySQL", 5432: "PostgreSQL"
    }
    if port in port_services:
        return {
            "name": port_services[port],
            "version": None,
            "risk": "Version not identified from banner"
        }

    return None


def grab_multiple_banners(
    host: str,
    open_ports: List[int],
    timeout: float = 3.0
) -> Dict[str, Any]:
    """
    Grab banners from all open ports on a target.

    Typically called after port scan to get service versions.
    Equivalent to: nmap -sV (version detection)

    Args:
        host: Target IP
        open_ports: List of open ports (from port scan)
        timeout: Per-port timeout

    Returns:
        All banner information plus summary
    """
    start_time = time.perf_counter()
    banners = []
    identified_services = []
    risks_found = []

    for port in open_ports:
        banner = grab_banner(host, port, timeout)
        banners.append(banner)

        if banner.get("service_identified"):
            service_info = {
                "port": port,
                "service": banner["service_identified"],
                "version": banner.get("version", "unknown")
            }
            identified_services.append(service_info)

        if banner.get("risk_notes") and banner.get("version"):
            risks_found.append({
                "port": port,
                "service": banner.get("service_identified"),
                "version": banner.get("version"),
                "risk": banner["risk_notes"]
            })

    duration = time.perf_counter() - start_time

    return {
        "target": host,
        "ports_analyzed": len(open_ports),
        "banners_grabbed": sum(1 for b in banners if b["success"]),
        "services_identified": identified_services,
        "potential_risks": risks_found,
        "banner_details": banners,
        "duration_seconds": round(duration, 2),
        "academic_note": (
            "Banner grabbing reveals exact software versions, "
            "enabling targeted CVE lookup. This is why hiding version info "
            "in server headers is a security best practice."
        )
    }
