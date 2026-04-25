"""
threatforge/core/recon/syn_scanner.py

TCP SYN Port Scanner - The Foundation of Network Reconnaissance

SYLLABUS: Unit 7 - Demonstrate nmap and various options
COVERAGE: CO3, CO4

THEORY:
TCP SYN scan (also called "half-open scan") is the most popular
and stealthy port scanning technique. It works by:

1. Sending a TCP SYN packet to target port
2. If port is OPEN:    target replies with SYN-ACK
   If port is CLOSED:  target replies with RST
   If port is FILTERED: no reply (firewall dropped it)
3. We send RST to close connection before it completes
   (Hence "half-open" - never completes TCP handshake)

WHY SYN SCAN IS STEALTHY:
- Many older IDS systems only log COMPLETED connections
- Since SYN scan never completes the handshake, old IDS misses it
- Modern IDS (like Snort) detects it by rate analysis

COMPARISON WITH NMAP:
nmap -sS target = TCP SYN scan (what we implement)
nmap -sT target = TCP connect scan (completes full handshake)
nmap -sU target = UDP scan (what udp_scanner.py implements)

REQUIRES: Root/sudo privileges for raw socket access
"""

import time
import socket
from typing import List, Dict, Any, Optional

# Scapy for raw packet crafting
try:
    from scapy.all import IP, TCP, sr1, send, conf
    # Suppress Scapy warnings in output
    conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# Common ports with their service names
# Used for reporting and academic demo
COMMON_PORTS: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    194: "IRC",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    515: "LPD",
    587: "SMTP Submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    2375: "Docker",
    2376: "Docker TLS",
    3000: "Node/React Dev",
    3306: "MySQL",
    3389: "RDP",
    5000: "Flask Dev",
    5432: "PostgreSQL",
    5900: "VNC",
    5984: "CouchDB",
    6379: "Redis",
    7001: "WebLogic",
    8000: "HTTP Alt",
    8080: "HTTP Proxy",
    8081: "HTTP Alt 2",
    8443: "HTTPS Alt",
    8888: "Jupyter",
    9000: "ThreatForge",
    9090: "Prometheus",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

# Port groups for organized scanning
PORT_GROUPS: Dict[str, List[int]] = {
    "top_20": [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
               3389, 8080, 8443, 3306, 5432, 6379, 27017, 3000, 5000, 9000],
    "top_100": list(COMMON_PORTS.keys()),
    "web": [80, 443, 8080, 8443, 8000, 8001, 8888, 3000, 5000, 9000],
    "database": [1433, 1521, 3306, 5432, 5984, 6379, 9200, 27017],
    "remote_access": [22, 23, 3389, 5900],
    "mail": [25, 110, 143, 465, 587, 993, 995],
}


def check_port_tcp_connect(host: str, port: int, timeout: float = 1.0) -> str:
    """
    Check port using TCP connect (no raw socket needed, works without root).

    This is the FALLBACK method when Scapy is not available or
    when we don't have root privileges.

    HOW IT WORKS:
    Python's socket library performs a full TCP connection.
    If connection succeeds → port is OPEN
    If connection refused → port is CLOSED
    If timeout → port is FILTERED

    DIFFERENCE FROM SYN SCAN:
    Connect scan completes the full handshake (more detectable).
    SYN scan only sends SYN (stealthier, needs root).

    Args:
        host: Target IP or hostname
        port: Port number to check
        timeout: Seconds to wait for response

    Returns:
        "open", "closed", or "filtered"
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()

        if result == 0:
            return "open"
        else:
            return "closed"
    except socket.timeout:
        return "filtered"
    except socket.error:
        return "closed"


def check_port_syn(host: str, port: int, timeout: float = 1.0) -> str:
    """
    Check port using TCP SYN scan (requires root + Scapy).

    HOW IT WORKS:
    1. Craft raw TCP SYN packet (no OS involvement)
    2. Send it directly to target
    3. Wait for response:
       SYN-ACK flags (0x12) → port OPEN
       RST-ACK flags (0x14) → port CLOSED
       No response         → port FILTERED
    4. If open: send RST to close cleanly

    PACKET ANATOMY:
    IP layer:  src=our_ip, dst=target_ip
    TCP layer: dport=target_port, flags="S" (SYN=0x02)

    Args:
        host: Target IP address
        port: Port number to check
        timeout: Seconds to wait for SYN-ACK

    Returns:
        "open", "closed", or "filtered"
    """
    if not SCAPY_AVAILABLE:
        # Fall back to connect scan
        return check_port_tcp_connect(host, port, timeout)

    try:
        # Build the SYN packet
        ip_layer = IP(dst=host)
        tcp_layer = TCP(dport=port, flags="S")  # S = SYN flag
        syn_packet = ip_layer / tcp_layer

        # Send and wait for response
        # sr1 = send one packet, receive one response
        response = sr1(syn_packet, timeout=timeout, verbose=0)

        if response is None:
            # No response = filtered (firewall dropped packet)
            return "filtered"

        if response.haslayer(TCP):
            tcp_flags = response[TCP].flags

            # SYN-ACK = 0x12 = 18 in decimal
            # This means port is OPEN and listening
            if tcp_flags == 0x12:
                # Send RST to close connection cleanly
                # Without this, the target keeps the half-open connection
                rst_packet = IP(dst=host) / TCP(
                    dport=port,
                    flags="R",        # R = RST flag
                    seq=response[TCP].ack
                )
                send(rst_packet, verbose=0)
                return "open"

            # RST-ACK = 0x14 = 20 in decimal
            # This means port is CLOSED (nothing listening)
            elif tcp_flags & 0x04:  # RST flag set
                return "closed"

        return "filtered"

    except Exception:
        # If anything goes wrong (permissions, network error), use fallback
        return check_port_tcp_connect(host, port, timeout)


def scan_ports(
    host: str,
    ports: List[int],
    timing: str = "normal",
    method: str = "auto"
) -> Dict[str, Any]:
    """
    Scan a list of ports on a target host.

    TIMING MODES:
    - "fast":   0.0s delay between ports (aggressive, loud)
    - "normal": 0.1s delay (balanced)
    - "slow":   0.5s delay (stealthy, evades rate-based IDS)
    - "paranoid": 2.0s delay (very stealthy, very slow)

    METHOD SELECTION:
    - "syn":  TCP SYN scan (requires root, stealthier)
    - "connect": TCP connect scan (no root needed, louder)
    - "auto": Try SYN first, fall back to connect

    Args:
        host: Target IP or hostname
        ports: List of port numbers to scan
        timing: Timing mode (see above)
        method: Scan method (see above)

    Returns:
        Complete scan results with per-port status and metadata
    """
    # Timing delays in seconds
    timing_delays = {
        "fast": 0.0,
        "normal": 0.1,
        "slow": 0.5,
        "paranoid": 2.0
    }
    delay = timing_delays.get(timing, 0.1)

    # Choose scan function
    if method == "syn" and SCAPY_AVAILABLE:
        scan_func = check_port_syn
    elif method == "connect":
        scan_func = check_port_tcp_connect
    else:
        # Auto: use SYN if available, connect as fallback
        scan_func = check_port_syn if SCAPY_AVAILABLE else check_port_tcp_connect

    start_time = time.perf_counter()
    results = {
        "open": [],
        "closed": [],
        "filtered": [],
        "details": []
    }

    total_ports = len(ports)

    for i, port in enumerate(ports):
        port_start = time.perf_counter()
        status = scan_func(host, port, timeout=1.0)
        port_time = time.perf_counter() - port_start

        # Record result
        results[status].append(port)
        results["details"].append({
            "port": port,
            "status": status,
            "service": COMMON_PORTS.get(port, "unknown"),
            "response_time_ms": round(port_time * 1000, 2)
        })

        # Apply timing delay (only between ports, not after last)
        if i < total_ports - 1 and delay > 0:
            time.sleep(delay)

    scan_duration = time.perf_counter() - start_time

    return {
        "target": host,
        "scan_method": "syn" if SCAPY_AVAILABLE and method != "connect" else "connect",
        "timing_mode": timing,
        "ports_scanned": total_ports,
        "open_ports": results["open"],
        "closed_ports": len(results["closed"]),
        "filtered_ports": len(results["filtered"]),
        "port_details": results["details"],
        "scan_duration_seconds": round(scan_duration, 2),
        "scan_rate_pps": round(total_ports / scan_duration, 2) if scan_duration > 0 else 0,
        "timestamp": time.time()
    }


def discover_hosts(
    subnet: str,
    timeout: float = 1.0
) -> List[str]:
    """
    Discover active hosts on a subnet using ICMP ping.

    ALGORITHM:
    Send ICMP echo request (ping) to each IP in subnet.
    If we get ICMP echo reply → host is up.

    This is equivalent to: nmap -sn 192.168.1.0/24

    Args:
        subnet: Network in CIDR notation (e.g., "172.25.0.0/24")
        timeout: Seconds to wait per host

    Returns:
        List of active IP addresses
    """
    import ipaddress

    active_hosts = []
    network = ipaddress.ip_network(subnet, strict=False)

    for host_ip in network.hosts():
        ip_str = str(host_ip)
        # Quick TCP check on port 80 or 22 to detect hosts
        # (ICMP ping often blocked by firewalls)
        if (check_port_tcp_connect(ip_str, 80, timeout=0.3) == "open" or
                check_port_tcp_connect(ip_str, 22, timeout=0.3) == "open" or
                check_port_tcp_connect(ip_str, 8080, timeout=0.3) == "open"):
            active_hosts.append(ip_str)

    return active_hosts


def quick_scan(host: str) -> Dict[str, Any]:
    """
    Quick scan of top 20 common ports.

    Used for rapid assessment during demo.
    Equivalent to: nmap --top-ports 20 target

    Args:
        host: Target IP address

    Returns:
        Scan results for top 20 ports
    """
    return scan_ports(host, PORT_GROUPS["top_20"], timing="normal")


def comprehensive_scan(host: str) -> Dict[str, Any]:
    """
    Comprehensive scan of all common ports.

    Used for thorough assessment.
    Equivalent to: nmap -sV --top-ports 100 target

    Args:
        host: Target IP address

    Returns:
        Scan results for top 100 ports
    """
    return scan_ports(host, PORT_GROUPS["top_100"], timing="slow")
