"""
threatforge/core/recon/udp_scanner.py

UDP Port Scanner

SYLLABUS: Unit 7 - nmap options (nmap -sU)
COVERAGE: CO3

THEORY:
UDP scanning is fundamentally different from TCP scanning because
UDP is connectionless - there is no handshake.

HOW UDP SCANNING WORKS:
1. Send an empty UDP packet to target port
2. Three possible responses:
   a) UDP response packet      → port is OPEN (service responded)
   b) ICMP "port unreachable"  → port is CLOSED (OS rejected it)
   c) No response              → port is OPEN or FILTERED (ambiguous)

CHALLENGE:
Unlike TCP, you cannot reliably distinguish between OPEN and FILTERED
for UDP because both result in no response. Modern scanners use
service-specific probes (e.g., send DNS query to port 53) to
distinguish properly.

IMPORTANT UDP SERVICES:
Port 53  = DNS (Domain Name System)
Port 67  = DHCP Server
Port 68  = DHCP Client
Port 69  = TFTP (Trivial File Transfer)
Port 123 = NTP (Network Time Protocol)
Port 161 = SNMP (Simple Network Management Protocol)
Port 514 = Syslog

WHY UDP MATTERS FOR SECURITY:
Many UDP services are poorly secured:
- SNMP default communities ("public", "private")
- NTP amplification attacks (DDoS)
- DNS amplification attacks (DDoS)
- TFTP has no authentication

EQUIVALENT NMAP COMMAND: nmap -sU target
"""

import time
import socket
from typing import List, Dict, Any

try:
    from scapy.all import IP, UDP, ICMP, sr1, conf
    conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# Service-specific probes
# When we probe a UDP port, we send a protocol-appropriate payload
# This gets better results than an empty packet
UDP_PROBES: Dict[int, bytes] = {
    53: b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        b'\x07example\x03com\x00\x00\x01\x00\x01',  # DNS query
    161: b'\x30\x26\x02\x01\x00\x04\x06public\xa0\x19'
         b'\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00'
         b'\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00',  # SNMP
    123: b'\x1b' + 47 * b'\x00',  # NTP
    69: b'\x00\x01test.txt\x00netascii\x00',  # TFTP
}

# Common UDP ports to scan
COMMON_UDP_PORTS: List[int] = [
    53, 67, 68, 69, 123, 137, 138, 161, 162,
    500, 514, 520, 1194, 1701, 1900, 4500, 5353
]


def check_udp_port(host: str, port: int, timeout: float = 2.0) -> Dict[str, Any]:
    """
    Check a single UDP port status.

    Returns more detail than TCP scanner because UDP is ambiguous.

    Args:
        host: Target IP address
        port: UDP port to check
        timeout: Seconds to wait for response

    Returns:
        Dict with status and additional information
    """
    if not SCAPY_AVAILABLE:
        return _check_udp_socket(host, port, timeout)

    try:
        # Build UDP packet with service-specific probe if available
        probe_data = UDP_PROBES.get(port, b'')

        ip_layer = IP(dst=host)
        udp_layer = UDP(dport=port)

        if probe_data:
            from scapy.all import Raw
            packet = ip_layer / udp_layer / Raw(load=probe_data)
        else:
            packet = ip_layer / udp_layer

        # Send and wait for response
        response = sr1(packet, timeout=timeout, verbose=0)

        if response is None:
            # No response = open or filtered (ambiguous for UDP)
            return {
                "port": port,
                "status": "open|filtered",
                "service": _get_udp_service(port),
                "reason": "no_response"
            }

        # Got a response - check type
        if response.haslayer(ICMP):
            icmp_type = response[ICMP].type
            icmp_code = response[ICMP].code

            # ICMP type 3 = Destination Unreachable
            if icmp_type == 3:
                if icmp_code == 3:
                    # Code 3 = Port Unreachable = CLOSED
                    return {
                        "port": port,
                        "status": "closed",
                        "service": _get_udp_service(port),
                        "reason": "icmp_port_unreachable"
                    }
                else:
                    # Other ICMP codes = filtered by firewall
                    return {
                        "port": port,
                        "status": "filtered",
                        "service": _get_udp_service(port),
                        "reason": f"icmp_type3_code{icmp_code}"
                    }

        # Got a UDP response = definitely OPEN
        if response.haslayer(UDP):
            return {
                "port": port,
                "status": "open",
                "service": _get_udp_service(port),
                "reason": "udp_response_received"
            }

        return {
            "port": port,
            "status": "open|filtered",
            "service": _get_udp_service(port),
            "reason": "unexpected_response"
        }

    except Exception as e:
        return {
            "port": port,
            "status": "error",
            "service": _get_udp_service(port),
            "reason": str(e)
        }


def _check_udp_socket(host: str, port: int, timeout: float) -> Dict[str, Any]:
    """Fallback UDP check using Python sockets (no Scapy needed)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(UDP_PROBES.get(port, b''), (host, port))

        try:
            data, addr = sock.recvfrom(1024)
            return {
                "port": port,
                "status": "open",
                "service": _get_udp_service(port),
                "reason": "response_received",
                "data_received": len(data)
            }
        except socket.timeout:
            return {
                "port": port,
                "status": "open|filtered",
                "service": _get_udp_service(port),
                "reason": "no_response_timeout"
            }
    except Exception as e:
        return {
            "port": port,
            "status": "error",
            "service": _get_udp_service(port),
            "reason": str(e)
        }
    finally:
        sock.close()


def _get_udp_service(port: int) -> str:
    """Get service name for UDP port."""
    udp_services = {
        53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client",
        69: "TFTP", 123: "NTP", 137: "NetBIOS-NS",
        138: "NetBIOS-DGM", 161: "SNMP", 162: "SNMP-Trap",
        500: "IKE", 514: "Syslog", 520: "RIP",
        1194: "OpenVPN", 1701: "L2TP", 1900: "UPnP",
        4500: "IPSec-NAT", 5353: "mDNS"
    }
    return udp_services.get(port, "unknown-udp")


def udp_scan(
    host: str,
    ports: List[int] = None,
    timeout: float = 2.0
) -> Dict[str, Any]:
    """
    Scan multiple UDP ports on a target.

    Args:
        host: Target IP address
        ports: List of ports to scan (defaults to common UDP ports)
        timeout: Per-port timeout

    Returns:
        Complete UDP scan results
    """
    if ports is None:
        ports = COMMON_UDP_PORTS

    start_time = time.perf_counter()
    port_results = []
    open_ports = []
    open_filtered = []
    closed_ports = []

    for port in ports:
        result = check_udp_port(host, port, timeout)
        port_results.append(result)

        if result["status"] == "open":
            open_ports.append(port)
        elif result["status"] == "open|filtered":
            open_filtered.append(port)
        elif result["status"] == "closed":
            closed_ports.append(port)

        # Small delay to avoid flooding
        time.sleep(0.1)

    duration = time.perf_counter() - start_time

    return {
        "target": host,
        "scan_type": "udp",
        "ports_scanned": len(ports),
        "open_ports": open_ports,
        "open_or_filtered": open_filtered,
        "closed_ports": closed_ports,
        "port_details": port_results,
        "duration_seconds": round(duration, 2),
        "note": "UDP scanning is inherently ambiguous - open|filtered means no ICMP unreachable received"
    }
