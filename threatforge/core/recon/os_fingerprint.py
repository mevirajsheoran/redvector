"""
threatforge/core/recon/os_fingerprint.py

OS Fingerprinting via TCP/IP Stack Analysis

SYLLABUS: Unit 8 - Network Reconnaissance Tools
COVERAGE: CO3

THEORY:
Different operating systems implement the TCP/IP stack differently.
These differences create a "fingerprint" that reveals the OS without
the target ever knowing we're probing for this information.

KEY FINGERPRINTING SIGNALS:

1. TTL (Time To Live) Initial Values:
   Linux:   TTL = 64
   Windows: TTL = 128
   Cisco:   TTL = 255
   FreeBSD: TTL = 64
   
   WHY: Each OS starts with a different TTL. By the time the packet
   reaches us, TTL has been decremented by each router hop.
   We add back estimated hops to find initial TTL.

2. TCP Window Size:
   Linux:    5840 or 29200
   Windows:  65535 or 8192
   macOS:    65535
   
   WHY: OS determines initial TCP window size in its networking stack.

3. TCP Options Order:
   Different OSes set TCP options in different orders:
   MSS (Maximum Segment Size)
   SACK (Selective Acknowledgment)
   Timestamps
   Window Scale
   
4. DF Bit (Don't Fragment):
   Some OSes set DF bit by default, others don't.

PASSIVE vs ACTIVE FINGERPRINTING:
- Passive: Watch traffic without sending anything (we analyze)
- Active:  Send crafted packets and analyze responses (we implement)

EQUIVALENT NMAP: nmap -O target (OS detection)
"""

import time
import socket
from typing import Dict, Any, Optional, List

try:
    from scapy.all import IP, TCP, sr1, conf
    conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# OS fingerprint database based on TTL and window size
# This is a simplified version of what nmap uses
OS_FINGERPRINTS: List[Dict[str, Any]] = [
    {
        "os": "Linux (Kernel 2.6+)",
        "ttl_range": (60, 68),
        "window_sizes": [5840, 14600, 29200, 65535],
        "confidence_base": 0.7
    },
    {
        "os": "Windows 10/11",
        "ttl_range": (120, 132),
        "window_sizes": [8192, 65535, 64240],
        "confidence_base": 0.75
    },
    {
        "os": "Windows 7/8",
        "ttl_range": (120, 132),
        "window_sizes": [8192, 65535],
        "confidence_base": 0.65
    },
    {
        "os": "macOS",
        "ttl_range": (60, 68),
        "window_sizes": [65535, 65228],
        "confidence_base": 0.65
    },
    {
        "os": "FreeBSD",
        "ttl_range": (60, 68),
        "window_sizes": [65535],
        "confidence_base": 0.6
    },
    {
        "os": "Cisco IOS",
        "ttl_range": (250, 260),
        "window_sizes": [4128, 16384],
        "confidence_base": 0.8
    },
    {
        "os": "Android",
        "ttl_range": (60, 68),
        "window_sizes": [65535, 14480],
        "confidence_base": 0.55
    },
]


def get_ttl_from_ping(host: str, timeout: float = 2.0) -> Optional[int]:
    """
    Get TTL value from ping response.

    We send an ICMP ping and read the TTL from the response.
    TTL tells us approximately how many hops away the host is
    AND gives us the starting TTL (initial OS-specific value).

    Args:
        host: Target IP
        timeout: Seconds to wait

    Returns:
        TTL value or None if host unreachable
    """
    if not SCAPY_AVAILABLE:
        return None

    try:
        from scapy.all import ICMP
        ping = IP(dst=host) / ICMP()
        response = sr1(ping, timeout=timeout, verbose=0)

        if response and response.haslayer(IP):
            return response[IP].ttl
        return None
    except Exception:
        return None


def get_tcp_syn_ack_info(host: str, port: int = 80, timeout: float = 2.0) -> Optional[Dict]:
    """
    Send SYN and analyze SYN-ACK response for fingerprinting signals.

    The SYN-ACK response contains:
    - Window size (OS-specific)
    - TCP options (order is OS-specific)
    - TTL of the response

    Args:
        host: Target IP
        port: Open port to probe (needs to be open to get SYN-ACK)
        timeout: Seconds to wait

    Returns:
        Dict with fingerprinting signals or None
    """
    if not SCAPY_AVAILABLE:
        return None

    try:
        syn = IP(dst=host) / TCP(dport=port, flags="S", options=[
            ('MSS', 1460),
            ('SAckOK', b''),
            ('Timestamp', (0, 0)),
            ('NOP', None),
            ('WScale', 6)
        ])

        response = sr1(syn, timeout=timeout, verbose=0)

        if response and response.haslayer(TCP):
            tcp_response = response[TCP]
            ip_response = response[IP]

            # Send RST to close cleanly
            rst = IP(dst=host) / TCP(
                dport=port, flags="R", seq=tcp_response.ack
            )
            from scapy.all import send
            send(rst, verbose=0)

            return {
                "ttl": ip_response.ttl,
                "window_size": tcp_response.window,
                "flags": tcp_response.flags,
                "options": tcp_response.options,
                "df_bit": bool(ip_response.flags & 0x02)
            }

        return None

    except Exception:
        return None


def fingerprint_os(
    host: str,
    open_port: Optional[int] = None
) -> Dict[str, Any]:
    """
    Attempt to identify the target's operating system.

    ALGORITHM:
    1. Get TTL via ICMP ping
    2. If we know an open port: get TCP SYN-ACK details
    3. Estimate hops from TTL (TTL decrements by 1 per router)
    4. Estimate initial TTL (round up to nearest: 64, 128, 255)
    5. Match initial TTL + window size against fingerprint database
    6. Return best match with confidence score

    Args:
        host: Target IP
        open_port: Known open TCP port (improves accuracy)

    Returns:
        OS fingerprinting results with confidence scores
    """
    start_time = time.perf_counter()

    result: Dict[str, Any] = {
        "target": host,
        "raw_signals": {},
        "os_guesses": [],
        "best_guess": None,
        "confidence": 0.0,
        "method": "ttl_window_analysis"
    }

    # Get TTL signal
    ttl = get_ttl_from_ping(host)
    if ttl:
        result["raw_signals"]["ttl_received"] = ttl

        # Estimate initial TTL
        if ttl <= 64:
            initial_ttl = 64
        elif ttl <= 128:
            initial_ttl = 128
        else:
            initial_ttl = 255

        result["raw_signals"]["estimated_initial_ttl"] = initial_ttl
        result["raw_signals"]["estimated_hops"] = initial_ttl - ttl

    # Get TCP signals if we have an open port
    window_size = None
    if open_port and SCAPY_AVAILABLE:
        tcp_info = get_tcp_syn_ack_info(host, open_port)
        if tcp_info:
            window_size = tcp_info["window_size"]
            result["raw_signals"]["tcp_window_size"] = window_size
            result["raw_signals"]["df_bit"] = tcp_info["df_bit"]
            result["raw_signals"]["tcp_options"] = str(tcp_info["options"])

    # Match signals to fingerprint database
    guesses = []
    if ttl:
        for fp in OS_FINGERPRINTS:
            score = 0.0
            match_reasons = []

            # TTL match check
            ttl_min, ttl_max = fp["ttl_range"]
            if ttl_min <= ttl <= ttl_max:
                score += fp["confidence_base"]
                match_reasons.append(f"TTL {ttl} in range {ttl_min}-{ttl_max}")

            # Window size match check
            if window_size and window_size in fp["window_sizes"]:
                score += 0.2
                match_reasons.append(f"Window size {window_size} matches")

            if score > 0.3:
                guesses.append({
                    "os": fp["os"],
                    "confidence": round(min(score, 1.0), 2),
                    "match_reasons": match_reasons
                })

    # Sort by confidence
    guesses.sort(key=lambda x: x["confidence"], reverse=True)
    result["os_guesses"] = guesses[:3]  # Top 3 guesses

    if guesses:
        result["best_guess"] = guesses[0]["os"]
        result["confidence"] = guesses[0]["confidence"]

    # Fallback if Scapy not available
    if not SCAPY_AVAILABLE:
        result["note"] = "Limited fingerprinting: Scapy not available. Using socket-based method."
        result["best_guess"] = "Unknown (install Scapy for full fingerprinting)"

    result["duration_ms"] = round((time.perf_counter() - start_time) * 1000, 2)
    result["academic_note"] = (
        "OS fingerprinting uses TCP/IP implementation differences between "
        "operating systems. TTL initial values: Linux=64, Windows=128, Cisco=255. "
        "This is why network hardening often involves changing default TTL values."
    )

    return result
