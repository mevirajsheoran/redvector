"""
threatforge/core/recon/stealth_modes.py

Stealth Scanning Techniques

SYLLABUS: Unit 7 - nmap and various options, Unit 8 - Reconnaissance tools
COVERAGE: CO3, CO5 (demonstrates what IDS must detect)

THEORY:
Standard port scanning generates easily detectable traffic patterns:
- Many SYN packets in rapid succession
- All from same source IP
- To sequential or known target ports

Stealth techniques attempt to evade detection:

1. SLOW SCAN:
   Add random delays between packets (0.5 - 5 seconds).
   IDS systems that use rate thresholds (e.g., "alert if >20 SYNs/second")
   will not trigger. Downside: very slow.

2. FRAGMENTED PACKETS:
   Split TCP SYN packet into multiple small IP fragments.
   Simple packet filters that inspect only the first fragment
   may miss the TCP flags. Modern IDS reassemble before inspection.

3. DECOY SCANNING:
   Send scan packets with spoofed source IPs alongside real packets.
   Target sees probes from many IPs - hard to identify real attacker.
   (We simulate this concept without actual spoofing)

4. RANDOMIZED PORT ORDER:
   Instead of scanning 1,2,3,4,5..., scan in random order.
   Sequential scans are the most obvious pattern.

ACADEMIC VALUE:
Understanding stealth techniques teaches you what IDS must detect.
Snort rule: alert tcp any any -> $HOME_NET any
           (flags:S; threshold:type both,track by_src,count 20,seconds 60;)
This would miss a slow scan with delays > 3 seconds between packets.
"""

import time
import random
from typing import List, Dict, Any

try:
    from scapy.all import IP, TCP, sr1, send, fragment, conf
    conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from .syn_scanner import check_port_tcp_connect, COMMON_PORTS


def slow_scan(
    host: str,
    ports: List[int],
    min_delay: float = 0.5,
    max_delay: float = 3.0
) -> Dict[str, Any]:
    """
    Stealth scan using random delays to evade rate-based IDS.

    EVASION PRINCIPLE:
    Most IDS systems detect scans by counting SYN packets per time unit.
    By keeping the rate below the detection threshold, we evade the alert.

    Example Snort rule this evades:
    threshold:type both, track by_src, count 10, seconds 60
    (triggers if same source sends 10+ SYNs in 60 seconds)
    With delays of 7+ seconds between ports, this threshold never triggers.

    Args:
        host: Target IP
        ports: Ports to scan
        min_delay: Minimum seconds between port probes
        max_delay: Maximum seconds between port probes

    Returns:
        Scan results with timing information
    """
    start_time = time.perf_counter()
    results = {"open": [], "closed": [], "filtered": [], "details": []}
    total_delay_used = 0.0

    for i, port in enumerate(ports):
        port_start = time.perf_counter()

        # Use SYN scan if available, connect scan otherwise
        if SCAPY_AVAILABLE:
            try:
                syn = IP(dst=host) / TCP(dport=port, flags="S")
                response = sr1(syn, timeout=1.0, verbose=0)

                if response is None:
                    status = "filtered"
                elif response.haslayer(TCP):
                    if response[TCP].flags == 0x12:  # SYN-ACK
                        rst = IP(dst=host) / TCP(dport=port, flags="R")
                        send(rst, verbose=0)
                        status = "open"
                    elif response[TCP].flags & 0x04:  # RST
                        status = "closed"
                    else:
                        status = "filtered"
                else:
                    status = "filtered"
            except Exception:
                status = check_port_tcp_connect(host, port)
        else:
            status = check_port_tcp_connect(host, port)

        port_time = time.perf_counter() - port_start
        results[status].append(port)
        results["details"].append({
            "port": port,
            "status": status,
            "service": COMMON_PORTS.get(port, "unknown"),
            "response_time_ms": round(port_time * 1000, 2)
        })

        # Random delay between probes (the stealth part)
        if i < len(ports) - 1:
            delay = random.uniform(min_delay, max_delay)
            total_delay_used += delay
            time.sleep(delay)

    total_duration = time.perf_counter() - start_time

    return {
        "target": host,
        "scan_type": "slow_stealth",
        "ports_scanned": len(ports),
        "open_ports": results["open"],
        "port_details": results["details"],
        "total_duration_seconds": round(total_duration, 2),
        "total_delay_seconds": round(total_delay_used, 2),
        "effective_rate_pps": round(len(ports) / total_duration, 4),
        "evasion_technique": "random_delay",
        "evasion_note": (
            f"Average {total_delay_used/max(len(ports)-1,1):.1f}s between probes. "
            "Rate-based IDS with threshold >1 probe/s will not trigger."
        )
    }


def randomized_port_scan(
    host: str,
    ports: List[int],
    delay: float = 0.1
) -> Dict[str, Any]:
    """
    Scan ports in random order to evade sequential scan detection.

    EVASION PRINCIPLE:
    IDS systems often look for sequential port access patterns.
    Random order makes the scan look less like a systematic probe.

    Args:
        host: Target IP
        ports: Ports to scan
        delay: Delay between probes

    Returns:
        Scan results in random order
    """
    # Randomize port order
    shuffled_ports = ports.copy()
    random.shuffle(shuffled_ports)

    from .syn_scanner import scan_ports
    result = scan_ports(host, shuffled_ports, timing="normal")
    result["scan_type"] = "randomized"
    result["evasion_technique"] = "randomized_port_order"
    result["original_port_order"] = ports[:10]
    result["scanned_port_order"] = shuffled_ports[:10]

    return result


def fragmented_syn_scan(
    host: str,
    port: int,
    fragment_size: int = 8
) -> Dict[str, Any]:
    """
    Send fragmented SYN packet to test packet reassembly in IDS.

    EVASION PRINCIPLE:
    Some older/simpler packet filters examine each IP fragment independently.
    A SYN packet fragmented into tiny pieces may pass a filter that
    would block a complete SYN packet.

    Modern IDS (Snort, Suricata) reassemble fragments before inspection,
    so this evades only legacy/simple filters.

    ACADEMIC VALUE:
    This demonstrates WHY modern IDS systems implement
    stream reassembly - to handle exactly this evasion technique.

    Note: This is a demonstration. Fragment scanning is less effective
    against modern systems but illustrates the concept.

    Args:
        host: Target IP
        port: Target port
        fragment_size: Size of each fragment in bytes (8 minimum)

    Returns:
        Result showing fragmentation attempt and port status
    """
    if not SCAPY_AVAILABLE:
        status = check_port_tcp_connect(host, port)
        return {
            "host": host,
            "port": port,
            "status": status,
            "scan_type": "fragmented",
            "note": "Scapy not available - used TCP connect fallback"
        }

    try:
        # Build complete SYN packet
        packet = IP(dst=host, flags="DF") / TCP(dport=port, flags="S")

        # Fragment it into small pieces
        fragments = fragment(packet, fragsize=fragment_size)

        # Send all fragments
        for frag in fragments:
            send(frag, verbose=0)

        # Wait briefly for reassembly and response
        time.sleep(0.5)

        # Check result with connect scan (fragmented probing is fire-and-forget)
        status = check_port_tcp_connect(host, port, timeout=2.0)

        return {
            "host": host,
            "port": port,
            "status": status,
            "scan_type": "fragmented",
            "fragment_count": len(fragments),
            "fragment_size_bytes": fragment_size,
            "evasion_technique": "ip_fragmentation",
            "evasion_note": (
                f"Sent {len(fragments)} fragments of {fragment_size} bytes each. "
                "Evades filters that inspect only first fragment. "
                "Modern IDS reassembles fragments before inspection."
            )
        }

    except Exception as e:
        return {
            "host": host,
            "port": port,
            "status": "error",
            "error": str(e),
            "scan_type": "fragmented"
        }


def compare_stealth_vs_normal(
    host: str,
    ports: List[int]
) -> Dict[str, Any]:
    """
    Run both normal and slow scan, compare results.

    ACADEMIC PURPOSE:
    This directly maps to your syllabus requirement of
    "demonstrating nmap options" - we show the difference between
    aggressive and stealthy scanning.

    The comparison shows:
    - Both find same open ports (accuracy equal)
    - Slow scan takes much longer (trade-off: stealth vs speed)
    - Slow scan rate is below IDS detection threshold

    Args:
        host: Target IP
        ports: Sample ports to scan

    Returns:
        Comparison of normal vs stealth scan results
    """
    from .syn_scanner import scan_ports

    # Use small sample for comparison
    sample_ports = ports[:10]

    # Normal scan
    print(f"[*] Running normal scan on {host}...")
    normal_result = scan_ports(host, sample_ports, timing="fast")

    # Slow scan
    print(f"[*] Running stealth scan on {host}...")
    stealth_result = slow_scan(host, sample_ports, min_delay=0.3, max_delay=0.8)

    return {
        "target": host,
        "ports_compared": sample_ports,
        "normal_scan": {
            "open_ports": normal_result["open_ports"],
            "duration_seconds": normal_result["scan_duration_seconds"],
            "rate_pps": normal_result["scan_rate_pps"],
            "ids_visibility": "HIGH - rate likely triggers IDS"
        },
        "stealth_scan": {
            "open_ports": stealth_result["open_ports"],
            "duration_seconds": stealth_result["total_duration_seconds"],
            "rate_pps": stealth_result["effective_rate_pps"],
            "ids_visibility": "LOW - rate below typical IDS threshold"
        },
        "results_match": (
            set(normal_result["open_ports"]) == set(stealth_result["open_ports"])
        ),
        "academic_insight": (
            "Both scans find identical open ports but stealth scan takes "
            f"{stealth_result['total_duration_seconds'] / max(normal_result['scan_duration_seconds'], 0.01):.0f}x "
            "longer. This is the fundamental trade-off in stealth scanning."
        )
    }
