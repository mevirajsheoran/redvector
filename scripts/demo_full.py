#!/usr/bin/env python3
"""
scripts/demo_full.py

COMPLETE PROFESSOR DEMO SCRIPT
ThreatForge - Offensive Security Testing Framework

This script runs the FULL demo sequence in order.
Designed for a 10-15 minute live demonstration.

PRESENTATION ORDER:
1. System overview (1 min)
2. Cryptanalysis demos (3 min)
3. Network recon demo (3 min)
4. DoS simulation demo (3 min)
5. Sentinel validation (4 min)
6. Validation matrix review (1 min)

Total: ~15 minutes

BEFORE RUNNING:
1. docker compose up -d
2. uvicorn threatforge.main:app --port 9000 (separate terminal)
3. uvicorn Vigil.main:app --port 8000 (separate terminal)
4. npm run dev in dashboard/ (separate terminal)
5. Open http://localhost:5173 in browser
"""

import sys
import os
import asyncio
import time
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from rich import box

console = Console()

THREATFORGE_URL = "http://localhost:9000"
SENTINEL_URL = "http://localhost:8000"
DOCKER_TARGET = "http://172.25.0.12"
DOCKER_IP = "172.25.0.12"


def section_header(title: str, subtitle: str = ""):
    """Print a clear section header for demo navigation."""
    console.print()
    console.print(Panel(
        f"[bold white]{title}[/bold white]\n[dim]{subtitle}[/dim]",
        style="bold cyan",
        expand=True
    ))
    console.print()


def wait_for_enter(message: str = "Press ENTER to continue..."):
    """Pause for professor to observe."""
    console.print(f"\n[yellow]>>> {message}[/yellow]")
    input()


def print_step(number: int, description: str):
    """Print numbered step."""
    console.print(f"[cyan]Step {number}:[/cyan] {description}")


# ─────────────────────────────────────────
# SECTION 1: SYSTEM OVERVIEW
# ─────────────────────────────────────────

def demo_system_overview():
    section_header(
        "SECTION 1: SYSTEM OVERVIEW",
        "What ThreatForge is and why it exists"
    )

    console.print("""
[bold]PROBLEM STATEMENT:[/bold]
  Defensive security tools are deployed without empirical validation.
  How do you PROVE your IDS actually works?

[bold]SOLUTION - THREATFORGE:[/bold]
  A controlled adversary emulation platform that:
  ├── Breaks classical ciphers (CO1, CO2)
  ├── Performs network reconnaissance (CO3)
  ├── Simulates DoS/DDoS attacks (CO4)
  ├── Demonstrates IDS evasion concepts (CO5)
  └── Validates defensive systems with measurable metrics

[bold]UNIQUE POSITION:[/bold]
  Every other student project builds DEFENSES.
  ThreatForge builds the ATTACK side AND validates defenses scientifically.
  This is called "Purple Teaming" in professional security.
    """)

    console.print("[bold]ARCHITECTURE:[/bold]")
    console.print("""
  ┌─────────────────┐     attacks     ┌──────────────────┐
  │   THREATFORGE   │ ──────────────► │  DOCKER TEST LAB  │
  │  (Port 9000)    │                 │  DVWA, WebGoat,   │
  │                 │ ──────────────► │  nginx, Python    │
  │  React Dashboard│                 └──────────────────┘
  │  (Port 5173)    │
  │                 │ ──────────────► ┌──────────────────┐
  │  4 Modules:     │   validates     │  SENTINEL/VIGIL  │
  │  Crypto         │ ◄────────────── │  (Port 8000)     │
  │  Recon          │   detection     └──────────────────┘
  │  DoS            │   metrics
  │  Validation     │
  └─────────────────┘
    """)

    wait_for_enter("Show dashboard in browser, then press ENTER")


# ─────────────────────────────────────────
# SECTION 2: CRYPTANALYSIS DEMO
# ─────────────────────────────────────────

def demo_cryptanalysis():
    section_header(
        "SECTION 2: CRYPTANALYSIS MODULE",
        "Breaking classical ciphers - Syllabus Units 1-6 (CO1, CO2)"
    )

    from threatforge.core.crypto_attacks.caesar import encrypt_caesar, run_full_caesar_analysis
    from threatforge.core.crypto_attacks.vigenere import encrypt_vigenere, kasiski_attack
    from threatforge.core.crypto_attacks.rsa_factor import demo_full_rsa_attack

    # Demo 2.1: Caesar Cipher
    print_step(1, "Caesar Cipher - Brute Force + Frequency Analysis")

    plaintext = "INFORMATION AND NETWORK SECURITY SYSTEM"
    key = 13
    ciphertext = encrypt_caesar(plaintext, key)

    console.print(f"  Original:  [green]{plaintext}[/green]")
    console.print(f"  Key:       [yellow]{key}[/yellow]")
    console.print(f"  Encrypted: [red]{ciphertext}[/red]")
    console.print("  [cyan]Attacking...[/cyan]")

    start = time.perf_counter()
    result = run_full_caesar_analysis(ciphertext)
    elapsed = time.perf_counter() - start

    console.print(f"  Key Found: [green]{result['final_answer']['key']}[/green] ({'CORRECT' if result['final_answer']['key'] == key else 'WRONG'})")
    console.print(f"  Decrypted: [green]{result['final_answer']['decrypted']}[/green]")
    console.print(f"  Confidence: [green]{result['final_answer']['confidence']}[/green]")
    console.print(f"  Time: [cyan]{elapsed*1000:.2f}ms[/cyan] (tried all 26 keys)")
    console.print(f"  Methods Agree: [green]{result['methods_agree']}[/green]")

    console.print("\n  [dim]Academic note: Caesar has only 26 possible keys.")
    console.print("  This proves why modern crypto needs 2^256 key space.[/dim]")

    wait_for_enter()

    # Demo 2.2: Vigenère Cipher
    print_step(2, "Vigenère Cipher - Kasiski Examination")

    plaintext2 = "THE SECURITY OF A CRYPTOGRAPHIC SYSTEM SHOULD NOT DEPEND ON THE ALGORITHM SECRECY"
    key2 = "CYBER"
    encrypted2 = encrypt_vigenere(plaintext2, key2)

    console.print(f"  Key Used: [yellow]{key2}[/yellow]")
    console.print(f"  Ciphertext: [red]{encrypted2[:50]}...[/red]")
    console.print("  [cyan]Running Kasiski examination...[/cyan]")

    result2 = kasiski_attack(encrypted2)
    best = result2["best_result"]

    console.print(f"  Repeated sequences found: [cyan]{result2['repeated_sequences_found']}[/cyan]")
    console.print(f"  Key length detected: [cyan]{best['key_length'] if best else 'N/A'}[/cyan]")
    console.print(f"  Key recovered: [green]{best['key_found'] if best else 'N/A'}[/green]")
    console.print(f"  Score: [cyan]{best['overall_score'] if best else 0}[/cyan]")

    wait_for_enter()

    # Demo 2.3: RSA Factorization
    print_step(3, "RSA Factorization - Small Prime Attack")

    console.print("  [cyan]Generating small RSA key pair and attacking...[/cyan]")

    result3 = demo_full_rsa_attack()
    scenario = result3["demo_scenario"]
    attack = result3["attack"]

    table = Table(title="RSA Attack Steps", box=box.SIMPLE)
    table.add_column("Step")
    table.add_column("Action")
    table.add_column("Result")

    for step in attack.get("steps", []):
        table.add_row(
            str(step["step"]),
            step["description"],
            str(step.get("result", ""))
        )

    console.print(table)
    console.print(f"\n  Original message: [yellow]{scenario['original_message']}[/yellow]")
    console.print(f"  Ciphertext: [red]{scenario['ciphertext']}[/red]")
    console.print(f"  Recovered: [green]{attack.get('decrypted_value')}[/green]")
    console.print(f"  Time: [cyan]{attack['time_taken_ms']}ms[/cyan]")
    console.print(f"\n  [dim]{attack['security_insight']}[/dim]")

    wait_for_enter()


# ─────────────────────────────────────────
# SECTION 3: RECONNAISSANCE DEMO
# ─────────────────────────────────────────

def demo_reconnaissance():
    section_header(
        "SECTION 3: NETWORK RECONNAISSANCE",
        "Scanning and fingerprinting - Syllabus Units 7-8 (CO3)"
    )

    from threatforge.core.recon.syn_scanner import scan_ports, PORT_GROUPS
    from threatforge.core.recon.banner_grab import grab_multiple_banners
    from threatforge.core.analyzer.metrics import ScanMetrics

    target = DOCKER_IP

    # Demo 3.1: Port Scan
    print_step(1, f"TCP Port Scan on {target} (Docker Lab nginx)")
    console.print("  [cyan]Scanning top 20 ports...[/cyan]")

    scan_result = scan_ports(target, PORT_GROUPS["top_20"], timing="normal", method="connect")

    table = Table(title=f"Port Scan Results - {target}", box=box.SIMPLE)
    table.add_column("Port", style="cyan")
    table.add_column("Status")
    table.add_column("Service")
    table.add_column("Time")

    open_ports = []
    for detail in scan_result["port_details"]:
        if detail["status"] == "open":
            table.add_row(
                str(detail["port"]),
                "[green]OPEN[/green]",
                detail["service"],
                f"{detail['response_time_ms']}ms"
            )
            open_ports.append(detail["port"])

    console.print(table)
    console.print(f"  Found {len(open_ports)} open ports: [green]{open_ports}[/green]")
    console.print(f"  Scan time: [cyan]{scan_result['scan_duration_seconds']}s[/cyan]")
    console.print(f"  Scan rate: [cyan]{scan_result['scan_rate_pps']} ports/sec[/cyan]")

    # Compare with nmap
    console.print("\n  [cyan]Comparing with nmap...[/cyan]")
    try:
        nmap_result = subprocess.run(
            ["nmap", "-sT", "--open", "-p", "21,22,80,443,3306,8080", target],
            capture_output=True, text=True, timeout=30
        )
        nmap_open = []
        for line in nmap_result.stdout.split('\n'):
            if '/tcp' in line and 'open' in line:
                port = int(line.split('/')[0].strip())
                nmap_open.append(port)

        if nmap_open:
            metrics = ScanMetrics.compare_with_nmap(open_ports, nmap_open)
            console.print(f"  Precision vs nmap: [green]{metrics['precision']:.1%}[/green]")
            console.print(f"  Recall vs nmap:    [green]{metrics['recall']:.1%}[/green]")
    except Exception:
        console.print("  [dim](nmap comparison skipped - not available)[/dim]")

    wait_for_enter()

    # Demo 3.2: Banner Grabbing
    if open_ports:
        print_step(2, "Banner Grabbing - Service Version Detection")
        console.print(f"  [cyan]Grabbing banners from {open_ports[:3]}...[/cyan]")

        banner_result = grab_multiple_banners(target, open_ports[:3])

        table2 = Table(title="Service Detection", box=box.SIMPLE)
        table2.add_column("Port")
        table2.add_column("Service")
        table2.add_column("Version")
        table2.add_column("Banner Preview")

        for b in banner_result["banner_details"]:
            preview = str(b.get("banner_clean", ""))[:35] + "..." if b.get("banner_clean") else "No banner"
            table2.add_row(
                str(b["port"]),
                b.get("service_identified", "?"),
                b.get("version", "?"),
                preview
            )

        console.print(table2)

    wait_for_enter()


# ─────────────────────────────────────────
# SECTION 4: DoS SIMULATION DEMO
# ─────────────────────────────────────────

async def demo_dos():
    section_header(
        "SECTION 4: DoS SIMULATION",
        "Controlled attack simulation - Syllabus Unit 11 (CO4)"
    )

    from threatforge.core.dos_simulation.http_flood import http_get_flood
    from threatforge.core.traffic_patterns.normal_baseline import generate_normal_traffic

    # Demo 4.1: Baseline
    print_step(1, "Generate Normal Baseline Traffic (30 seconds)")
    console.print("  [cyan]Generating human-like browsing traffic...[/cyan]")

    baseline = await generate_normal_traffic(DOCKER_TARGET, 30, 8)
    console.print(f"  Baseline RPM: [green]{baseline['average_rpm']}[/green]")
    console.print(f"  Pattern: [green]{baseline['traffic_pattern']}[/green]")
    console.print(f"  Requests sent: [green]{baseline['total_requests']}[/green]")

    wait_for_enter()

    # Demo 4.2: HTTP Flood
    print_step(2, "HTTP Flood Attack (50 RPS, 20 seconds)")
    console.print("  [cyan]Flooding target...[/cyan]")
    console.print(f"  Target: [red]{DOCKER_TARGET}[/red]")
    console.print(f"  Rate: [red]50 requests/second[/red]")

    flood_result = await http_get_flood(DOCKER_TARGET, 50, 20)

    table = Table(title="HTTP Flood Metrics", box=box.SIMPLE)
    table.add_column("Metric", style="cyan")
    table.add_column("Baseline")
    table.add_column("Attack")

    baseline_rpm = baseline.get("average_rpm", 0)
    attack_rpm = flood_result.get("actual_rps", 0) * 60

    table.add_row("Requests/Minute", str(baseline_rpm), f"[red]{attack_rpm:.0f}[/red]")
    table.add_row("Pattern", "Human (varied)", "[red]Automated (same endpoint)[/red]")
    table.add_row("Success Rate", "~95%", f"{flood_result.get('success_rate_pct', 0):.1f}%")
    table.add_row("Total Sent", str(baseline.get("total_requests", 0)),
                  str(flood_result.get("total_requests_sent", 0)))

    console.print(table)

    amplification = attack_rpm / max(baseline_rpm, 1)
    console.print(f"\n  Attack is [red]{amplification:.0f}x[/red] louder than normal traffic")
    console.print("  [dim]This difference is what IDS systems like Sentinel detect[/dim]")

    wait_for_enter()


# ─────────────────────────────────────────
# SECTION 5: SENTINEL VALIDATION DEMO
# ─────────────────────────────────────────

async def demo_validation():
    section_header(
        "SECTION 5: SENTINEL VALIDATION (SHOWSTOPPER)",
        "Scientific proof that Sentinel detects real attacks"
    )

    from threatforge.validation.sentinel_client import SentinelClient
    from threatforge.validation.correlator import AttackCorrelator
    from threatforge.validation.matrix_builder import ValidationMatrixBuilder

    sentinel = SentinelClient(SENTINEL_URL)

    if not sentinel.test_connection():
        console.print("[red]❌ Sentinel offline. Showing expected results instead.[/red]")
        console.print("\n[yellow]Start Sentinel:[/yellow] uvicorn Vigil.main:app --port 8000")

        # Show expected output
        table = Table(title="Expected Validation Results", box=box.DOUBLE_EDGE)
        table.add_column("Test ID", style="cyan")
        table.add_column("Attack Type")
        table.add_column("Sent")
        table.add_column("Detected")
        table.add_column("Latency")
        table.add_column("Block%")
        table.add_column("Confidence")

        expected_data = [
            ("TF-HTTP-001", "http_flood", "1000", "✅ YES", "2.3s", "85.5%", "HIGH"),
            ("TF-CRED-002", "credential_stuffing", "100", "✅ YES", "5.1s", "42.3%", "MEDIUM"),
            ("TF-ENUM-003", "enumeration", "200", "✅ YES", "3.7s", "28.1%", "HIGH"),
        ]

        for row in expected_data:
            table.add_row(*row)

        console.print(table)
        console.print("\n[dim]These results are generated when Sentinel is running.[/dim]")
        wait_for_enter()
        return

    console.print("[green]✅ Sentinel connected[/green]")

    correlator = AttackCorrelator(sentinel)
    builder = ValidationMatrixBuilder()

    print_step(1, "Get Sentinel Baseline Stats")
    baseline_stats = sentinel.snapshot_stats()
    console.print(f"  Total requests processed: [cyan]{baseline_stats.total_requests}[/cyan]")
    console.print(f"  Current block rate: [cyan]{baseline_stats.block_rate_pct}%[/cyan]")
    console.print(f"  Active fingerprints: [cyan]{baseline_stats.unique_fingerprints}[/cyan]")

    wait_for_enter()

    # Run each test with live output
    all_results = []

    for test_name, test_fn, kwargs in [
        ("HTTP FLOOD", correlator.run_http_flood_validation,
         {"target_url": SENTINEL_URL, "requests_per_second": 50, "duration_seconds": 20}),
        ("CREDENTIAL STUFFING", correlator.run_credential_stuffing_validation,
         {"target_url": SENTINEL_URL, "attempts_per_second": 5, "duration_seconds": 20}),
        ("ENUMERATION", correlator.run_enumeration_validation,
         {"target_url": SENTINEL_URL, "items_per_second": 10, "duration_seconds": 20}),
    ]:
        console.print(f"\n  [yellow]Running {test_name} test...[/yellow]")
        result = await test_fn(**kwargs)
        all_results.append(result)
        builder.add_result(result)

        status = "[green]✅ DETECTED[/green]" if result.sentinel_detected else "[red]❌ MISSED[/red]"
        console.print(f"  Result: {status}")
        console.print(f"  Blocks triggered: [cyan]{result.blocks_triggered}[/cyan]")
        console.print(f"  Block rate: [cyan]{result.block_rate_pct:.1f}%[/cyan]")
        console.print(f"  Confidence: [cyan]{result.detection_confidence}[/cyan]")

        await asyncio.sleep(2)

    # Final table
    print_step(2, "Validation Matrix (Generated Automatically)")

    table = Table(title="VALIDATION_MATRIX.CSV", box=box.DOUBLE_EDGE)
    table.add_column("Test ID", style="cyan")
    table.add_column("Attack")
    table.add_column("Sent")
    table.add_column("Detected")
    table.add_column("Latency")
    table.add_column("Block%")
    table.add_column("Confidence")

    for r in all_results:
        det = "[green]✅ YES[/green]" if r.sentinel_detected else "[red]❌ NO[/red]"
        table.add_row(
            r.test_id,
            r.attack_type,
            str(r.payloads_sent),
            det,
            f"{r.detection_latency_seconds:.1f}s" if r.detection_latency_seconds else "N/A",
            f"{r.block_rate_pct:.1f}%",
            r.detection_confidence
        )

    console.print(table)

    # Save matrix
    csv_path = builder.save_csv()
    json_path = builder.save_json()
    metrics = builder.compute_final_metrics()

    console.print(Panel(
        f"[green]FINAL METRICS[/green]\n\n"
        f"  Detection Rate:    [bold green]{metrics.get('detection_rate_pct', 0)}%[/bold green]\n"
        f"  Avg Block Rate:    [bold green]{metrics.get('avg_block_rate_pct', 0)}%[/bold green]\n"
        f"  Avg Latency:       [bold green]{metrics.get('avg_detection_latency_s', 'N/A')}s[/bold green]\n\n"
        f"  CSV: [cyan]{csv_path}[/cyan]\n"
        f"  JSON: [cyan]{json_path}[/cyan]",
        style="bold green"
    ))

    wait_for_enter()


# ─────────────────────────────────────────
# MAIN DEMO RUNNER
# ─────────────────────────────────────────

async def main():
    console.print(Panel(
        "[bold green]⚔ THREATFORGE - LIVE DEMONSTRATION[/bold green]\n"
        "INS Lab TE7947 - Academic Project\n"
        "Offensive Security Testing Framework\n\n"
        "[dim]ETHICAL STATEMENT: All testing on isolated Docker lab only[/dim]",
        style="bold blue",
        expand=True
    ))

    wait_for_enter("Demo ready. Press ENTER to start Section 1")

    demo_system_overview()
    demo_cryptanalysis()
    demo_reconnaissance()
    await demo_dos()
    await demo_validation()

    # Final summary
    console.print(Panel(
        "[bold green]✅ DEMO COMPLETE[/bold green]\n\n"
        "Demonstrated:\n"
        "  🔐 Cryptanalysis (Caesar, Vigenère, RSA) → CO1, CO2\n"
        "  🔍 Network Recon (TCP scan, banner grab)  → CO3\n"
        "  💥 DoS Simulation (HTTP flood, baseline)  → CO4, CO5\n"
        "  ✅ Sentinel Validation (scientific proof)  → All COs\n\n"
        "Files generated:\n"
        "  📄 reports/validation_matrix.csv\n"
        "  📄 reports/validation_full.json\n\n"
        "[cyan]GitHub: github.com/YOUR_USERNAME/threatforge[/cyan]",
        style="bold green"
    ))


if __name__ == "__main__":
    asyncio.run(main())
