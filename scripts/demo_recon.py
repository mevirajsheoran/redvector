#!/usr/bin/env python3
"""
scripts/demo_recon.py

Week 2 Demo Script - Network Reconnaissance Module

Shows live port scanning, banner grabbing, and OS fingerprinting.

Usage: python scripts/demo_recon.py
       sudo python scripts/demo_recon.py  (for SYN scan)

TARGETS: Docker lab containers (must be running)
         Run: docker compose up -d
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from threatforge.core.recon.syn_scanner import scan_ports, PORT_GROUPS
from threatforge.core.recon.banner_grab import grab_multiple_banners
from threatforge.core.recon.os_fingerprint import fingerprint_os
from threatforge.core.recon.stealth_modes import compare_stealth_vs_normal
from threatforge.core.analyzer.metrics import ScanMetrics

console = Console()

# Demo target (nginx container in Docker lab)
TARGET = "172.25.0.12"  # Change to 127.0.0.1 if Docker not running


def demo_port_scan():
    console.print(Panel("🔍 DEMO 1: TCP PORT SCAN", style="bold cyan"))
    console.print(f"\n[yellow]Target:[/yellow] {TARGET}")
    console.print("[yellow]Method:[/yellow] TCP Connect Scan (SYN scan if root)")
    console.print("[yellow]Ports:[/yellow] Top 20 common ports\n")

    console.print("[cyan]Scanning...[/cyan]")
    result = scan_ports(TARGET, PORT_GROUPS["top_20"], timing="normal", method="connect")

    # Display results table
    table = Table(title="Port Scan Results", box=box.ROUNDED)
    table.add_column("Port", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Service")
    table.add_column("Response Time")

    for detail in result["port_details"]:
        status_color = "green" if detail["status"] == "open" else "red"
        table.add_row(
            str(detail["port"]),
            f"[{status_color}]{detail['status']}[/{status_color}]",
            detail["service"],
            f"{detail['response_time_ms']}ms"
        )

    console.print(table)
    console.print(f"\n[green]Open ports:[/green] {result['open_ports']}")
    console.print(f"[green]Scan time:[/green] {result['scan_duration_seconds']}s")
    console.print(f"[green]Scan rate:[/green] {result['scan_rate_pps']} ports/sec")

    return result["open_ports"]


def demo_banner_grabbing(open_ports):
    console.print(Panel("🏷️  DEMO 2: BANNER GRABBING (Service Detection)", style="bold cyan"))

    if not open_ports:
        console.print("[yellow]No open ports found, using defaults[/yellow]")
        open_ports = [80, 8080]

    console.print(f"\n[yellow]Grabbing banners from ports:[/yellow] {open_ports}\n")

    result = grab_multiple_banners(TARGET, open_ports)

    table = Table(title="Service Detection Results", box=box.ROUNDED)
    table.add_column("Port", style="cyan")
    table.add_column("Service")
    table.add_column("Version")
    table.add_column("Banner (Preview)")

    for banner in result["banner_details"]:
        banner_preview = str(banner.get("banner_clean", ""))[:40] + "..." if banner.get("banner_clean") else "No banner"
        table.add_row(
            str(banner["port"]),
            banner.get("service_identified", "Unknown"),
            banner.get("version", "?"),
            banner_preview
        )

    console.print(table)
    console.print(f"\n[green]Services identified:[/green] {len(result['services_identified'])}")


def demo_stealth_comparison():
    console.print(Panel("🥷 DEMO 3: NORMAL vs STEALTH SCAN", style="bold cyan"))
    console.print("\n[cyan]Running comparison (this takes ~30 seconds)...[/cyan]\n")

    # Use only 5 ports for quick demo
    sample_ports = [80, 443, 22, 3306, 8080]
    result = compare_stealth_vs_normal(TARGET, sample_ports)

    table = Table(title="Scan Comparison", box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Normal Scan")
    table.add_column("Stealth Scan")

    normal = result["normal_scan"]
    stealth = result["stealth_scan"]

    table.add_row("Duration", f"{normal['duration_seconds']}s", f"{stealth['duration_seconds']}s")
    table.add_row("Rate", f"{normal['rate_pps']} pps", f"{stealth['rate_pps']} pps")
    table.add_row("IDS Visibility", normal['ids_visibility'], stealth['ids_visibility'])
    table.add_row("Results Match", str(result["results_match"]), "")

    console.print(table)
    console.print(f"\n[green]Academic Insight:[/green] {result['academic_insight']}")


def main():
    console.print(Panel(
        "🛡️  THREATFORGE - NETWORK RECONNAISSANCE DEMO\n"
        "INS Lab - Unit 7 & 8 Coverage\n"
        f"Target: {TARGET} (Docker Lab)",
        style="bold blue"
    ))

    console.print("\n[yellow]⚠️  ETHICAL USE: Testing isolated Docker lab only[/yellow]\n")

    # Make sure Docker lab is accessible
    import socket
    try:
        sock = socket.socket()
        sock.settimeout(1)
        sock.connect((TARGET, 80))
        sock.close()
        console.print("[green]✅ Docker lab accessible[/green]\n")
    except Exception:
        console.print(f"[red]⚠️  Cannot reach {TARGET}[/red]")
        console.print("[yellow]Using 127.0.0.1 as fallback target[/yellow]\n")
        global TARGET
        TARGET = "127.0.0.1"

    open_ports = demo_port_scan()
    console.print("\n" + "─" * 60 + "\n")

    demo_banner_grabbing(open_ports)
    console.print("\n" + "─" * 60 + "\n")

    demo_stealth_comparison()

    console.print(Panel(
        "✅ RECONNAISSANCE DEMO COMPLETE\n"
        "Covered: Port scanning, banner grabbing, stealth techniques\n"
        "Syllabus: Unit 7 (nmap options) + Unit 8 (recon tools)",
        style="bold green"
    ))


if __name__ == "__main__":
    main()
