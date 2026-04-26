#!/usr/bin/env python3
"""
scripts/demo_dos.py

Week 3 Demo Script - DoS Simulation Module

Shows live DoS attacks with metrics.

Usage: python scripts/demo_dos.py
"""

import sys
import os
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from threatforge.core.dos_simulation.http_flood import http_get_flood
from threatforge.core.dos_simulation.slowloris import SlowlorisAttack
from threatforge.core.traffic_patterns.normal_baseline import generate_normal_traffic

console = Console()
TARGET_HTTP = "http://172.25.0.12"  # nginx in Docker lab
TARGET_IP = "172.25.0.12"


async def demo_http_flood():
    console.print(Panel("💧 DEMO 1: HTTP FLOOD ATTACK", style="bold red"))
    console.print(f"\n[yellow]Target:[/yellow] {TARGET_HTTP}")
    console.print("[yellow]Rate:[/yellow] 50 requests/second")
    console.print("[yellow]Duration:[/yellow] 20 seconds\n")

    console.print("[cyan]Flooding...[/cyan]")
    result = await http_get_flood(TARGET_HTTP, 50, 20)

    table = Table(title="HTTP Flood Results", box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Total Requests Sent", str(result["total_requests_sent"]))
    table.add_row("Successful Responses", str(result["successful_responses"]))
    table.add_row("Actual Rate (RPS)", str(result["actual_rps"]))
    table.add_row("Success Rate", f"{result['success_rate_pct']}%")
    table.add_row("Duration", f"{result['duration_seconds']}s")
    table.add_row("Avg Response Time", f"{result['avg_response_time_ms']}ms")

    console.print(table)

    # Show response code distribution
    console.print("\n[yellow]Response Code Distribution:[/yellow]")
    for code, count in result.get("response_code_distribution", {}).items():
        bar = "█" * min(count // 10, 50)
        console.print(f"  HTTP {code}: {bar} ({count})")


async def demo_baseline_vs_attack():
    console.print(Panel("📊 DEMO 2: BASELINE vs ATTACK COMPARISON", style="bold red"))
    console.print("\n[cyan]Generating 30s normal baseline...[/cyan]")

    baseline = await generate_normal_traffic(TARGET_HTTP, 30, 5)

    console.print("[cyan]Generating 30s attack traffic...[/cyan]")
    attack = await http_get_flood(TARGET_HTTP, 100, 30)

    table = Table(title="Traffic Pattern Comparison", box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Normal Traffic")
    table.add_column("Attack Traffic")

    table.add_row("Requests/Minute",
                  str(baseline["average_rpm"]),
                  str(round(attack["actual_rps"] * 60, 1)))
    table.add_row("Pattern", "Human-like (varied paths, delays)", "Automated (same endpoint)")
    table.add_row("IDS Should Flag", "[green]NO[/green]", "[red]YES[/red]")

    console.print(table)

    amplification = round(attack["actual_rps"] * 60 / max(baseline["average_rpm"], 1), 1)
    console.print(f"\n[yellow]Attack amplification:[/yellow] {amplification}x baseline traffic")
    console.print("[green]This difference is what IDS systems (like Sentinel) detect![/green]")


def main():
    console.print(Panel(
        "🛡️  THREATFORGE - DoS SIMULATION DEMO\n"
        "INS Lab - Unit 11 Coverage\n"
        f"Target: Docker Lab ({TARGET_HTTP})",
        style="bold blue"
    ))
    console.print("\n[yellow]⚠️  ETHICAL USE: Testing isolated Docker lab only[/yellow]\n")

    asyncio.run(demo_http_flood())
    console.print("\n" + "─" * 60 + "\n")
    asyncio.run(demo_baseline_vs_attack())

    console.print(Panel(
        "✅ DoS DEMO COMPLETE\n"
        "Covered: HTTP Flood, SYN Flood concept, baseline comparison\n"
        "Syllabus: Unit 11 (DoS/DDoS simulation)",
        style="bold green"
    ))


if __name__ == "__main__":
    main()
