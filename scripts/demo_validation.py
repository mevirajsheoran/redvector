#!/usr/bin/env python3
"""
scripts/demo_validation.py

Week 4 Demo Script - Complete ThreatForge vs Sentinel Validation

THIS IS YOUR SHOWSTOPPER DEMO.

Prerequisites:
1. Sentinel/Vigil running: uvicorn Vigil.main:app --port 8000
2. ThreatForge running:    uvicorn threatforge.main:app --port 9000
3. React dashboard:        npm run dev (in dashboard/)

Usage: python scripts/demo_validation.py
"""

import sys
import os
import asyncio
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

from threatforge.validation.sentinel_client import SentinelClient
from threatforge.validation.correlator import AttackCorrelator
from threatforge.validation.matrix_builder import ValidationMatrixBuilder

console = Console()


async def main():
    console.print(Panel(
        "🛡️  THREATFORGE vs SENTINEL - COMPLETE VALIDATION DEMO\n"
        "Scientific proof that Sentinel detects real attacks\n"
        "INS Lab TE7947 - Academic Adversarial Validation",
        style="bold blue"
    ))

    # Step 1: Connect to Sentinel
    console.print("\n[cyan]Step 1: Connecting to Sentinel/Vigil...[/cyan]")
    sentinel = SentinelClient("http://localhost:8000")

    if not sentinel.test_connection():
        console.print("[red]❌ Sentinel not reachable![/red]")
        console.print("[yellow]Start Sentinel with:[/yellow]")
        console.print("  [cyan]uvicorn Vigil.main:app --port 8000 --reload[/cyan]")
        console.print("\n[yellow]Running in SIMULATION MODE (no real Sentinel)[/yellow]")
        return

    console.print("[green]✅ Sentinel connected[/green]")

    # Get baseline stats
    baseline = sentinel.snapshot_stats()
    console.print(f"[green]Baseline:[/green] {baseline.total_requests} total requests, {baseline.block_rate_pct}% block rate")

    # Step 2: Initialize correlator
    correlator = AttackCorrelator(sentinel)
    builder = ValidationMatrixBuilder()

    # Step 3: Run attacks and validate
    tests = [
        ("HTTP Flood (50 RPS, 20s)", correlator.run_http_flood_validation, {"target_url": "http://localhost:8000", "requests_per_second": 50, "duration_seconds": 20}),
        ("Credential Stuffing (5 APS, 20s)", correlator.run_credential_stuffing_validation, {"target_url": "http://localhost:8000", "attempts_per_second": 5, "duration_seconds": 20}),
        ("Enumeration (10 IPS, 20s)", correlator.run_enumeration_validation, {"target_url": "http://localhost:8000", "items_per_second": 10, "duration_seconds": 20}),
    ]

    results = []
    for test_name, test_fn, kwargs in tests:
        console.print(f"\n[yellow]Running: {test_name}...[/yellow]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True
        ) as progress:
            task = progress.add_task(f"Attacking...", total=None)
            result = await test_fn(**kwargs)
            progress.update(task, completed=True)

        results.append(result)
        builder.add_result(result)

        status = "✅ DETECTED" if result.sentinel_detected else "❌ MISSED"
        console.print(f"  Result: [{'green' if result.sentinel_detected else 'red'}]{status}[/]")
        if result.detection_latency_seconds:
            console.print(f"  Latency: {result.detection_latency_seconds:.1f}s")
        console.print(f"  Blocks: {result.blocks_triggered}")

        await asyncio.sleep(2)

    # Step 4: Show results table
    console.print("\n")
    table = Table(title="VALIDATION MATRIX", box=box.DOUBLE_EDGE)
    table.add_column("Test ID", style="cyan")
    table.add_column("Attack Type", style="yellow")
    table.add_column("Sent")
    table.add_column("Detected")
    table.add_column("Latency")
    table.add_column("Block%")
    table.add_column("Confidence")

    for r in results:
        detected_str = "[green]✅ YES[/green]" if r.sentinel_detected else "[red]❌ NO[/red]"
        table.add_row(
            r.test_id,
            r.attack_type,
            str(r.payloads_sent),
            detected_str,
            f"{r.detection_latency_seconds:.1f}s" if r.detection_latency_seconds else "N/A",
            f"{r.block_rate_pct:.1f}%",
            r.detection_confidence
        )

    console.print(table)

    # Step 5: Save matrix
    csv_path = builder.save_csv()
    json_path = builder.save_json()
    metrics = builder.compute_final_metrics()

    console.print(Panel(
        f"[green]✅ VALIDATION COMPLETE[/green]\n\n"
        f"Detection Rate: [bold green]{metrics.get('detection_rate_pct', 0)}%[/bold green]\n"
        f"Avg Block Rate: [bold green]{metrics.get('avg_block_rate_pct', 0)}%[/bold green]\n"
        f"Avg Latency: [bold green]{metrics.get('avg_detection_latency_s', 'N/A')}s[/bold green]\n\n"
        f"CSV saved: {csv_path}\n"
        f"JSON saved: {json_path}\n\n"
        f"[yellow]{metrics.get('report_statement', '')}[/yellow]",
        style="bold green"
    ))


if __name__ == "__main__":
    asyncio.run(main())
