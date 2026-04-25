#!/usr/bin/env python3
"""
scripts/demo_crypto.py

Week 1 Demo Script - Cryptanalysis Module

Run this to demonstrate all cipher attacks for your professor.

Usage: python scripts/demo_crypto.py

This script shows:
1. Caesar cipher attack (brute force + frequency)
2. Vigenere cipher attack (Kasiski examination)
3. Rail Fence attack
4. RSA factorization attack
"""

import sys
import os
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from threatforge.core.crypto_attacks.caesar import encrypt_caesar, run_full_caesar_analysis
from threatforge.core.crypto_attacks.vigenere import encrypt_vigenere, kasiski_attack
from threatforge.core.crypto_attacks.rail_fence import encrypt_rail_fence, brute_force_rails
from threatforge.core.crypto_attacks.rsa_factor import demo_full_rsa_attack

console = Console()


def demo_caesar():
    console.print(Panel("🔐 DEMO 1: CAESAR CIPHER ATTACK", style="bold red"))

    plaintext = "INFORMATION AND NETWORK SECURITY THREATFORGE DEMONSTRATION"
    key = 13

    console.print(f"\n[yellow]Original:[/yellow] {plaintext}")
    encrypted = encrypt_caesar(plaintext, key)
    console.print(f"[red]Encrypted (key={key}):[/red] {encrypted}")

    console.print("\n[cyan]Running brute force + frequency analysis...[/cyan]")
    time.sleep(0.5)

    result = run_full_caesar_analysis(encrypted)

    console.print(f"\n[green]✅ Key Found:[/green] {result['final_answer']['key']}")
    console.print(f"[green]✅ Decrypted:[/green] {result['final_answer']['decrypted']}")
    console.print(f"[green]✅ Confidence:[/green] {result['final_answer']['confidence']}")
    console.print(f"[green]✅ Time Taken:[/green] {result['brute_force']['time_taken_ms']}ms")
    console.print(f"[green]✅ Methods Agree:[/green] {result['methods_agree']}")


def demo_vigenere():
    console.print(Panel("🔤 DEMO 2: VIGENERE CIPHER ATTACK (Kasiski)", style="bold red"))

    plaintext = "THE SECURITY OF A CRYPTOGRAPHIC SYSTEM SHOULD NOT DEPEND ON THE SECRECY OF THE ALGORITHM BUT ONLY ON THE SECRECY OF THE KEY THIS IS KERCKHOFFS PRINCIPLE"
    key = "CYBER"

    console.print(f"\n[yellow]Key Used:[/yellow] {key}")
    encrypted = encrypt_vigenere(plaintext, key)
    console.print(f"[red]Ciphertext:[/red] {encrypted[:60]}...")

    console.print("\n[cyan]Running Kasiski examination...[/cyan]")
    time.sleep(1)

    result = kasiski_attack(encrypted)
    best = result["best_result"]

    console.print(f"\n[green]✅ Key Found:[/green] {best['key_found'] if best else 'Not found'}")
    console.print(f"[green]✅ Score:[/green] {best['overall_score'] if best else 0}")
    console.print(f"[green]✅ Repeated Sequences:[/green] {result['repeated_sequences_found']}")
    console.print(f"[green]✅ Time Taken:[/green] {result['time_taken_ms']}ms")


def demo_rsa():
    console.print(Panel("🔑 DEMO 3: RSA SMALL PRIME FACTORIZATION", style="bold red"))

    console.print("\n[cyan]Generating small RSA key pair and attacking...[/cyan]")
    time.sleep(0.5)

    result = demo_full_rsa_attack()
    scenario = result["demo_scenario"]
    attack = result["attack"]

    console.print(f"\n[yellow]Public Key n:[/yellow] {scenario['public_key']['n']}")
    console.print(f"[yellow]Public Key e:[/yellow] {scenario['public_key']['e']}")
    console.print(f"[yellow]Ciphertext:[/yellow] {scenario['ciphertext']}")
    console.print(f"[yellow]Original Message:[/yellow] {scenario['original_message']}")

    console.print("\n[cyan]Attack Steps:[/cyan]")
    for step in attack.get("steps", []):
        console.print(f"  Step {step['step']}: {step['description']}")
        if "result" in step:
            console.print(f"    → Result: {step['result']}")

    console.print(f"\n[green]✅ Attack Success:[/green] {attack['success']}")
    console.print(f"[green]✅ Recovered Message:[/green] {attack.get('decrypted_value')}")
    console.print(f"[green]✅ Time:[/green] {attack['time_taken_ms']}ms")


def main():
    console.print(Panel(
        "🛡️  THREATFORGE - CRYPTANALYSIS MODULE DEMO\n"
        "Academic Security Testing Framework\n"
        "INS Lab - TE7947",
        style="bold blue"
    ))

    console.print("\n[yellow]⚠️  ETHICAL USE:[/yellow] All testing on controlled lab environments only\n")

    demo_caesar()
    console.print("\n" + "─" * 60 + "\n")

    demo_vigenere()
    console.print("\n" + "─" * 60 + "\n")

    demo_rsa()

    console.print(Panel(
        "✅ DEMO COMPLETE\n"
        "All cipher attacks demonstrated successfully.\n"
        "Full API available at: http://localhost:9000/docs",
        style="bold green"
    ))


if __name__ == "__main__":
    main()
