# Ethical Use Statement

## Project Purpose

ThreatForge is an **academic security testing framework** developed as part 
of the Information and Network Security course. Its purpose is:

1. **Educational**: Demonstrate how attacks function so defenders can build 
   better defenses
2. **Validation**: Test defensive systems (IDS, WAFs, firewalls) under 
   controlled conditions
3. **Research**: Provide reproducible attack patterns for security research

## Authorized Use Only

This framework MUST ONLY be used against:

✅ **Allowed Targets**:
- Systems you personally own
- Isolated Docker/VM lab environments  
- Systems with written authorization for testing
- Intentionally vulnerable training apps (DVWA, WebGoat, Metasploitable)

❌ **PROHIBITED**:
- Production systems without authorization
- Third-party websites or services
- Public infrastructure
- Any system where you lack explicit permission

## Built-in Safeguards

ThreatForge includes:

1. **Target Whitelisting** (`utils/ethics.py`): Refuses to attack non-whitelisted IPs
2. **Rate Limiting**: Maximum traffic rates capped to prevent real damage
3. **Synthetic Payloads**: No real exploit code, only pattern generation
4. **Audit Logging**: Every attack logged with timestamp and target
5. **Lab Isolation**: Designed for Docker/VM environments only

## Legal Disclaimer

The author and contributors assume **no liability** for misuse of this 
framework. Users are solely responsible for ensuring their use complies 
with all applicable laws including:

- Computer Fraud and Abuse Act (USA)
- IT Act 2000 (India)
- General Data Protection Regulation (EU)
- Local cybersecurity legislation

**By using ThreatForge, you agree to these terms.**

## Reporting Concerns

If you discover misuse, security issues, or have concerns:
- Email: [your.email@symbiosis.ac.in]
- File a GitHub issue with [SECURITY] tag

## Academic Context

Submitted as part of **TE7947 - Information and Network Security Lab**  
Symbiosis Institute of Technology  
Academic Year 2025-2026

This project is graded on offensive technique implementation, NOT on real-world 
attack execution.
