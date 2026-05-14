# Ethical Use Statement

## Project Purpose

ThreatForge is an academic and research-oriented security testing framework. Its intended use is:

1. Education: help students and defenders understand how attack workflows behave.
2. Validation: test whether a defensive system detects or blocks suspicious behavior.
3. Research: produce reproducible local attack traffic for measurement and comparison.

## Authorized Use Only

Use ThreatForge only against:

- Systems you personally own
- Isolated Docker or VM lab environments
- Systems you have explicit written authorization to test
- Intentionally vulnerable training applications

Do not use ThreatForge against:

- Production systems without authorization
- Third-party services
- Public infrastructure
- Any environment where you do not have explicit permission

## Built-In Safeguards

ThreatForge is designed to encourage safer experimentation:

1. Target allow-listing is enforced in API routes for local lab use.
2. Rate limits are used in simulation modules to reduce risk.
3. The framework is oriented around synthetic demonstrations and validation workflows.
4. The default setup is a local Docker lab, not an internet-facing target list.

## Legal Disclaimer

The author and contributors provide this project as-is and assume no liability for misuse. You are responsible for ensuring your use complies with all applicable laws, policies, and authorization requirements.

By using ThreatForge, you agree to use it only in lawful, authorized, and controlled environments.

## Reporting Concerns

If you discover a safety concern or vulnerability:

- Use the process described in [SECURITY.md](SECURITY.md) for sensitive reports.
- Use GitHub issues only for non-sensitive questions or documentation improvements.

## Academic Context

ThreatForge originated as part of an Information and Network Security lab project and is now being prepared for open-source use. That academic origin does not change the requirement for authorized, lawful use.
