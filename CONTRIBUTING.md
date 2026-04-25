# Contributing to ThreatForge

Thank you for your interest in contributing to ThreatForge! This document provides guidelines for contributing to this educational security testing framework.

## Code of Conduct

This project is for **educational and authorized security testing only**. All contributions must:
- Be designed for defensive/educational purposes
- Include proper safeguards and warnings
- Never include real exploit code or malware
- Include comprehensive documentation about safe usage

## How to Contribute

### Reporting Bugs

Use GitHub Issues with the bug report template:
- Describe the bug clearly
- Include reproduction steps
- Specify environment details (Python version, OS)
- Include relevant logs or screenshots

### Suggesting Features

Use GitHub Issues with the feature request template:
- Describe the feature and its educational value
- Explain how it helps defensive security
- Note any safety considerations

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes with clear commit messages
4. Add tests for new functionality
5. Ensure all tests pass: `make check`
6. Submit a pull request with detailed description

## Development Setup

```bash
# Clone your fork
git clone https://github.com/your-username/redvector.git
cd redvector

# Run setup script
./scripts/setup.sh

# Or manually:
python -m venv venv
source venv/bin/activate  # Windows: .\venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

## Coding Standards

- Follow PEP 8 style guidelines
- Use type hints where appropriate
- Add docstrings to all public functions and classes
- Keep functions focused and under 50 lines when possible
- Add comprehensive error handling
- Include unit tests for new code

## Safety Requirements

All attack simulation modules must include:
- Rate limiting to prevent real damage
- Target validation (whitelist/checks)
- Clear warnings about authorized use only
- Audit logging of all operations
- Safe defaults (dry-run mode)

## Commit Message Format

Use conventional commits:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Test additions/changes
- `chore:` Maintenance tasks
- `security:` Security-related changes

## Questions?

Open a GitHub Discussion or contact the maintainers.
