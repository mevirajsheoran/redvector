# Contributing to ThreatForge

Thanks for helping improve ThreatForge.

This repository is open source, but it is also a security-focused project. Every contribution should improve the codebase without weakening the safety, clarity, or educational framing of the project.

## Ground Rules

Contributions should:

- Support authorized testing, education, or defense validation
- Preserve or improve built-in safeguards
- Avoid adding malware, persistence tooling, or real-world exploit payloads
- Include documentation and tests when behavior changes

## Development Setup

```bash
git clone https://github.com/mevirajsheoran/redvector.git
cd redvector

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt
pip install -r requirements-dev.txt
```

Frontend setup:

```bash
cd dashboard
npm install
```

## Common Commands

Run these from the repository root:

```bash
make test
make lint
make format
docker compose up -d
```

If you are working on the API:

```bash
uvicorn threatforge.main:app --reload --port 9000
```

If you are working on the dashboard:

```bash
cd dashboard
npm run dev -- --host --port 5173
```

## Pull Requests

1. Fork the repository.
2. Create a topic branch.
3. Make the smallest focused change that solves the problem.
4. Add or update tests when behavior changes.
5. Run the relevant checks before opening the PR.
6. Explain the motivation, scope, and any safety implications in the PR description.

## Commit Style

Conventional commits are preferred:

- `feat:` new functionality
- `fix:` bug fixes
- `docs:` documentation only
- `test:` test changes
- `chore:` maintenance
- `security:` safety or security-related changes

## Safety Review Expectations

Changes touching attack execution, targeting logic, rate limits, or validation logic should include:

- A clear explanation of intended use
- Notes on how misuse risk was considered
- Guardrails or defaults that keep behavior contained
- Tests for any new validation or restriction logic

## Reporting Bugs

When opening an issue, include:

- What you expected
- What happened instead
- Reproduction steps
- Environment details
- Logs, screenshots, or example inputs when useful

For sensitive security reports, use the process in [SECURITY.md](SECURITY.md) instead of opening a public issue.
