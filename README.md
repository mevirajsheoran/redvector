# ThreatForge

Offensive security testing framework for authorized penetration testing, lab exercises, and defense validation.

<div align="center">

Built to attack. Designed to prove defense works.

[Quick Start](#quick-start) • [Architecture](#architecture) • [API](#api-reference) • [Contributing](#contributing) • [Ethics](ETHICS.md)

</div>

## Ethical Use Statement

ThreatForge is built for authorized testing only.

Use it only against:

- Systems you own
- Isolated Docker or VM lab environments
- Systems you have explicit written permission to test
- Intentionally vulnerable training targets such as DVWA

Do not use it against:

- Production systems without authorization
- Third-party websites or services
- Public infrastructure
- Any target you do not control or have permission to assess

By using this project, you accept full responsibility for ensuring your work is legal, ethical, and contained. See [ETHICS.md](ETHICS.md) for the full statement.

## What ThreatForge Does

ThreatForge is a modular offensive security framework that helps security students, defenders, and researchers simulate realistic attacks in a controlled environment. It combines:

- Classical cryptanalysis demos
- Network reconnaissance workflows
- Rate-limited DoS simulation
- Validation workflows for defensive systems such as Vigil or Sentinel
- A React dashboard with a terminal-style interface and live updates

The project is meant to answer a practical question: how do you validate that a defensive system actually detects and responds to attack behavior before a real attacker does?

## Feature Overview

| Area | Capabilities |
| --- | --- |
| Cryptanalysis | Caesar, Vigenere, Rail Fence, Hill, and small-key RSA demonstrations |
| Reconnaissance | TCP scanning, UDP scanning, banner grabbing, OS fingerprinting, stealth timing comparisons |
| DoS Simulation | HTTP flood, SYN flood, Slowloris, credential stuffing simulation |
| Defense Validation | Detection and block-rate measurement against Vigil or Sentinel-style middleware |
| Reporting | Validation matrix CSV generation and JSON-friendly outputs |
| Dashboard | React + TypeScript UI with terminal-style monitoring and WebSocket updates |

## Architecture

```text
┌──────────────────────────────────────────────────────────────┐
│                         ThreatForge                         │
├───────────────────────────────┬──────────────────────────────┤
│ React Dashboard               │ FastAPI Backend              │
│ dashboard/                    │ threatforge/                 │
│ - Terminal-style UI           │ - /api/crypto/*             │
│ - Live WebSocket feed         │ - /api/recon/*              │
│ - Attack launcher             │ - /api/dos/*                │
│ - System monitor              │ - /api/validate/*           │
├───────────────────────────────┴──────────────────────────────┤
│ Core modules: crypto_attacks, recon, dos_simulation,        │
│ traffic_patterns, analyzer, validation                      │
├──────────────────────────────────────────────────────────────┤
│ Optional lab + validation targets                           │
│ - Docker lab containers                                     │
│ - Vigil / Sentinel API                                      │
└──────────────────────────────────────────────────────────────┘
```

## Repository Layout

```text
threatforge/
├── threatforge/          # FastAPI app, attack modules, validation logic
├── dashboard/            # React + TypeScript frontend
├── scripts/              # Demo and helper scripts
├── tests/                # Unit and integration tests
├── reports/              # Generated reports (gitkept, report outputs ignored)
├── docker-compose.yml    # Local target lab
├── ETHICS.md             # Ethical use statement
├── CONTRIBUTING.md       # Contribution guide
└── Makefile              # Common development commands
```

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 20+
- Docker
- WSL2 on Windows if you want raw-socket Scapy functionality

Optional tools:

- `nmap` for scan comparisons
- Wireshark for packet inspection

### 1. Clone and Install

```bash
git clone https://github.com/mevirajsheoran/threatforge.git
cd threatforge

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### 2. Start the Lab Targets

```bash
docker compose up -d
docker compose ps
curl http://172.25.0.13/
```

The default Docker lab currently includes:

- `tf_http` at `172.25.0.13`
- `tf_nginx` at `172.25.0.12`
- `tf_dvwa` at `172.25.0.10`

### 3. Start the FastAPI Backend

Standalone mode:

```bash
uvicorn threatforge.main:app --reload --host 0.0.0.0 --port 9000
```

With Vigil or Sentinel-style validation:

```bash
export SENTINEL_URL="http://YOUR_HOST:8000"
uvicorn threatforge.main:app --reload --host 0.0.0.0 --port 9000
```

Verify:

```bash
curl http://localhost:9000/health
curl http://localhost:9000/docs
```

### 4. Start the Dashboard

```bash
cd dashboard
npm install
npm run dev -- --host --port 5173
```

Open `http://localhost:5173`, or use the printed WSL host URL if you are running the frontend inside WSL on Windows.

### 5. Run Demo Scripts

```bash
python scripts/demo_crypto.py
python scripts/demo_recon.py
python scripts/demo_dos.py
python scripts/demo_validation.py
```

## Development Commands

Run these from the repository root:

```bash
make install
make dev-install
make test
make lint
make format
make docker
make run
make lab
```

## API Reference

FastAPI docs are available at `http://localhost:9000/docs` when the backend is running.

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/health` | `GET` | Service health check |
| `/ethics` | `GET` | Ethical use statement |
| `/api/crypto/caesar/demo` | `POST` | Caesar demo and attack |
| `/api/crypto/vigenere/demo` | `POST` | Vigenere demo |
| `/api/crypto/rsa/demo` | `POST` | Small-key RSA factorization demo |
| `/api/recon/scan/tcp` | `POST` | TCP scan |
| `/api/recon/scan/udp` | `POST` | UDP scan |
| `/api/recon/banner` | `POST` | Banner grabbing |
| `/api/recon/os` | `POST` | OS fingerprinting |
| `/api/recon/stealth` | `POST` | Stealth comparison modes |
| `/api/recon/full` | `POST` | Full recon pipeline |
| `/api/dos/http-flood` | `POST` | HTTP flood simulation |
| `/api/dos/slowloris` | `POST` | Slowloris simulation |
| `/api/dos/credential-stuff` | `POST` | Credential stuffing simulation |
| `/api/validate/status` | `GET` | Validation target connectivity |
| `/api/validate/full-suite` | `POST` | Run defense validation suite |
| `/ws/live-feed` | `WebSocket` | Live event stream |

## Tests

```bash
pytest tests/unit -v
pytest tests/unit --cov=threatforge --cov-report=term-missing
pytest tests/integration -v
```

Some integration paths require Docker targets or a running validation service.

## Target Restrictions

ThreatForge includes target allow-listing for reconnaissance and simulation routes. Out of the box it is intended for the local lab and loopback targets. If you need to extend the allow-list for your own authorized environment, update:

- `threatforge/api/recon.py`
- `threatforge/api/dos.py`

Review those changes carefully before using the project outside the bundled lab.

## Open Source Notes

ThreatForge is being published as an educational and research-friendly project. A few expectations are worth calling out:

- The project is alpha-stage and interfaces may still change
- Some modules require elevated privileges for raw socket access
- Validation workflows depend on an external defensive service
- Generated reports and packet captures are intentionally ignored from version control

## Contributing

Contributions are welcome if they improve the project's educational value, safety, reproducibility, or defensive usefulness.

Start here:

- Read [CONTRIBUTING.md](CONTRIBUTING.md)
- Review [ETHICS.md](ETHICS.md)
- Report sensitive issues through [SECURITY.md](SECURITY.md)

## License

This project is licensed under the [MIT License](LICENSE).

The ethics notice in this repository does not replace the license; it defines the intended and expected use of the project.
