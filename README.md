# 🛡️ ThreatForge

> Offensive Security Testing Framework for Educational Use

## ⚠️ Ethical Use Statement

**ThreatForge is designed exclusively for authorized security testing in 
isolated lab environments.** All offensive techniques must be executed against:
- Systems you own
- Systems you have explicit written permission to test
- Isolated Docker/VM lab environments

Unauthorized use against external systems is illegal and unethical.

## What is ThreatForge?

ThreatForge is a modular adversary emulation platform covering:

- **Cryptanalysis**: Caesar, Vigenère, Rail Fence, RSA factoring
- **Network Reconnaissance**: TCP SYN scanning, OS fingerprinting, banner grabbing
- **DoS Simulation**: HTTP flood, SYN flood, Slowloris (rate-controlled)
- **Traffic Pattern Analysis**: Baseline vs attack traffic generation
- **Defense Validation**: Tests defensive systems (Sentinel/Vigil) for detection efficacy

## Quick Start

```bash
# Activate venv
source venv/bin/activate

# Start test lab
./scripts/start_lab.sh

# Run ThreatForge backend
uvicorn threatforge.main:app --reload --port 9000

# In another terminal, start dashboard
cd dashboard
npm run dev

# Open http://localhost:5173

## Architecture

See [docs/architecture.md](docs/architecture.md) for detailed architecture documentation.

## License

MIT - Educational use only. See [LICENSE](LICENSE) for full terms.

