#!/bin/bash
# setup_structure.sh - Creates ThreatForge folder structure

echo "Creating ThreatForge project structure..."

# Main directories
mkdir -p threatforge/{core,api,validation,utils}
mkdir -p threatforge/core/{crypto_attacks,recon,dos_simulation,traffic_patterns,analyzer}
mkdir -p dashboard/src/{components,hooks,pages,styles}
mkdir -p dashboard/public
mkdir -p tests/{unit,integration,fixtures}
mkdir -p tests/fixtures/sample_pcaps
mkdir -p docs/images
mkdir -p scripts
mkdir -p reports/attack_logs
mkdir -p lab/{nginx,http_target}
mkdir -p academic/screenshots

# Python __init__.py files
touch threatforge/__init__.py
touch threatforge/core/__init__.py
touch threatforge/core/crypto_attacks/__init__.py
touch threatforge/core/recon/__init__.py
touch threatforge/core/dos_simulation/__init__.py
touch threatforge/core/traffic_patterns/__init__.py
touch threatforge/core/analyzer/__init__.py
touch threatforge/api/__init__.py
touch threatforge/validation/__init__.py
touch threatforge/utils/__init__.py
touch tests/__init__.py
touch tests/unit/__init__.py
touch tests/integration/__init__.py

# Placeholder files
touch reports/.gitkeep
touch README.md ETHICS.md LICENSE .gitignore
touch requirements.txt requirements-dev.txt
touch docker-compose.yml pyproject.toml

echo "✅ Structure created successfully!"
tree -L 3 -d