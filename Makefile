# Makefile for ThreatForge Development Workflow
# =============================================

.PHONY: help install dev-install test lint format clean docker run lab

# Default target
help:
	@echo "ThreatForge Development Commands"
	@echo "================================"
	@echo "install       - Install production dependencies"
	@echo "dev-install   - Install development dependencies"
	@echo "test          - Run all tests with coverage"
	@echo "lint          - Run ruff linter and mypy type checker"
	@echo "format        - Format code with ruff and black"
	@echo "clean         - Remove build artifacts and cache files"
	@echo "docker        - Build and start Docker containers"
	@echo "run           - Start the development server"
	@echo "lab           - Start the test lab environment"

# Installation
install:
	cd backend && pip install -r requirements.txt

dev-install: install
	cd backend && pip install -r requirements-dev.txt

# Testing
test:
	cd backend && pytest -v --cov=threatforge --cov-report=term-missing

test-unit:
	cd backend && pytest tests/unit -v

test-integration:
	cd backend && pytest tests/integration -v

# Code quality
lint:
	cd backend && ruff check threatforge tests
	cd backend && mypy threatforge

format:
	cd backend && ruff format threatforge tests
	cd backend && black threatforge tests

# Cleanup
clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ *.egg-info/ 2>/dev/null || true

# Docker
docker:
	docker-compose up -d

docker-down:
	docker-compose down

docker-build:
	docker-compose build

# Development server
run:
	cd backend && uvicorn threatforge.main:app --reload --port 9000

# Test lab
lab:
	./scripts/start_lab.sh

# All-in-one check before commit
check: lint test
	@echo "✅ All checks passed!"
