# Makefile for ThreatForge Development Workflow

.PHONY: help install dev-install test test-unit test-integration lint format clean docker docker-down docker-build run lab check

help:
	@echo "ThreatForge Development Commands"
	@echo "================================"
	@echo "install       - Install production dependencies"
	@echo "dev-install   - Install development dependencies"
	@echo "test          - Run all tests with coverage"
	@echo "test-unit     - Run unit tests"
	@echo "test-integration - Run integration tests"
	@echo "lint          - Run ruff and mypy"
	@echo "format        - Format code with ruff and black"
	@echo "clean         - Remove cache and build artifacts"
	@echo "docker        - Start Docker lab containers"
	@echo "docker-down   - Stop Docker lab containers"
	@echo "docker-build  - Rebuild Docker lab containers"
	@echo "run           - Start the FastAPI server"
	@echo "lab           - Alias for docker"
	@echo "check         - Run lint and tests"

install:
	pip install -r requirements.txt

dev-install: install
	pip install -r requirements-dev.txt

test:
	pytest -v --cov=threatforge --cov-report=term-missing

test-unit:
	pytest tests/unit -v

test-integration:
	pytest tests/integration -v

lint:
	ruff check threatforge tests
	mypy threatforge

format:
	ruff format threatforge tests
	black threatforge tests

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ *.egg-info/ 2>/dev/null || true

docker:
	docker compose up -d

docker-down:
	docker compose down

docker-build:
	docker compose build

run:
	uvicorn threatforge.main:app --reload --port 9000

lab: docker

check: lint test
	@echo "All checks passed!"
