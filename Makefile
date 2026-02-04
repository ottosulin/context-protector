.PHONY: help install install-dev install-local build test lint lint-fix typecheck check smoke-test clean

help:
	@echo "Context Protector - Development Commands"
	@echo ""
	@echo "Setup:"
	@echo "  make install        Install dependencies"
	@echo "  make install-dev    Install with dev dependencies"
	@echo "  make install-local  Install Python + OpenCode plugin locally for testing"
	@echo ""
	@echo "Development:"
	@echo "  make test         Run tests"
	@echo "  make lint         Run linter"
	@echo "  make lint-fix     Auto-fix lint issues"
	@echo "  make typecheck    Run type checker"
	@echo "  make check        Run all checks (test + lint + typecheck)"
	@echo ""
	@echo "Build:"
	@echo "  make build        Build wheel package"
	@echo "  make clean        Remove build artifacts"
	@echo ""
	@echo "Testing:"
	@echo "  make smoke-test   Quick smoke test with sample input"

# Setup
install:
	uv sync

install-dev:
	uv sync --all-groups

# Install both Python tool and OpenCode plugin locally for testing
install-local:
	@echo "Installing Python package as global tool..."
	uv tool install --force --editable .
	@echo "Building and linking OpenCode plugin..."
	cd opencode-plugin && npm install && npm run build && npm link
	@echo ""
	@echo "Done! Both packages installed locally."
	@echo "  - Python: context-protector (global tool, editable)"
	@echo "  - npm: opencode-context-protector (linked)"

# Development
test:
	uv run pytest tests/ -v --ignore=tests/test_llama_firewall.py --ignore=tests/test_nemo_guardrails.py --ignore=tests/test_gcp_model_armor.py --ignore=tests/test_apriel_guard.py

test-all:
	uv run pytest tests/ -v

lint:
	uv run ruff check src tests

lint-fix:
	uv run ruff check src tests --fix

typecheck:
	uv run mypy src

check: test lint typecheck
	@echo "All checks passed!"

# Build
build:
	uv build

# Testing
smoke-test:
	PYTHONPATH=src python3 scripts/smoke_test_check_mode.py

# Cleanup
clean:
	rm -rf dist/ build/ *.egg-info/ src/*.egg-info/
	rm -rf .pytest_cache/ .mypy_cache/ .ruff_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
