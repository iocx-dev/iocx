# ===========================
# Project Configuration
# ===========================
VENV := .venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip
PACKAGE := iocx

# Stamp files to avoid repeated work
STAMP_VENV := .venv.created
STAMP_INSTALL := .venv.installed
STAMP_DEV := .venv.devtools

# Tests
PYTEST := pytest
INTEGRATION_DIR := tests/integration

.PHONY: activate
activate:
	@echo "Run: source .venv/bin/activate"

# ===========================
# Help
# ===========================
.PHONY: help
help:
	@echo ""
	@echo "Available commands:"
	@echo "  make venv        Create virtual environment (only once)"
	@echo "  make install     Install package in editable mode"
	@echo "  make dev         Install dev tools (pytest, ruff, black)"
	@echo "  make test        Run test suite"
	@echo "  make lint        Run ruff linter"
	@echo "  make format      Auto-format with black"
	@echo "  make run         Run CLI tool"
	@echo "  make clean       Remove build artifacts"
	@echo "  make dist        Build wheel + sdist"
	@echo "  make reset       Delete venv and reinstall everything"
	@echo ""


# ===========================
# Virtual Environment
# ===========================
$(STAMP_VENV):
	python3 -m venv $(VENV)
	@touch $(STAMP_VENV)
	@echo "Virtual environment created at $(VENV)"

venv: $(STAMP_VENV)


# ===========================
# Install Package
# ===========================
$(STAMP_INSTALL): venv
	$(PIP) install -e .
	@touch $(STAMP_INSTALL)
	@echo "Package installed in editable mode"

install: $(STAMP_INSTALL)


# ===========================
# Development Tools
# ===========================
$(STAMP_DEV): install
	$(PIP) install pytest ruff black coverage
	@touch $(STAMP_DEV)
	@echo "Development tools installed"

dev: $(STAMP_DEV)


# ===========================
# Testing
# ===========================
.PHONY: test
test: dev
	$(PYTHON) -m pytest -q -m "not integration"

# ----------------------------------------
# Integration tests only
# ----------------------------------------
.PHONY: test-integration
test-integration: dev
	@echo "Running integration tests..."
	$(PYTEST) -m integration $(INTEGRATION_DIR)

# ----------------------------------------
# Tests with coverage
# ----------------------------------------
.PHONY: test-coverage
test-coverage: dev
	$(PYTHON) -m coverage run -m pytest
	$(PYTHON) -m coverage report -m

# ===========================
# Linting & Formatting
# ===========================
.PHONY: lint
lint: dev
	$(VENV)/bin/ruff check $(PACKAGE)

.PHONY: format
format: dev
	$(VENV)/bin/black $(PACKAGE)


# ===========================
# Run CLI
# ===========================
.PHONY: run
run: install
	$(PYTHON) -m $(PACKAGE).cli.main $(ARGS)


# ===========================
# Build Distribution
# ===========================
.PHONY: dist
dist: install
	$(PYTHON) -m build


# ===========================
# Clean
# ===========================
.PHONY: clean
clean:
	rm -rf build dist *.egg-info
	find . -name "__pycache__" -type d -exec rm -rf {} +
	@echo "Cleaned build artifacts"


# ===========================
# Reset Everything
# ===========================
.PHONY: reset
reset:
	rm -rf $(VENV)
	rm -f $(STAMP_VENV) $(STAMP_INSTALL) $(STAMP_DEV)
	make dev

# ===========================
# Go Toolchain Check
# ===========================

.PHONY: check-go
check-go:
	@command -v go >/dev/null 2>&1 || { \
        echo "Error: Go is not installed or not on PATH."; \
        echo "Install it with: sudo apt install golang-go"; \
        exit 1; \
	}

# ===========================
# Synthetic Sample Generation
# ===========================

GENERATOR_SCRIPTS := $(filter-out %/__init__.py, $(wildcard examples/generators/**/*.py))
SAMPLES := $(patsubst examples/generators/%.py, examples/samples/exe/%.exe, $(GENERATOR_SCRIPTS))

.PHONY: samples
samples: $(SAMPLES)
	@echo "All synthetic samples generated."

examples/samples/exe/%.exe: examples/generators/%.py
	@mkdir -p examples/samples/exe
	$(PYTHON) $< $@
	@echo "Generated sample: $@"

.PHONY: clean-samples
clean-samples:
	rm -rf examples/samples/exe
	@echo "Removed all synthetic samples."

