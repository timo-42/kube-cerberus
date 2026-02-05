.PHONY: help test-unit test-integration test-integration-setup test-integration-teardown test-all clean build-wheel all

ifdef UV_PYTHON
UV_PYTHON := $(UV_PYTHON)
else
UV_PYTHON := "3.12"
endif

help:
	@echo "Main Commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""

install:  ## Install development dependencies
	uv venv
	uv pip install \
		--requirements pyproject.toml \
		--extra dev

install-integration:  ## Install integration test dependencies
	uv pip install \
		--requirements pyproject.toml \
		--extra integration

test-unit:  ## Run unit tests
	. .venv/bin/activate
	uv run pytest tests/unit_tests/ -v

test-integration-setup:  ## Setup kind cluster for integration tests
	@echo "Setting up kind cluster..."
	@bash tests/integration_tests/scripts/setup_kind.sh

test-integration-teardown:  ## Teardown kind cluster
	@echo "Tearing down kind cluster..."
	@bash tests/integration_tests/scripts/teardown_kind.sh

test-integration:  ## Run integration tests (requires Docker)
	@echo "Running integration tests..."
	@$(MAKE) test-integration-setup
	@echo "Installing integration dependencies..."
	@$(MAKE) install-integration
	@echo "Running tests..."
	uv run pytest tests/integration_tests/ -v -m integration
	@echo "✅ Integration tests complete"
	@echo "💡 Tip: Run 'make test-integration-teardown' to cleanup the kind cluster"

test-all:  ## Run all tests (unit + integration)
	@$(MAKE) test-unit
	@$(MAKE) test-integration

clean:  ## Clean build artifacts
	rm -rf dist/
	rm -rf __pycache__/
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} +
	$(MAKE) -C tests clean-test

build-wheel:  ## Build wheel package
	uv build

all: test-unit
