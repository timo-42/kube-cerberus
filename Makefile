# Makefile for admission validation project

.PHONY: help test-unit clean build-wheel all

help:  ## Show this help message
	@echo "Main Commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""


test-unit:  ## Run unit tests only (alias for test-unit)
	uv run pytest tests/unit_tests/ -v

clean:  ## Clean up generated files
	rm -rf dist/
	rm -rf __pycache__/
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} +
	$(MAKE) -C tests clean-test

build-wheel:  ## Build Python wheel package
	uv build

# Default target
all: test-unit  ## Run unit tests by default
