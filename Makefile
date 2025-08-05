.PHONY: help test-unit clean build-wheel all

ifdef UV_PYTHON
UV_PYTHON := $(UV_PYTHON)
else
UV_PYTHON := "3.12"
endif

help:
	@echo "Main Commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""

install:
	uv venv
	uv pip install \
		--requirements pyproject.toml \
		--extra dev

test-unit:
	. .venv/bin/activate
	uv run pytest tests/unit_tests/ -v

clean:
	rm -rf dist/
	rm -rf __pycache__/
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} +
	$(MAKE) -C tests clean-test

build-wheel:
	uv build

all: test-unit
