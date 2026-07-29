.PHONY: install lint reformat test-local test-integration

install:
	uv pip install -U -e ".[dev]"

lint:
	uv run ruff check src tests
	uv run ruff format --check src tests
	uv run ty check src tests

reformat:
	uv run ruff format src tests
	uv run ruff check --fix src tests

test-local:
	uv run pytest

test-integration:
	@echo "Integrationstests kommen in einem spaeteren Meilenstein (compose)."
