SHELL := /usr/bin/env bash
.PHONY: test lint deny

TEST_OPTS ?= --all-features --all-targets

test:
	@echo "Running tests with options: $(TEST_OPTS)"
	@cargo test $(TEST_OPTS)

lint:
	@echo "Running linter"
	@cargo clippy --all-targets --all-features -- -D warnings
	@cargo fmt --check

deny:
	@echo "Running cargo-deny"
	@cargo deny check --hide-inclusion-graph
