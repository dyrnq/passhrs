BINARY_NAME := passhrs
TARGET_DIR := target/release

# Default target
.PHONY: all
all: build

# Build
.PHONY: build
build:
	cargo build --release

# Check
.PHONY: fmt clippy check
fmt:
	cargo fmt --all -- --check

fmt-fix:
	cargo fmt --all

clippy:
	cargo clippy --all-targets -- -D warnings

check: fmt clippy build

# Test
.PHONY: test
test:
	cargo test --release

# Integration test (rebuilds Docker SSH container)
.PHONY: test-integration
test-integration: docker-start
	cargo test --release -- --include-ignored

test-all: test test-integration

# CI (full pipeline)
.PHONY: ci
ci: check test test-integration

# Run
.PHONY: run
run:
	cargo run --release -- $(ARGS)

# Clean
.PHONY: clean
clean:
	cargo clean
	rm -rf target/

# Dev helpers
.PHONY: doc
doc:
	cargo doc --no-deps --open

.PHONY: update
update:
	cargo update

# Docker SSH container for integration tests (Alpine-based, TCP forwarding enabled)
.PHONY: docker-start docker-stop docker-restart docker-status

DOCKER_SSH_IMAGE := phr-test-ssh-image
DOCKER_SSH_NAME := phr-test-ssh
DOCKER_SSH_PORT := 22222

docker-start:
	@echo "Building Docker SSH container for integration tests..."
	docker build -t $(DOCKER_SSH_IMAGE) tests/container/
	@docker rm -f $(DOCKER_SSH_NAME) 2>/dev/null || true
	docker run -d --name $(DOCKER_SSH_NAME) -p $(DOCKER_SSH_PORT):22 $(DOCKER_SSH_IMAGE)
	@sleep 2
	@echo "Container $(DOCKER_SSH_NAME) ready on port $(DOCKER_SSH_PORT)"

docker-stop:
	docker stop $(DOCKER_SSH_NAME) 2>/dev/null || true
	docker rm $(DOCKER_SSH_NAME) 2>/dev/null || true

docker-restart: docker-stop docker-start

docker-status:
	@docker ps --filter name=$(DOCKER_SSH_NAME) --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"

# Cross-compile helpers (requires cross)
.PHONY: cross-linux-musl cross-linux-arm cross-win cross-mac

cross-linux-musl:
	cross build --release --target x86_64-unknown-linux-musl

cross-linux-arm:
	cross build --release --target aarch64-unknown-linux-gnu

cross-win:
	cargo build --release --target x86_64-pc-windows-msvc

# Release: simulate the CI build matrix locally
.PHONY: release-simulate
release-simulate:
	@echo "=== Release simulation ==="
	cargo build --release
	@echo "Binary: $(TARGET_DIR)/$(BINARY_NAME)"
	@ls -lh $(TARGET_DIR)/$(BINARY_NAME)
	@file $(TARGET_DIR)/$(BINARY_NAME) 2>/dev/null || true

# Info
.PHONY: info
info:
	@echo "$(BINARY_NAME) - SSH automation tool (russh-based)"
	@echo "Target:  $(shell rustc -vV | grep host | cut -d' ' -f2)"
	@echo "Binary:  $(TARGET_DIR)/$(BINARY_NAME)"

.DEFAULT_GOAL := all
