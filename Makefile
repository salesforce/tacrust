.PHONY: all
all: format build lint test test-server

.PHONY: format
format:
	cargo fmt -- --emit=files

.PHONY: lint
lint:
	cargo clippy --all -- -D warnings

.PHONY: clean
clean:
	cargo clean

.PHONY: build
build:
	cargo build --workspace

.PHONY: build-release
build-release:
	cargo build --release --workspace

.PHONY: test
test:
	cargo test

.PHONY: test-server
test-server:
	cargo test -p tacrustd

.PHONY: run-server
run-server:
	cargo run -p tacrustd

