export CARGO_INCREMENTAL := 0
export RUSTFLAGS := -Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests -Cpanic=abort
export RUSTDOCFLAGS := -Cpanic=abort

.PHONY: all
all: format build lint test

.PHONY: format
format:
	cargo fmt -- --emit=files

.PHONY: lint
lint:
	cargo clippy -- -D warnings

.PHONY: clean
clean:
	cargo clean

.PHONY: build
build:
	cargo build

.PHONY: build-release
build-release:
	cargo build --release

.PHONY: test
test:
	cargo test -- --nocapture --test-threads=1

