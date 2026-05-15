.PHONY: dev build test lint fmt fmt-fix tidy clean ci doc license-check

dev:
	cargo build --workspace

build:
	cargo build --workspace --release

test:
	cargo test --workspace

lint:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

fmt:
	cargo fmt --all -- --check

fmt-fix:
	cargo fmt --all

license-check:
	cargo run --quiet --package xtask -- license-check

tidy:
	cargo update --workspace

doc:
	cargo doc --workspace --no-deps

clean:
	cargo clean

ci: fmt license-check lint test build
