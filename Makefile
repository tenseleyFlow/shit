.PHONY: dev build test lint fmt fmt-fix tidy clean ci doc license-check tracing-leak-check

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

# S20.7 — grep guard against tracing calls that interpolate
# secret-bearing fields. See .docs/audits/tracing-leak-audit.md.
tracing-leak-check:
	@if grep -rEn --include='*.rs' \
		'tracing::(debug|info|warn|error|trace)!\([^)]*\<(value|body|sql|env_value|statement_text|raw_block) *= *%' \
		crates/ 2>/dev/null; then \
		echo "S20.7 leak guard: tracing call interpolates a value-bearing field — review and redact"; \
		exit 1; \
	fi
	@if grep -rEn --include='*.rs' \
		'tracing::(debug|info|warn|error|trace)!\([^)]*\<(password|secret) *=' \
		crates/ 2>/dev/null; then \
		echo "S20.7 leak guard: tracing call carries a password/secret field name"; \
		exit 1; \
	fi
	@echo "tracing-leak-check: ok"

tidy:
	cargo update --workspace

doc:
	cargo doc --workspace --no-deps

clean:
	cargo clean

ci: fmt license-check tracing-leak-check lint test build
