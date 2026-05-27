.PHONY: dev build test lint fmt fmt-fix tidy clean ci doc license-check tracing-leak-check post-build

dev:
	cargo build --workspace
	@$(MAKE) --no-print-directory post-build BIN=target/debug/shit-helper

build:
	cargo build --workspace --release
	@$(MAKE) --no-print-directory post-build BIN=target/release/shit-helper

# AU08 — reapply helper file caps stripped by cargo's link step.
# No-op unless SHIT_AUTO_SETCAP=1 is exported (the script's own gate).
# Self-skips on non-Linux uname.
post-build:
	@if [ -x tools/linux/post-build-setcap.sh ] && [ -n "$(BIN)" ]; then \
		bash tools/linux/post-build-setcap.sh "$(BIN)"; \
	fi

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
