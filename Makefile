.PHONY: dev build test lint fmt fmt-fix tidy clean ci doc license-check tracing-leak-check post-build install uninstall

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

# ---------------------------------------------------------------------
# AU07.A — system-prefix install layout.
#
# Standard PREFIX / DESTDIR conventions. `make install` after `make
# build` places:
#
#   $(DESTDIR)$(PREFIX)/bin/shit
#   $(DESTDIR)$(PREFIX)/bin/shitd
#   $(DESTDIR)$(PREFIX)/bin/shit-helper
#   $(DESTDIR)$(PREFIX)/lib/shit/libshit_preload_shim.{so,dylib}
#
# The shim path matches the canonical detection site in
# `crates/shit/src/doctor/probes/bsd.rs` and the helper's BSD tier
# picker. After install, `shit doctor` on a fresh BSD reports
# `runtime_capture: kqueue+preload`.
#
# Override `PREFIX` for a non-system install (e.g. PREFIX=$HOME/.local
# for unprivileged use). Override `DESTDIR` for staged installs
# (packagers).
# ---------------------------------------------------------------------

PREFIX ?= /usr/local
DESTDIR ?=

# Files we install. Listing them top-level keeps install/uninstall in
# sync. The shim is platform-extension (.so on Linux/BSD, .dylib on
# macOS) and we don't templatize it in make: the recipe shell loop
# below picks whichever extension exists in target/release/, which is
# portable between GNU make and BSD make (neither `ifeq` nor
# `$(shell ...)` work universally across both flavors).
INSTALL_BINS = shit shitd shit-helper

# AU07.A — `install` requires a release build to exist. We don't
# auto-build because operators often want to gate the build step
# (cross-compile, custom RUSTFLAGS, CI artifact transfer); instead
# we error loud if the artifacts are missing.
install:
	@for b in $(INSTALL_BINS); do \
		if [ ! -x "target/release/$$b" ]; then \
			echo "ERROR: target/release/$$b not built — run \`make build\` first" >&2; \
			exit 1; \
		fi; \
	done
	@found=""; \
	for ext in so dylib; do \
		if [ -f "target/release/libshit_preload_shim.$$ext" ]; then \
			found="$$ext"; break; \
		fi; \
	done; \
	if [ -z "$$found" ]; then \
		echo "ERROR: target/release/libshit_preload_shim.{so,dylib} not built — run \`make build\` first" >&2; \
		exit 1; \
	fi; \
	install -d "$(DESTDIR)$(PREFIX)/bin"; \
	install -d "$(DESTDIR)$(PREFIX)/lib/shit"; \
	for b in $(INSTALL_BINS); do \
		echo "  install $(DESTDIR)$(PREFIX)/bin/$$b"; \
		install -m 0755 "target/release/$$b" "$(DESTDIR)$(PREFIX)/bin/$$b"; \
	done; \
	echo "  install $(DESTDIR)$(PREFIX)/lib/shit/libshit_preload_shim.$$found"; \
	install -m 0644 "target/release/libshit_preload_shim.$$found" \
		"$(DESTDIR)$(PREFIX)/lib/shit/libshit_preload_shim.$$found"; \
	echo "installed to $(DESTDIR)$(PREFIX)"; \
	echo ""; \
	echo "Run \`$(DESTDIR)$(PREFIX)/bin/shit doctor\` to verify; the BSD report"; \
	echo "should now show runtime_capture=kqueue+preload."

uninstall:
	@for b in $(INSTALL_BINS); do \
		f="$(DESTDIR)$(PREFIX)/bin/$$b"; \
		if [ -e "$$f" ]; then echo "  rm $$f"; rm -f "$$f"; fi; \
	done
	@for ext in so dylib; do \
		f="$(DESTDIR)$(PREFIX)/lib/shit/libshit_preload_shim.$$ext"; \
		if [ -e "$$f" ]; then echo "  rm $$f"; rm -f "$$f"; fi; \
	done
	@d="$(DESTDIR)$(PREFIX)/lib/shit"; \
		if [ -d "$$d" ] && [ -z "$$(ls -A $$d 2>/dev/null)" ]; then \
			echo "  rmdir $$d"; rmdir "$$d"; \
		fi
	@echo "uninstalled from $(DESTDIR)$(PREFIX)"
