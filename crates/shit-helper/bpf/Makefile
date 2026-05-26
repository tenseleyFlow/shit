# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Build the eBPF programs that ship in shit-helper.
#
# Outputs are committed to the repo (under build/) so downstream
# builds don't need clang. Regenerate after editing the .c sources:
#
#     make -C crates/shit-helper/bpf clean all
#
# Requirements:
#   - clang ≥ 14 (clang 21 used during S09 dev)
#   - llvm-objdump (for `make inspect`)
#
# No libbpf / kernel-headers dependency. The programs are written to
# avoid any header use; see src/*.c for the rationale.

CLANG     ?= clang
LLVM_OBJDUMP ?= llvm-objdump

SRC_DIR   = src
BUILD_DIR = build
INCLUDE_DIR = include

# Where libbpf's headers (bpf_helpers.h, bpf_core_read.h, bpf_tracing.h)
# live. On NixOS they're tucked under the kernel-dev nix-store path;
# override via BPF_HELPERS_INCLUDE=/path/to/libbpf/include when
# building from a non-default environment. tools/linux/build-bpf.sh
# sets this for hasu.
BPF_HELPERS_INCLUDE ?= /usr/include

# Two compile profiles:
#   - the legacy noop_tracepoint program uses NO headers / no -g.
#     Kept verbatim to preserve the S09 regression hold (aya 0.13's
#     parser rejects -g-produced BTF on the trivial 2-instruction
#     program).
#   - the L04 LSM hooks include vmlinux.h + libbpf helpers + -g so
#     BTF/CO-RE relocations are emitted. Required for BPF_CORE_READ.
CFLAGS_NOHDR = -O2 -Wall -fno-stack-protector -target bpf
CFLAGS_LSM   = -O2 -g -Wall -fno-stack-protector -target bpf \
               -I$(INCLUDE_DIR) -I$(BPF_HELPERS_INCLUDE)

# Programs that use the LSM compile profile (vmlinux.h + libbpf).
LSM_PROGRAMS = inode_unlink inode_setattr inode_mkdir inode_create inode_rename file_open inode_symlink inode_link inode_rmdir

# All sources are .bpf.c; outputs are .bpf.o.
SOURCES = $(wildcard $(SRC_DIR)/*.bpf.c)
OBJECTS = $(patsubst $(SRC_DIR)/%.bpf.c,$(BUILD_DIR)/%.bpf.o,$(SOURCES))

.PHONY: all clean inspect

all: $(OBJECTS)

# Default rule for legacy header-less programs (noop_tracepoint).
$(BUILD_DIR)/%.bpf.o: $(SRC_DIR)/%.bpf.c | $(BUILD_DIR)
	$(CLANG) $(CFLAGS_NOHDR) -c $< -o $@

# LSM-profile overrides for each L04 program. The double-$$ escapes
# survive one `eval` round so the recipe gets the right substitution.
define LSM_RULE
$(BUILD_DIR)/$(1).bpf.o: $(SRC_DIR)/$(1).bpf.c $(SRC_DIR)/common.h $(INCLUDE_DIR)/vmlinux.h | $(BUILD_DIR)
	$$(CLANG) $$(CFLAGS_LSM) -c $$< -o $$@
endef
$(foreach p,$(LSM_PROGRAMS),$(eval $(call LSM_RULE,$(p))))

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)

# Confirm the resulting ELF has the expected sections + a tiny prog.
inspect: all
	@for o in $(OBJECTS); do \
		echo "==> $$o"; \
		$(LLVM_OBJDUMP) -h $$o | grep -E "tracepoint|lsm|license"; \
		echo "--- disassembly ---"; \
		$(LLVM_OBJDUMP) -d $$o; \
	done
