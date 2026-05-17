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

# clang flags for BPF compilation:
#   -O2            -- verifier rejects unoptimized code on most kernels
#   -g             -- BTF generation
#   -target bpf    -- emit bpfel-unknown-none
#   -Wall          -- catch obvious mistakes
#   -fno-stack-protector -- BPF has no stack canary support
CFLAGS = -O2 -g -Wall -fno-stack-protector -target bpf

# All sources are .bpf.c; outputs are .bpf.o.
SOURCES = $(wildcard $(SRC_DIR)/*.bpf.c)
OBJECTS = $(patsubst $(SRC_DIR)/%.bpf.c,$(BUILD_DIR)/%.bpf.o,$(SOURCES))

.PHONY: all clean inspect

all: $(OBJECTS)

$(BUILD_DIR)/%.bpf.o: $(SRC_DIR)/%.bpf.c | $(BUILD_DIR)
	$(CLANG) $(CFLAGS) -c $< -o $@

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
