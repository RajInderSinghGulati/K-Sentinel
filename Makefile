# ══════════════════════════════════════════════════════════════════════════════
# K-Sentinel — Kernel-Space Security Sentinel
# Makefile — Build System
#
# Targets:
#   make bpf        — Compile eBPF kernel-space programs (Linux only)
#   make skeleton   — Generate BPF skeleton headers (Linux only)
#   make agent      — Compile user-space agent (Linux only)
#   make canary     — Deploy honeyfiles
#   make test       — Run all tests
#   make dashboard  — Open dashboard in browser
#   make clean      — Remove build artifacts
#   make all        — Build everything (Linux only)
#
# Usage on macOS:
#   This Makefile detects the OS and restricts targets accordingly.
#   On macOS, only canary, test-detection, test-canary, and dashboard work.
#   For full builds, use `make all` inside the Lima VM.
# ══════════════════════════════════════════════════════════════════════════════

# ── Detect OS ─────────────────────────────────────────────────────────────────
UNAME_S := $(shell uname -s)

# ── Toolchain ─────────────────────────────────────────────────────────────────
CLANG      ?= clang
LLC        ?= llc
CC         ?= gcc
BPFTOOL    ?= bpftool
PYTHON     ?= python3

# ── Directories ───────────────────────────────────────────────────────────────
SRC_DIR     = src
BPF_DIR     = $(SRC_DIR)/bpf
AGENT_DIR   = $(SRC_DIR)/agent
INCLUDE_DIR = $(SRC_DIR)/include
CANARY_DIR  = $(SRC_DIR)/canary
TEST_DIR    = tests
BUILD_DIR   = build
OBJ_DIR     = $(BUILD_DIR)/obj
SKEL_DIR    = $(BUILD_DIR)/skel

# ── Output ────────────────────────────────────────────────────────────────────
BPF_OBJ     = $(BUILD_DIR)/ksentinel.bpf.o
SKEL_HEADER = $(SKEL_DIR)/ksentinel.skel.h
AGENT_BIN   = $(BUILD_DIR)/ksentinel-agent

# ── Source Files ──────────────────────────────────────────────────────────────
BPF_SRC     = $(BPF_DIR)/ksentinel.bpf.c
AGENT_SRCS  = $(AGENT_DIR)/main.c \
              $(AGENT_DIR)/event_handler.c \
              $(AGENT_DIR)/detection_engine.c \
              $(AGENT_DIR)/response_engine.c
AGENT_HDRS  = $(AGENT_DIR)/event_handler.h \
              $(AGENT_DIR)/detection_engine.h \
              $(AGENT_DIR)/response_engine.h \
              $(INCLUDE_DIR)/ksentinel_common.h \
              $(INCLUDE_DIR)/ksentinel_events.h

# ── Compiler Flags ────────────────────────────────────────────────────────────
# BPF compilation flags
BPF_CFLAGS  = -g -O2 -target bpf \
              -D__TARGET_ARCH_$(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/') \
              -I$(INCLUDE_DIR) \
              -I$(BPF_DIR)

# Agent compilation flags
AGENT_CFLAGS = -Wall -Wextra -Werror -Wno-stringop-truncation -O2 -g \
               -I$(INCLUDE_DIR) \
               -I$(SKEL_DIR)
AGENT_LDFLAGS = -lbpf -lelf -lz -lm

# macOS agent flags (no BPF, for testing detection engine standalone)
MAC_CFLAGS   = -Wall -Wextra -O2 -g \
               -I$(INCLUDE_DIR)
MAC_LDFLAGS  = -lm

# ── Architecture Detection ───────────────────────────────────────────────────
ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
    VMLINUX_ARCH = x86
else ifeq ($(ARCH),aarch64)
    VMLINUX_ARCH = arm64
else
    VMLINUX_ARCH = $(ARCH)
endif

# ══════════════════════════════════════════════════════════════════════════════
# Targets
# ══════════════════════════════════════════════════════════════════════════════

.PHONY: all bpf skeleton agent canary test test-detection test-canary \
        dashboard clean help vmlinux dirs demo

# ── Default Target ────────────────────────────────────────────────────────────
ifeq ($(UNAME_S),Linux)
all: dirs bpf skeleton agent
	@echo ""
	@echo "══════════════════════════════════════════════════════════════"
	@echo " K-Sentinel build complete!"
	@echo " Binary: $(AGENT_BIN)"
	@echo "══════════════════════════════════════════════════════════════"
else
all:
	@echo "══════════════════════════════════════════════════════════════"
	@echo " K-Sentinel — macOS detected"
	@echo ""
	@echo " Quick 40% Milestone Demo:"
	@echo "   make demo             — Run full interactive 40% demonstration"
	@echo ""
	@echo " Other available targets:"
	@echo "   make test-detection   — Test detection engine (macOS OK)"
	@echo "   make test-canary      — Test canary manager (macOS OK)"
	@echo "   make dashboard        — Open monitoring dashboard"
	@echo ""
	@echo " For full build, run inside Lima VM:"
	@echo "   limactl shell ebpf-dev"
	@echo "   cd /Users/$(USER)/Downloads/Cybersec_Proj/K-Sentinel"
	@echo "   make all"
	@echo "══════════════════════════════════════════════════════════════"
endif

# ── Create build directories ─────────────────────────────────────────────────
dirs:
	@mkdir -p $(BUILD_DIR) $(OBJ_DIR) $(SKEL_DIR)

# ── Generate vmlinux.h ───────────────────────────────────────────────────────
vmlinux: dirs
ifeq ($(UNAME_S),Linux)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(BPF_DIR)/vmlinux.h
	@echo "Generated vmlinux.h from running kernel"
else
	@echo "ERROR: vmlinux.h can only be generated on Linux"
	@exit 1
endif

# ── Compile eBPF programs ────────────────────────────────────────────────────
bpf: dirs
ifeq ($(UNAME_S),Linux)
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $(BPF_OBJ)
	@echo "Compiled eBPF program: $(BPF_OBJ)"
else
	@echo "ERROR: eBPF compilation requires Linux"
	@exit 1
endif

# ── Generate BPF skeleton ────────────────────────────────────────────────────
skeleton: bpf
ifeq ($(UNAME_S),Linux)
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $(SKEL_HEADER)
	@echo "Generated skeleton: $(SKEL_HEADER)"
else
	@echo "ERROR: Skeleton generation requires Linux"
	@exit 1
endif

# ── Compile user-space agent ─────────────────────────────────────────────────
agent: skeleton
ifeq ($(UNAME_S),Linux)
	$(CC) $(AGENT_CFLAGS) -D__linux__ $(AGENT_SRCS) -o $(AGENT_BIN) $(AGENT_LDFLAGS)
	@echo "Compiled agent: $(AGENT_BIN)"
else
	@echo "ERROR: Full agent compilation requires Linux"
	@exit 1
endif

# ── macOS-compatible test binary (detection engine only) ─────────────────────
test-detection: dirs
	$(CC) $(MAC_CFLAGS) \
		$(TEST_DIR)/test_detection_engine.c \
		$(AGENT_DIR)/detection_engine.c \
		-o $(BUILD_DIR)/test_detection_engine \
		$(MAC_LDFLAGS)
	@echo "Running detection engine tests..."
	@$(BUILD_DIR)/test_detection_engine

# ── Canary manager tests ─────────────────────────────────────────────────────
test-canary:
	$(PYTHON) -m pytest $(TEST_DIR)/test_canary_manager.py -v

# ── Run all available tests ──────────────────────────────────────────────────
test: test-detection test-canary
	@echo "All tests passed!"

# ── Deploy honeyfiles ─────────────────────────────────────────────────────────
canary:
	$(PYTHON) $(CANARY_DIR)/canary_manager.py deploy -c $(CANARY_DIR)/canary_config.yaml

# ── 40% Milestone Interactive Demo ──────────────────────────────────────────
demo:
	@chmod +x scripts/demo-40percent.sh
	@./scripts/demo-40percent.sh

# ── Open dashboard in browser ─────────────────────────────────────────────────
dashboard:
ifeq ($(UNAME_S),Darwin)
	open dashboard/index.html
else
	xdg-open dashboard/index.html 2>/dev/null || echo "Open dashboard/index.html in your browser"
endif

# ── Clean build artifacts ─────────────────────────────────────────────────────
clean:
	rm -rf $(BUILD_DIR)
	@echo "Build artifacts cleaned"

# ── Help ──────────────────────────────────────────────────────────────────────
help:
	@echo "K-Sentinel Build System"
	@echo "═══════════════════════"
	@echo ""
	@echo "Linux targets (inside Lima VM):"
	@echo "  make all            Build everything (eBPF + agent)"
	@echo "  make bpf            Compile eBPF kernel programs"
	@echo "  make skeleton       Generate BPF skeleton headers"
	@echo "  make agent          Compile user-space agent"
	@echo "  make vmlinux        Generate vmlinux.h from kernel"
	@echo ""
	@echo "Cross-platform targets:"
	@echo "  make test           Run all tests"
	@echo "  make test-detection Test detection engine (macOS OK)"
	@echo "  make test-canary    Test canary manager (macOS OK)"
	@echo "  make canary         Deploy honeyfiles"
	@echo "  make dashboard      Open monitoring dashboard"
	@echo "  make clean          Remove build artifacts"
	@echo "  make help           Show this message"
