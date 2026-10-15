# ALIRT top-level Makefile (v0.5.2)
# Sources live in src/<tool>/; this file only dispatches the builds.
# Usage:
#   make                        build all four kernel modules (native)
#   make mod_hunter             build a single module
#   make clean                  clean all build outputs
#   make help                   list supported platforms and usage examples
#   make KDIR=/path/to/kernel   build against a specific kernel tree
#                               (cross-compilation / testing)
#
# Cross-compilation uses user-friendly platform names; a CROSS_COMPILE
# given on the command line or in the environment overrides the default
# prefix for the platform:
#
#   make ARCH=aarch64 KDIR=/build/linux-6.12
#   make ARCH=armv7 CROSS_COMPILE=arm-none-linux-gnueabihf- KDIR=... mod_hunter

KDIR  ?= /lib/modules/$(shell uname -r)/build
PWD   := $(shell pwd)

TOOLS := mod_hunter process_hunter sock_hunter mod_dumper

# ---- Platform selection ---------------------------------------------------
# ARCH names the *target platform*, not the kernel's internal directory
# name; this table maps it to the kernel ARCH and a default cross prefix.
# Kernel-style names (x86, arm, arm64, mips, powerpc, riscv) are accepted
# too and passed through unchanged. With no ARCH, kbuild infers the
# architecture from the kernel tree itself (native build).
USER_ARCH := $(strip $(ARCH))

ifeq ($(USER_ARCH),)
KBUILD_FLAGS :=
else ifeq ($(USER_ARCH),x86_64)
KARCH := x86
KBUILD_FLAGS := ARCH=$(KARCH)
else ifeq ($(USER_ARCH),armv7)
KARCH := arm
CROSS_COMPILE ?= arm-linux-gnueabihf-
KBUILD_FLAGS := ARCH=$(KARCH) CROSS_COMPILE=$(CROSS_COMPILE)
else ifeq ($(USER_ARCH),aarch64)
KARCH := arm64
CROSS_COMPILE ?= aarch64-linux-gnu-
KBUILD_FLAGS := ARCH=$(KARCH) CROSS_COMPILE=$(CROSS_COMPILE)
else ifeq ($(USER_ARCH),mips)
KARCH := mips
CROSS_COMPILE ?= mips-linux-gnu-
KBUILD_FLAGS := ARCH=$(KARCH) CROSS_COMPILE=$(CROSS_COMPILE)
else ifeq ($(USER_ARCH),powerpc)
KARCH := powerpc
CROSS_COMPILE ?= powerpc64le-linux-gnu-
KBUILD_FLAGS := ARCH=$(KARCH) CROSS_COMPILE=$(CROSS_COMPILE)
else ifeq ($(USER_ARCH),riscv)
KARCH := riscv
CROSS_COMPILE ?= riscv64-linux-gnu-
KBUILD_FLAGS := ARCH=$(KARCH) CROSS_COMPILE=$(CROSS_COMPILE)
else ifneq ($(filter x86 arm arm64 mips powerpc riscv,$(USER_ARCH)),)
# kernel-style ARCH name: pass through, keep any user CROSS_COMPILE
KARCH := $(USER_ARCH)
KBUILD_FLAGS := ARCH=$(KARCH)
ifneq ($(strip $(CROSS_COMPILE)),)
KBUILD_FLAGS += CROSS_COMPILE=$(CROSS_COMPILE)
endif
else
$(error Unsupported ARCH '$(USER_ARCH)'. Supported platforms: x86_64, armv7, aarch64, mips, powerpc, riscv (kernel-style: x86, arm, arm64, mips, powerpc, riscv). See 'make help')
endif

all: $(TOOLS)

$(TOOLS):
	$(MAKE) -C $(KDIR) M=$(PWD)/src/$@ modules $(KBUILD_FLAGS)

clean:
	@for t in $(TOOLS); do \
		$(MAKE) -C $(KDIR) M=$(PWD)/src/$$t clean 2>/dev/null || true; \
	done

help:
	@echo "ALIRT build - targets: all (default), $(TOOLS), clean"
	@echo ""
	@echo "Platforms:  make ARCH=<name> [CROSS_COMPILE=<prefix>] [KDIR=<kernel build dir>]"
	@echo "  x86_64    native x86-64 (default; no cross prefix)"
	@echo "  armv7     32-bit ARM     (default cross: arm-linux-gnueabihf-)"
	@echo "  aarch64   64-bit ARM     (default cross: aarch64-linux-gnu-)"
	@echo "  mips      MIPS           (default cross: mips-linux-gnu-)"
	@echo "  powerpc   PowerPC 64LE   (default cross: powerpc64le-linux-gnu-)"
	@echo "  riscv     RISC-V 64      (default cross: riscv64-linux-gnu-)"
	@echo "  (kernel-style ARCH=x86/arm/arm64/mips/powerpc/riscv also accepted)"
	@echo ""
	@echo "Examples:"
	@echo "  make                                          # native build, all modules"
	@echo "  make ARCH=aarch64 KDIR=/build/linux-6.12      # cross-build all modules for arm64"
	@echo "  make ARCH=armv7 CROSS_COMPILE=arm-none-linux-gnueabihf- KDIR=/build/linux-5.15 mod_hunter"

.PHONY: all clean help $(TOOLS)
