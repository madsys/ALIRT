# SPDX-License-Identifier: GPL-3.0-only
#
# process_hunter - ALIRT hidden process hunter
#
# Builds process_hunter.ko against the running kernel's build tree:
#
#     make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
#
# The version adaptation layer lives in ../compat, the arch-specific
# address-space helpers in ../arch/<arch>. Real page-table walkers
# exist for x86_64, arm64, armv7, mips, powerpc and riscv; the header
# is selected from the target kernel's own CONFIG_* (available in
# Kbuild Makefiles) so both native and cross builds route correctly.
# process_hunter.c #errors out at compile time on any other
# architecture.

obj-m += process_hunter.o

ccflags-y += -I$(src)/../compat

ifeq ($(CONFIG_ARM64),y)
ccflags-y += -I$(src)/../arch/arm64
else ifeq ($(CONFIG_ARM),y)
ccflags-y += -I$(src)/../arch/armv7
else ifeq ($(CONFIG_MIPS),y)
ccflags-y += -I$(src)/../arch/mips
else ifeq ($(CONFIG_PPC),y)
ccflags-y += -I$(src)/../arch/powerpc
else ifeq ($(CONFIG_RISCV),y)
ccflags-y += -I$(src)/../arch/riscv
else
ccflags-y += -I$(src)/../arch/x86_64
endif
