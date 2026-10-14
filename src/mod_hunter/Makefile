# SPDX-License-Identifier: GPL-3.0-only
#
# mod_hunter - ALIRT hidden kernel module hunter
#
# Builds mod_hunter.ko against the running kernel's build tree:
#
#     make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
#
# The version adaptation layer lives in ../compat, the arch-specific
# address-space helpers in ../arch/<arch>. Only x86_64 headers exist
# today; the arm64 directory is the target layout for the upcoming
# arm64 port, and any other arch currently falls back to the x86_64
# headers and is expected to fail compilation there (mod_hunter.c
# additionally refuses to load with -ENODEV off x86_64).

obj-m += mod_hunter.o

ccflags-y += -I$(src)/../compat

ifeq ($(ARCH),x86)
ccflags-y += -I$(src)/../arch/x86_64
else ifeq ($(ARCH),arm64)
ccflags-y += -I$(src)/../arch/arm64
else
ccflags-y += -I$(src)/../arch/x86_64
endif
