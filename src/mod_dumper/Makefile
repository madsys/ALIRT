# SPDX-License-Identifier: GPL-3.0-only
#
# modumper - ALIRT kernel module dumper
#
# Builds modumper.ko against the running kernel's build tree:
#
#     make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
#
# The version adaptation layer lives in ../compat. Same kbuild pattern
# as ../mod_hunter; the arch include dir is added for consistency with
# the other ALIRT modules (modumper itself only needs compat.h).

obj-m += modumper.o

ccflags-y += -I$(src)/../compat

ifeq ($(ARCH),x86)
ccflags-y += -I$(src)/../arch/x86_64
else ifeq ($(ARCH),arm64)
ccflags-y += -I$(src)/../arch/arm64
else
ccflags-y += -I$(src)/../arch/x86_64
endif
