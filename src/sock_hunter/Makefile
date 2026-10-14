# SPDX-License-Identifier: GPL-3.0-only
#
# sock_hunter - ALIRT hidden socket hunter
#
# Builds sock_hunter.ko against the running kernel's build tree:
#
#     make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
#
# The version adaptation layer lives in ../compat (proc_ops switch and
# friends). sock_hunter resolves the rest of its kernel differences
# (SLUB slab container eras, inet_sock field renames, IPv6 presence)
# internally via LINUX_VERSION_CODE, so no arch-specific include path
# is needed here.

obj-m += sock_hunter.o

ccflags-y += -I$(src)/../compat
