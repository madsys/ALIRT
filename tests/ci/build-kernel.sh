#!/usr/bin/env bash
# Build a kernel of the given version from kernel.org sources (defconfig + bzImage + modules).
# Runs inside the container; build artifacts land in /build/linux-<version>/.
# Usage: build-kernel.sh <kernel-version> <arch>
set -euo pipefail

KVER="$1"
ARCH="${2:-x86_64}"

# KARCH: the kernel tree's arch name; CROSS: toolchain prefix;
# IMG: kernel image target/path; DEFCFG: defconfig to start from.
# The mips job boots Malta as qemu-system-mips64el -M malta with
# malta_defconfig (little-endian o32) and the matching mipsel-linux-gnu
# toolchain; this is the combination kernelci exercises daily.  A
# big-endian Malta boot (qemu-system-mips64) was tried first: the kernel
# builds fine after flipping CONFIG_CPU_BIG_ENDIAN, but the BE guest
# stays completely silent under QEMU 8.2 TCG and never reaches the
# console, so the LE path is used for reliability.  The pseries job uses
# pseries_defconfig, which is a generated config (ppc64_defconfig + le +
# guest + kvm_guest fragments), i.e. a ppc64 little-endian kernel;
# powerpc64le-linux-gnu matches it end to end and the static init binary
# must be little-endian too (a BE binary fails execve with -ENOEXEC on
# an LE kernel).
case "$ARCH" in
    x86_64)  KARCH=x86;     CROSS="";                       IMG=bzImage; DEFCFG=defconfig ;;
    aarch64) KARCH=arm64;   CROSS="aarch64-linux-gnu-";     IMG=Image;   DEFCFG=defconfig ;;
    armv7)   KARCH=arm;     CROSS="arm-linux-gnueabihf-";   IMG=zImage;  DEFCFG=multi_v7_defconfig ;;
    mips)    KARCH=mips;    CROSS="mipsel-linux-gnu-";      IMG=vmlinux; DEFCFG=malta_defconfig ;;
    powerpc) KARCH=powerpc; CROSS="powerpc64le-linux-gnu-"; IMG=zImage
             # pseries_defconfig only exists from 4.17; older kernels start
             # from ppc64_defconfig.  Either way the config is switched to
             # little-endian below.
             if [ "$(printf '%s\n' "4.17" "$KVER" | sort -V | head -n1)" = "4.17" ]; then
                 DEFCFG=pseries_defconfig
             else
                 DEFCFG=ppc64_defconfig
             fi ;;
    riscv)   KARCH=riscv;   CROSS="riscv64-linux-gnu-";     DEFCFG=defconfig
             # arch/riscv/boot/ (the Image target) only exists from v4.20;
             # v4.19 has no arch/riscv/boot/Makefile ("No rule to make
             # target 'Image'"), so build the ELF vmlinux there and boot
             # it directly under QEMU (see run-in-container.sh).
             if [ "$(printf '%s\n' "4.20" "$KVER" | sort -V | head -n1)" = "4.20" ]; then
                 IMG=Image
             else
                 IMG=vmlinux
             fi ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

mkdir -p /build
cd /build

echo "Downloading linux-${KVER} ..."
curl -fsSL "https://cdn.kernel.org/pub/linux/kernel/v${KVER%%.*}.x/linux-${KVER}.tar.xz" | tar xJ

cd "linux-${KVER}"
make ARCH="$KARCH" CROSS_COMPILE="$CROSS" "$DEFCFG" >/dev/null
# ALIRT resolves 'modules', 'module_kset' and 'init_mm' from kallsyms at
# module-load time; without CONFIG_KALLSYMS_ALL these data symbols are not
# in the kallsyms table and every cross-check degrades to "disabled".
# scripts/config + olddefconfig enables the option on every architecture;
# if an arch does not define the symbol, olddefconfig silently drops the
# orphan line and the build proceeds.
# ALIRT builds exclusively as loadable modules; multi_v7_defconfig on
# 3.10 ships CONFIG_MODULES=n ("The present kernel configuration has
# modules disabled"), which makes the modules target a hard error.
./scripts/config --enable MODULES
# mod_hunter reads struct module.exit directly (source frozen); on 3.10 the
# member only exists under CONFIG_MODULE_UNLOAD (multi_v7_defconfig ships
# it off - hence the armv7 3.10 build error - while x86 defconfig has it
# on).  Enable everywhere: the compat layer's alirt_mod_exit() handles
# either layout, but the frozen caller requires the member to exist.
./scripts/config --enable MODULE_UNLOAD
./scripts/config --enable KALLSYMS_ALL
# ALIRT resolves kallsyms_lookup_name via the kprobe trick on >= 5.7
# (see alirt_resolve_kln() in compat.h); without CONFIG_KPROBES that
# resolution returns -ENODEV and every kallsyms-based cross-check plus
# the init_mm-dependent address validation degrade.  The cross-arch
# defconfigs ship KPROBES=n, so force it on like KALLSYMS_ALL.
./scripts/config --enable KPROBES
# The runtime test boots the guest with -initrd; malta_defconfig (and
# other cross-arch defconfigs of the matrix) ship BLK_DEV_INITRD=n, so the
# firmware-passed rd_start=/rd_size= arguments are ignored and the guest
# panics with "Unable to mount root fs".  Nothing in ALIRT needs it
# disabled.
./scripts/config --enable BLK_DEV_INITRD
if [ "$KARCH" = "mips" ]; then
    # process_hunter.c requires CONFIG_SLUB (compile-time #error in its
    # SLUB path, source frozen); malta_defconfig still selects
    # CONFIG_SLAB on 4.4-5.15 (only 6.1+ switched to SLUB).  Swap the
    # SLAB choice for SLUB there; scripts/config + olddefconfig lets
    # the y-member win the choice.
    ./scripts/config --disable SLAB --enable SLUB
    if [ "$(printf '%s\n' "3.11" "$KVER" | sort -V | head -n1)" != "3.11" ]; then
        # gcc >= 4.9 (Ubuntu 16.04 ships gcc-5) forwards -msoft-float to
        # gas, so gas assembles in soft-float mode and rejects EVERY FP
        # mnemonic with "opcode not supported on this processor" - seen
        # in r4k_fpu.S via EX-ldc1/sdc1, then r4k_switch.S via the
        # asmmacro-32.h fpu_save/restore_double expansions, then even
        # mtc1/cfc1/ctc1 via fpu_save/restore_single.  Era toolchains
        # never passed the flag to gas and 3.10's .S sources use FP
        # instructions freely.  v4.4 solved the same problem with
        # per-site SET_HARDFLOAT markers (GAS_HAS_SET_HARDFLOAT); for
        # 3.10 restore hardfloat assembly mode globally - every mips
        # .S file includes asm.h before touching FP registers.  asm.h is
        # also #included from C (process.c et al), so gate the assembler
        # directive on __ASSEMBLY__.
        printf '\n/* gcc >= 4.9 forwards -msoft-float to gas, which then\n   rejects FP mnemonics tree-wide; era gas never saw the flag.\n   v4.4 fixed this with SET_HARDFLOAT markers - restore hardfloat\n   assembly mode globally instead. */\n#ifdef __ASSEMBLY__\n\t.set\thardfloat\n#endif\n' \
            >> arch/mips/include/asm/asm.h
    fi
fi
# gcc-9 vs the 5.10 nfsd code trips a clamp() compiletime_assert in
# fs/nfsd/nfs4state.c; nothing in ALIRT needs the NFS server.
./scripts/config --disable NFSD
if [ "$KARCH" = "powerpc" ]; then
    # The cross toolchain (powerpc64le), the QEMU pseries machine and the
    # static init binary are all little-endian.  Several defconfigs in the
    # matrix (e.g. v5.15's pseries_defconfig) are big-endian; a BE guest
    # kernel builds fine but SLOF dies on the very first instruction with
    # a program exception (the LE machine byte-swaps the entry opcode).
    # Force LE on every version.
    ./scripts/config --disable CPU_BIG_ENDIAN --enable CPU_LITTLE_ENDIAN
fi
make ARCH="$KARCH" CROSS_COMPILE="$CROSS" olddefconfig >/dev/null
# Note: the kernel image target differs per arch (x86=bzImage, arm64=Image,
# riscv=Image on 4.20+, vmlinux on 4.19, mips=vmlinux)
# Capture the full build log: 3.10-armv7 once "finished" in 35s with no
# error text because make's stdout was discarded - QEMU then booted an
# empty zImage image silently (load_image_targphys reports success for a
# 0-byte file, so no "could not load kernel" error appears either).
if ! make -j"$(nproc)" ARCH="$KARCH" CROSS_COMPILE="$CROSS" "$IMG" modules >kbuild.log 2>&1; then
    echo "BUILD-RESULT: FAIL (kernel make)"
    tail -40 kbuild.log
    exit 1
fi

echo "Kernel build finished: $(pwd)"
