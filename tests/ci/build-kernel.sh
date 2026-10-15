#!/usr/bin/env bash
# Build a kernel of the given version from kernel.org sources (defconfig + bzImage + modules).
# Runs inside the container; build artifacts land in /build/linux-<version>/.
# Usage: build-kernel.sh <kernel-version> <arch>
set -euo pipefail

KVER="$1"
ARCH="${2:-x86_64}"

# KARCH: the kernel tree's arch name; CROSS: toolchain prefix;
# IMG: kernel image target/path; DEFCFG: defconfig to start from.
# The mips job boots Malta in qemu-system-mips64; mips64_defconfig was
# removed from the kernel tree, so use malta_defconfig (32-bit BE): the
# 64-bit Malta CPU in QEMU runs o32 kernels fine, and the 32-bit
# mips-linux-gnu toolchain matches the kernel ABI for module builds.
# The pseries job uses pseries_defconfig, which is a generated config
# (ppc64_defconfig + le + guest + kvm_guest fragments), i.e. a ppc64
# little-endian kernel; powerpc64le-linux-gnu matches it end to end and
# the static init binary must be little-endian too (a BE binary fails
# execve with -ENOEXEC on an LE kernel).
case "$ARCH" in
    x86_64)  KARCH=x86;     CROSS="";                       IMG=bzImage; DEFCFG=defconfig ;;
    aarch64) KARCH=arm64;   CROSS="aarch64-linux-gnu-";     IMG=Image;   DEFCFG=defconfig ;;
    armv7)   KARCH=arm;     CROSS="arm-linux-gnueabihf-";   IMG=zImage;  DEFCFG=multi_v7_defconfig ;;
    mips)    KARCH=mips;    CROSS="mips-linux-gnu-";        IMG=vmlinux; DEFCFG=malta_defconfig ;;
    powerpc) KARCH=powerpc; CROSS="powerpc64le-linux-gnu-"; IMG=zImage;  DEFCFG=pseries_defconfig ;;
    riscv)   KARCH=riscv;   CROSS="riscv64-linux-gnu-";     IMG=Image;   DEFCFG=defconfig ;;
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
./scripts/config --enable KALLSYMS_ALL
# ALIRT resolves kallsyms_lookup_name via the kprobe trick on >= 5.7
# (see alirt_resolve_kln() in compat.h); without CONFIG_KPROBES that
# resolution returns -ENODEV and every kallsyms-based cross-check plus
# the init_mm-dependent address validation degrade.  The cross-arch
# defconfigs ship KPROBES=n, so force it on like KALLSYMS_ALL.
./scripts/config --enable KPROBES
if [ "$ARCH" = "mips" ]; then
    # malta_defconfig is little-endian (CONFIG_CPU_LITTLE_ENDIAN) since the
    # 5.x cycle, but the CI job boots the big-endian qemu-system-mips64 with
    # the big-endian mips-linux-gnu toolchain; flip the endianness choice
    # explicitly both ways or olddefconfig may keep the little-endian side.
    ./scripts/config --disable CPU_LITTLE_ENDIAN --enable CPU_BIG_ENDIAN
fi
make ARCH="$KARCH" CROSS_COMPILE="$CROSS" olddefconfig >/dev/null
# Note: the kernel image target differs per arch (x86=bzImage, arm64=Image, riscv=Image)
make -j"$(nproc)" ARCH="$KARCH" CROSS_COMPILE="$CROSS" "$IMG" modules >/dev/null

echo "Kernel build finished: $(pwd)"
