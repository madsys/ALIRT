#!/usr/bin/env bash
# Runs inside an era-matched distribution container:
#   1. Install build dependencies (automatically handles repo migration for
#      EOL distributions)
#   2. Build the given kernel version from kernel.org sources (bzImage + modules)
#   3. Compile the ALIRT modules against that kernel tree
#   4. If runtime is enabled: build the self-hiding sample module, assemble
#      an initramfs, boot a QEMU VM and run the detection test, with console
#      output saved to /src/vm-console.log
#
# Usage: run-in-container.sh <kernel-version> <arch> <runtime: true|false> [qarch]
set -uo pipefail

KVER="$1"
ARCH="$2"
RUNTIME="$3"
QARCH="${4:-}"

echo "===== [1/4] Installing dependencies (container era image) ====="
if command -v apt-get >/dev/null 2>&1; then
    if ! apt-get update; then
        # EOL releases (16.04/18.04): repos have moved to old-releases
        sed -i -e 's|//archive.ubuntu.com|//old-releases.ubuntu.com|g' \
               -e 's|//security.ubuntu.com|//old-releases.ubuntu.com|g' \
               /etc/apt/sources.list
        apt-get update
    fi
    PKGS="build-essential bc bison flex libelf-dev libssl-dev cpio curl ca-certificates xz-utils"
    # Kernel 6.12 arm64 defconfig builds DRM_MSM, whose generated headers
    # require python3 (a2xx.xml.h etc.); without it the kernel build dies
    # with Error 127 in drivers/gpu/drm/msm.
    PKGS="$PKGS python3"
    if [ "$ARCH" = "x86_64" ] && [ "$RUNTIME" = "true" ]; then
        PKGS="$PKGS qemu-system-x86 busybox-static"
    fi
    # Cross toolchains (needed for the module build on every cross arch) and,
    # for runtime jobs, the matching QEMU system emulator.  Ubuntu package
    # contents: qemu-system-arm ships qemu-system-arm + qemu-system-aarch64,
    # qemu-system-mips ships qemu-system-mips{,64,el,64el},
    # qemu-system-ppc ships qemu-system-ppc{,64}, qemu-system-misc ships
    # qemu-system-riscv64 (Ubuntu 24.04, QEMU 8.2).
    case "$ARCH" in
        aarch64) PKGS="$PKGS gcc-aarch64-linux-gnu"
                 [ "$RUNTIME" = "true" ] && PKGS="$PKGS qemu-system-arm" ;;
        armv7)   PKGS="$PKGS gcc-arm-linux-gnueabihf"
                 [ "$RUNTIME" = "true" ] && PKGS="$PKGS qemu-system-arm" ;;
        mips)    PKGS="$PKGS gcc-mipsel-linux-gnu"
                 [ "$RUNTIME" = "true" ] && PKGS="$PKGS qemu-system-mips" ;;
        powerpc) PKGS="$PKGS gcc-powerpc64le-linux-gnu"
                 [ "$RUNTIME" = "true" ] && PKGS="$PKGS qemu-system-ppc" ;;
        riscv)   PKGS="$PKGS gcc-riscv64-linux-gnu"
                 [ "$RUNTIME" = "true" ] && PKGS="$PKGS qemu-system-misc" ;;
    esac
    DEBIAN_FRONTEND=noninteractive apt-get install -y $PKGS
else
    # CentOS 7: official mirrors are gone, switch to vault
    sed -i -e 's|mirror.centos.org|vault.centos.org|g' \
           -e 's|^#baseurl|baseurl|' \
           -e 's|^mirrorlist|#mirrorlist|' \
           /etc/yum.repos.d/CentOS-Base.repo
    yum install -y gcc make bc bison flex elfutils-libelf-devel \
                   openssl-devel cpio curl tar xz perl
    if [ "$ARCH" = "x86_64" ] && [ "$RUNTIME" = "true" ]; then
        # CentOS 7 has no qemu-system-x86 / busybox-static packages:
        # qemu-kvm provides the system emulator, and a static busybox
        # is fetched for the initramfs.
        yum install -y qemu-kvm
        curl -fsSL -o /bin/busybox \
            "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox"
        chmod +x /bin/busybox
    fi
fi

echo "===== [2/4] Building kernel linux-${KVER} (${ARCH}) ====="
bash /src/tests/ci/build-kernel.sh "$KVER" "$ARCH" || {
    echo "KERNEL-BUILD: FAIL"
    exit 1
}

KDIR="/build/linux-${KVER}"

case "$ARCH" in
    x86_64)  KARCH=x86;     CROSS="" ;;
    aarch64) KARCH=arm64;   CROSS="aarch64-linux-gnu-" ;;
    armv7)   KARCH=arm;     CROSS="arm-linux-gnueabihf-" ;;
    mips)    KARCH=mips;    CROSS="mipsel-linux-gnu-"        ;;
    powerpc) KARCH=powerpc; CROSS="powerpc64le-linux-gnu-" ;;
    riscv)   KARCH=riscv;   CROSS="riscv64-linux-gnu-" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# arm32/arm64/ppc64 module layouts can place struct module at offsets that
# are only 8-byte aligned; the hunter's 0x10 scan step then permanently
# misses the (real) modules and the runtime test finds nothing (powerpc
# 6.12 scanned 134M steps with 0 candidates while mod_hunter's own struct
# module sat inside the window).  On those arches, raise the alignment of
# the module's struct module section after the link: the loader places
# each section at ALIGN(cumulative, sh_addralign), so a 16-byte alignment
# for .gnu.linkonce.this_module puts struct module on a scanned offset
# regardless of the sizes of the sections before it.
# (GCC has no -falign-variables; objcopy --set-section-alignment needs
# binutils >= 2.39, which every cross container here ships.  x86_64/riscv/
# and mips layouts are already 16-aligned and are left untouched.)
#
# The section is located through the __this_module SYMBOL (objdump -t)
# rather than by hard-coding a name: modpost always emits the symbol, and
# the section name varies with kernel/binutils combinations (the naive
# readelf -S name grep missed on powerpc even though the loader - which
# resolves the same section by name - loads the module fine).
align_modstruct() {
    ko="$1"
    sec=$(${CROSS}objdump -t "$ko" 2>/dev/null | awk '$NF == "__this_module" && NF >= 5 {print $(NF-2); exit}')
    case "$sec" in
        ""|UND|UNDEF|ABS)
            echo "WARN: __this_module symbol/section not found in $ko"
            echo "WARN:   module-ish sections: $(${CROSS}readelf -S "$ko" 2>/dev/null | grep -iE 'this_module|modul' | tr -s ' ' | head -5)"
            echo "WARN:   symbol: $(${CROSS}objdump -t "$ko" 2>/dev/null | grep this_module | head -2)"
            return
            ;;
    esac
    ${CROSS}objcopy --set-section-alignment "$sec=16" "$ko" \
        || echo "WARN: could not align $sec in $ko"
}

NEED_ALIGN=no
if [ "$RUNTIME" = "true" ]; then
    case "$ARCH" in
        armv7|aarch64|powerpc) NEED_ALIGN=yes ;;
    esac
fi

# Diagnose the kallsyms-based symbol resolution: ALIRT needs KALLSYMS_ALL
# (data symbols: init_mm, module_kset) and KPROBES (kln resolution); print
# the effective values so a silent olddefconfig drop is visible in the log.
grep -E "^CONFIG_KALLSYMS|^# CONFIG_KALLSYMS|^CONFIG_KPROBES|^# CONFIG_KPROBES" \
    "$KDIR/.config" || true

kmake() {
    make -C "$KDIR" "$@" ARCH="$KARCH" CROSS_COMPILE="$CROSS" modules
}

echo "===== [3/4] Compiling ALIRT modules (src/ layout) ====="
COMPILE_OK=1
for tool in mod_hunter process_hunter sock_hunter; do
    if kmake "M=/src/src/$tool"; then
        if [ "$NEED_ALIGN" = "yes" ] && [ "$tool" = "mod_hunter" ]; then
            align_modstruct "/src/src/$tool/$tool.ko"
        fi
        echo "COMPILE-$tool: PASS"
    else
        echo "COMPILE-$tool: FAIL"
        COMPILE_OK=0
    fi
done
[ "$COMPILE_OK" = 1 ] && echo "COMPILE-RESULT: PASS" || echo "COMPILE-RESULT: FAIL"

# mod_dumper is built standalone (failure does not block the main flow; logged separately)
if kmake M=/src/src/mod_dumper; then
    echo "COMPILE-MODUMPER: PASS"
else
    echo "COMPILE-MODUMPER: FAIL"
fi

if [ "$RUNTIME" = "true" ]; then
    echo "===== [4/4] QEMU runtime detection test ====="
    # Build the self-hiding sample module
    kmake M=/src/tests/samples \
        || { echo "RUNTIME-RESULT: FAIL (sample build)"; exit 1; }
    if [ "$NEED_ALIGN" = "yes" ]; then
        for ko in /src/tests/samples/*.ko; do
            align_modstruct "$ko"
        done
    fi

    # Assemble the initramfs
    R=/ir-root
    rm -rf "$R" /ir.cpio.gz
    mkdir -p "$R/ko" "$R/proc" "$R/sys"
    cp /src/src/mod_hunter/mod_hunter.ko /src/tests/samples/hide_self.ko "$R/ko/"

    if [ "$ARCH" = "x86_64" ]; then
        # x86_64 keeps the proven busybox initramfs path
        mkdir -p "$R/bin"
        cp /bin/busybox "$R/bin/"
        cp /src/tests/init "$R/init"
        chmod +x "$R/init"
        ( cd "$R" && find . -print0 | cpio --null -o -H newc --quiet | gzip -9 ) > /ir.cpio.gz

        KVM=""
        [ -w /dev/kvm ] && KVM="-enable-kvm"
        # CentOS 7 ships the emulator as /usr/libexec/qemu-kvm
        QEMU_BIN="$(command -v qemu-system-x86_64 || echo /usr/libexec/qemu-kvm)"
        timeout 300 "$QEMU_BIN" $KVM -m 512M -smp 2 \
            -kernel "$KDIR/arch/x86/boot/bzImage" \
            -initrd /ir.cpio.gz \
            -append "console=ttyS0,115200 loglevel=8 panic=10" \
            -nographic -no-reboot 2>&1 | tee /src/vm-console.log
    else
        # Cross-arch path: static, pure-syscall init (tests/init-cross.c),
        # so no per-arch busybox is required.  QEMU machine/console choices:
        #   aarch64 : virt + cortex-a57, PL011 serial -> ttyAMA0
        #   armv7   : virt + cortex-a15, PL011 serial -> ttyAMA0
        #   mips    : Malta in qemu-system-mipsel (LE o32 malta_defconfig
        #             kernel; the o32 guest is silent under the 64-bit
        #             qemu-system-mips64el CPU, and BE Malta under QEMU
        #             8.2 TCG is silent in either width), 8250 -> ttyS0
        #   powerpc : pSeries, hypervisor console -> hvc0
        #   riscv   : virt (OpenSBI bundled with QEMU boots the Image), 8250 -> ttyS0
        "${CROSS}gcc" -O2 -static -Wall -o "$R/init" /src/tests/init-cross.c \
            || { echo "RUNTIME-RESULT: FAIL (init build)"; exit 1; }
        ( cd "$R" && find . -print0 | cpio --null -o -H newc --quiet | gzip -9 ) > /ir.cpio.gz

        case "${QARCH:-$ARCH}" in
            aarch64) QEMU="qemu-system-aarch64 -M virt -cpu cortex-a57"
                     KIMG="$KDIR/arch/arm64/boot/Image"
                     CONSOLE="ttyAMA0" ;;
            armv7)   QEMU="qemu-system-arm -M virt -cpu cortex-a15"
                     KIMG="$KDIR/arch/arm/boot/zImage"
                     CONSOLE="ttyAMA0" ;;
            mips)    QEMU="qemu-system-mipsel -M malta"
                     KIMG="$KDIR/vmlinux"
                     CONSOLE="ttyS0"
                     QMEM="-m 512M" ;;
            powerpc) QEMU="qemu-system-ppc64 -M pseries"
                     KIMG="$KDIR/arch/powerpc/boot/zImage"
                     CONSOLE="hvc0" ;;
            riscv)   QEMU="qemu-system-riscv64 -M virt"
                     KIMG="$KDIR/arch/riscv/boot/Image"
                     CONSOLE="ttyS0" ;;
            *) echo "RUNTIME-RESULT: FAIL (no QEMU mapping for $ARCH)"; exit 1 ;;
        esac
        # TCG emulation is slow (a full defconfig kernel under emulation):
        # allow 7 minutes for boot + module load + scan.  mips Malta is
        # o32 without CONFIG_HIGHMEM, so cap RAM at 512M: a 1G lowmem
        # region can hang the guest before the serial console registers,
        # producing a completely silent boot.
        # shellcheck disable=SC2086
        timeout 420 $QEMU ${QMEM:--m 1G} \
            -kernel "$KIMG" \
            -initrd /ir.cpio.gz \
            -append "console=$CONSOLE,115200 loglevel=8 panic=10" \
            -nographic -no-reboot 2>&1 | tee /src/vm-console.log
    fi

    if grep -q "RESULT: PASS" /src/vm-console.log; then
        echo "RUNTIME-RESULT: PASS"
    else
        echo "RUNTIME-RESULT: FAIL"
        exit 1
    fi
fi
