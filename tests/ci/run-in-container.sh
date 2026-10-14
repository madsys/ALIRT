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
# Usage: run-in-container.sh <kernel-version> <arch x86_64|aarch64> <runtime: true|false>
set -uo pipefail

KVER="$1"
ARCH="$2"
RUNTIME="$3"

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
    if [ "$ARCH" = "aarch64" ]; then
        PKGS="$PKGS gcc-aarch64-linux-gnu"
    fi
    DEBIAN_FRONTEND=noninteractive apt-get install -y $PKGS
else
    # CentOS 7: official mirrors are gone, switch to vault
    sed -i -e 's|mirror.centos.org|vault.centos.org|g' \
           -e 's|^#baseurl|baseurl|' \
           -e 's|^mirrorlist|#mirrorlist|' \
           /etc/yum.repos.d/CentOS-Base.repo
    yum install -y gcc make bc bison flex elfutils-libelf-devel \
                   openssl-devel cpio curl tar xz perl
fi

echo "===== [2/4] Building kernel linux-${KVER} (${ARCH}) ====="
bash /src/tests/ci/build-kernel.sh "$KVER" "$ARCH" || {
    echo "KERNEL-BUILD: FAIL"
    exit 1
}

KDIR="/build/linux-${KVER}"

case "$ARCH" in
    x86_64)  KARCH=x86;  CROSS="" ;;
    aarch64) KARCH=arm64; CROSS="aarch64-linux-gnu-" ;;
esac

echo "===== [3/4] Compiling ALIRT modules (src/ layout) ====="
COMPILE_OK=1
for tool in mod_hunter process_hunter sock_hunter; do
    if make -C "$KDIR" "M=/src/src/$tool" ARCH="$KARCH" CROSS_COMPILE="$CROSS" modules; then
        echo "COMPILE-$tool: PASS"
    else
        echo "COMPILE-$tool: FAIL"
        COMPILE_OK=0
    fi
done
[ "$COMPILE_OK" = 1 ] && echo "COMPILE-RESULT: PASS" || echo "COMPILE-RESULT: FAIL"

# mod_dumper is built standalone (failure does not block the main flow; logged separately)
if make -C "$KDIR" M=/src/src/mod_dumper ARCH="$KARCH" CROSS_COMPILE="$CROSS" modules; then
    echo "COMPILE-MODUMPER: PASS"
else
    echo "COMPILE-MODUMPER: FAIL"
fi

if [ "$RUNTIME" = "true" ]; then
    echo "===== [4/4] QEMU runtime detection test ====="
    # Build the self-hiding sample module
    make -C "$KDIR" M=/src/tests/samples ARCH="$KARCH" CROSS_COMPILE="$CROSS" modules \
        || { echo "RUNTIME-RESULT: FAIL (sample build)"; exit 1; }

    # Assemble the initramfs
    R=/ir-root
    mkdir -p "$R/bin" "$R/ko" "$R/proc" "$R/sys"
    cp /bin/busybox "$R/bin/"
    cp /src/src/mod_hunter/mod_hunter.ko /src/tests/samples/hide_self.ko "$R/ko/"
    cp /src/tests/init "$R/init"
    chmod +x "$R/init"
    ( cd "$R" && find . -print0 | cpio --null -o -H newc --quiet | gzip -9 ) > /ir.cpio.gz

    KVM=""
    [ -w /dev/kvm ] && KVM="-enable-kvm"
    timeout 300 qemu-system-x86_64 $KVM -m 512M -smp 2 \
        -kernel "$KDIR/arch/x86/boot/bzImage" \
        -initrd /ir.cpio.gz \
        -append "console=ttyS0,115200 loglevel=8 panic=10" \
        -nographic -no-reboot 2>&1 | tee /src/vm-console.log

    if grep -q "RESULT: PASS" /src/vm-console.log; then
        echo "RUNTIME-RESULT: PASS"
    else
        echo "RUNTIME-RESULT: FAIL"
        exit 1
    fi
fi
