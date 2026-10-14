#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
#
# dismod.sh - ALIRT dismod replacement, built on the system objdump.
#
# Disassembles a raw module core image produced by the ALIRT modumper
# tool (dump.dat). The original load address is recovered from the
# sibling dump.info (core_base=...) so branch/call targets line up
# with the live addresses seen in mod_hunter reports.
#
# Usage:
#   dismod.sh <dump.dat> [arch]
#
#   dump.dat  raw module core image (modumper dump.dat, or the
#             dump.dat rebuilt by dump-extract.sh on >= 5.10 kernels)
#   arch      target architecture; default: `uname -m`. Accepts any of:
#             x86_64 amd64 i386 i486 i586 i686 arm64 aarch64 arm*
#             mips mipsel mips64 mips64el powerpc ppc powerpc64 ppc64
#             riscv64
#
# Requires: objdump (binutils).
#
# Copyright (C) 2025 ALIRT

set -euo pipefail

usage() {
	sed -n '3,22p' "$0" | sed 's/^# \{0,1\}//'
}

if [[ $# -lt 1 || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
	usage
	[[ $# -lt 1 ]] && exit 1
	exit 0
fi

DUMP=$1
ARCH_IN=${2:-}

[[ -f "$DUMP" ]] || { echo "dismod: $DUMP: no such file" >&2; exit 1; }

if ! command -v objdump >/dev/null 2>&1; then
	cat >&2 <<'EOF'
dismod: objdump not found. Install the binutils package:
  Debian/Ubuntu : apt install binutils
  RHEL/Fedora   : yum install binutils   (or: dnf install binutils)
  Arch          : pacman -S binutils
  Alpine        : apk add binutils
EOF
	exit 1
fi

# --- architecture -> objdump machine mapping -------------------------
ARCH_IN=${ARCH_IN:-$(uname -m)}
MACH=
ENDIAN=

case "$ARCH_IN" in
	x86_64|amd64)      MACH="i386:x86-64" ;;
	i386|i486|i586|i686) MACH="i386" ;;
	arm64|aarch64)     MACH="aarch64" ;;
	arm*)              MACH="arm" ;;
	mips)              MACH="mips" ;;
	mipsel)            MACH="mips";  ENDIAN="-EL" ;;
	mips64)            MACH="mips:isa64" ;;
	mips64el)          MACH="mips:isa64"; ENDIAN="-EL" ;;
	powerpc|ppc)       MACH="powerpc:common" ;;
	powerpc64|ppc64)   MACH="powerpc:common64" ;;
	riscv64)           MACH="riscv:rv64" ;;
	*)
		echo "dismod: unsupported architecture '$ARCH_IN'" >&2
		exit 1
		;;
esac

# --- recover the load address from dump.info -------------------------
INFO=${DUMP%.dat}.info
VMA=
if [[ -f "$INFO" ]]; then
	# key=value metadata written by modumper (both legacy and hex mode)
	VMA=$(sed -n 's/^core_base=0x//p' "$INFO" | head -n 1 || true)
fi

ARGS=(-D -b binary -m "$MACH")
[[ -n "$ENDIAN" ]] && ARGS+=("$ENDIAN")
[[ -n "$VMA" ]] && ARGS+=("--adjust-vma=0x$VMA")
ARGS+=("$DUMP")

echo "dismod: objdump -m $MACH ${ENDIAN:+$ENDIAN }--adjust-vma=0x${VMA:-0} $DUMP" >&2
exec objdump "${ARGS[@]}"
