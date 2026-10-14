#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
#
# dump-extract.sh - convert a 5.10+ modumper hex dump back to files.
#
# On kernels >= 5.10 set_fs() no longer exists, so modumper cannot
# write dump.dat/dump.info from kernel space. Instead `cat
# /proc/get_mod` emits the metadata as '#' comment lines followed by
# the core image as lowercase hex (16 bytes per line). This script
# splits that capture back into the classic two files:
#
#   # metadata lines  -> <out>.info
#   # hex lines       -> <out>.dat   (raw binary, xxd or perl)
#
# Usage:
#   cat /proc/get_mod > capture.txt
#   dump-extract.sh capture.txt [out]      # default out: dump
#
# Requires: xxd (vim package) or perl.
#
# Copyright (C) 2025 ALIRT

set -euo pipefail

if [[ $# -lt 1 || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
	sed -n '3,19p' "$0" | sed 's/^# \{0,1\}//'
	[[ $# -lt 1 ]] && exit 1
	exit 0
fi

IN=$1
OUT=${2:-dump}

[[ -f "$IN" ]] || { echo "dump-extract: $IN: no such file" >&2; exit 1; }

TMP_HEX=$(mktemp)
trap 'rm -f "$TMP_HEX"' EXIT

# '#' comment lines are the metadata block (strip the leading "# ")
{ grep '^# ' "$IN" 2>/dev/null || true; } | sed 's/^# //' > "$OUT.info"

# everything else is hex payload
{ grep -v '^#' "$IN" 2>/dev/null || true; } | tr -d '[:space:]' > "$TMP_HEX"

if [[ ! -s "$TMP_HEX" ]]; then
	echo "dump-extract: no hex payload in $IN" \
	     "(this capture does not look like a 5.10+ hex dump)" >&2
	exit 1
fi

if command -v xxd >/dev/null 2>&1; then
	xxd -r -p "$TMP_HEX" > "$OUT.dat"
elif command -v perl >/dev/null 2>&1; then
	perl -ne 'print pack("H*", $_)' "$TMP_HEX" > "$OUT.dat"
else
	echo "dump-extract: need xxd (vim package) or perl to decode hex" >&2
	exit 1
fi

echo "dump-extract: wrote $OUT.info and $OUT.dat" >&2
