/* SPDX-License-Identifier: GPL-3.0-only */
/*
 * ALIRT — arm64 address-space adaptation layer (stub implementation)
 *
 * Page-table walking / module-space support for this architecture is
 * still being ported. The code compiles; at module load time it returns
 * -ENODEV with a clear message and does not panic.
 * TODO(v0.6.0): implement this architecture per the contract in
 * src/arch/x86_64/alirt_mm.h.
 */
#ifndef ALIRT_ARCH_ARM64_MM_H
#define ALIRT_ARCH_ARM64_MM_H

#include <linux/types.h>

static inline bool alirt_addr_valid(unsigned long addr, size_t size)
{
	(void)addr; (void)size;
	return false;
}

static inline unsigned long alirt_modules_start(void) { return 0; }
static inline unsigned long alirt_modules_end(void)   { return 0; }

static inline bool alirt_is_module_space(const void *p)
{
	(void)p;
	return false;
}

#endif
