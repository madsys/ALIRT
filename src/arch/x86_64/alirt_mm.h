/* SPDX-License-Identifier: GPL-3.0-only */
/*
 * ALIRT — x86_64 address-space adaptation layer
 *
 * Provides, across 2.6.32 ~ 6.12+:
 *   1. Kernel virtual-address validity checks (multi-level page-table
 *      walk, fault-safe)
 *   2. The module mapping space (MODULES_VADDR ~ MODULES_END, 1520MB)
 *
 * Technical lineage: madsys "Finding hidden kernel modules (the extrem way)"
 * (Phrack 61-3, 2005) -> nitara2 (g1inko/ksen-lin, Phrack 71, 2024).
 * This implementation uses init_mm instead of current->mm (when reading
 * proc, current may be a kernel thread whose mm is NULL, which would
 * crash the walk).  init_mm itself is NOT referenced by name: it is
 * not exported on any supported kernel (verified: no
 * EXPORT_SYMBOL(init_mm) in mm/init-mm.c from v2.6.32 through v6.12),
 * so a direct &init_mm reference only earns a modpost warning on
 * <= 4.19 kernels - where insmod then fails with "Unknown symbol
 * init_mm" - and a hard modpost "undefined" error on 5.4+.  Instead
 * every consumer resolves the address through kallsyms by calling
 * alirt_mm_init() once, right after alirt_resolve_kln() (compat.h).
 * Until that succeeds - and whenever it cannot (init_mm is a data
 * symbol, so it only appears in kallsyms with CONFIG_KALLSYMS_ALL) -
 * alirt_addr_valid() degrades to always-false instead of walking a
 * NULL mm.  The other arch headers in src/arch/ carry stubs with no
 * init_mm involvement at all.
 */
#ifndef ALIRT_ARCH_X86_64_MM_H
#define ALIRT_ARCH_X86_64_MM_H

#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
#  include <linux/mm.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#  include <linux/pgtable.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#  include <asm-generic/pgtable-nop4d.h>
#else
#  include <asm/pgtable.h>
#endif

#include <asm/fixmap.h>

/*
 * Resolved address of the init_mm data symbol (see the file header).
 * Per-translation-unit static: each including module owns its copy and
 * feeds it via alirt_mm_init().
 */
static struct mm_struct *alirt_mm_init_mm;

/*
 * Resolve init_mm through kallsyms.  @kln is a working
 * kallsyms_lookup_name (see alirt_resolve_kln() in compat.h; NULL is
 * tolerated).  Returns 0 on success; until then, and on failure,
 * alirt_addr_valid() reports every address as unvalidated.
 */
static inline int alirt_mm_init(unsigned long (*kln)(const char *name))
{
	if (!kln)
		return -EINVAL;
	alirt_mm_init_mm = (struct mm_struct *)kln("init_mm");
	return alirt_mm_init_mm ? 0 : -ENOENT;
}

/*
 * Walk the page tables to verify that [addr, addr+size) is fully mapped.
 * Handles 4-level / 5-level page tables (5-level was introduced by
 * CONFIG_X86_5LEVEL in 4.11+) as well as PMD/PUD huge pages. Returns
 * false as soon as any intermediate page-table entry is missing.
 */
static inline bool alirt_addr_valid(unsigned long addr, size_t size)
{
	pgd_t *pgd;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0) || defined(CONFIG_X86_5LEVEL)
	p4d_t *p4d;
#endif
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	unsigned long end_addr;

	/* Kernel threads have current->mm == NULL; the kernel address
	 * space is identical for every mm, so use init_mm (swapper_pg_dir).
	 * Unresolvable (see alirt_mm_init): fail safe, never walk a NULL
	 * mm. */
	if (unlikely(!alirt_mm_init_mm))
		return false;
	pgd = pgd_offset(alirt_mm_init_mm, addr);
	if (unlikely(!pgd) || unlikely(pgd_none(*pgd)) || unlikely(!pgd_present(*pgd)))
		return false;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0) || defined(CONFIG_X86_5LEVEL)
	p4d = p4d_offset(pgd, addr);
	if (unlikely(!p4d) || unlikely(p4d_none(*p4d)) || unlikely(!p4d_present(*p4d)))
		return false;
	pud = pud_offset(p4d, addr);
#else
	pud = pud_offset(pgd, addr);
#endif
	if (unlikely(!pud) || unlikely(pud_none(*pud)) || unlikely(!pud_present(*pud)))
		return false;

	pmd = pmd_offset(pud, addr);
	if (unlikely(!pmd) || unlikely(pmd_none(*pmd)) || unlikely(!pmd_present(*pmd)))
		return false;

	/* pmd_trans_huge() arrived with transparent huge pages (THP) in
	 * 2.6.38; earlier kernels have no huge PMDs, go straight to PTE */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
	if (pmd_trans_huge(*pmd)) {
		end_addr = (((addr >> PMD_SHIFT) + 1) << PMD_SHIFT) - 1;
		goto end;
	}
#endif

	/* pte_offset_map() is unavailable in out-of-tree modules on >= 6.5 */
	pte = pte_offset_kernel(pmd, addr);
	if (unlikely(!pte) || unlikely(!pte_present(*pte)))
		return false;

	end_addr = (((addr >> PAGE_SHIFT) + 1) << PAGE_SHIFT) - 1;

end:
	if (end_addr >= addr + size - 1)
		return true;

	return alirt_addr_valid(end_addr + 1, size - (end_addr - addr + 1));
}

/* x86_64-specific module mapping space (1520MB under both 4-level and
 * 5-level virtual addressing) */
static inline unsigned long alirt_modules_start(void)
{
	return MODULES_VADDR;
}

static inline unsigned long alirt_modules_end(void)
{
	return MODULES_END;
}

static inline bool alirt_is_module_space(const void *p)
{
	return (unsigned long)p >= MODULES_VADDR &&
	       (unsigned long)p < MODULES_END;
}

#endif /* ALIRT_ARCH_X86_64_MM_H */
