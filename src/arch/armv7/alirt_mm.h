/* SPDX-License-Identifier: GPL-3.0-only */
/*
 * ALIRT — ARM 32-bit (ARMv7) address-space adaptation layer
 *
 * Provides, across 2.6.32 ~ 6.12+ (both classic 2-level and LPAE
 * 3-level MMU configurations):
 *   1. Kernel virtual-address validity checks (multi-level page-table
 *      walk, fault-safe)
 *   2. The module mapping space (MODULES_VADDR ~ MODULES_END, a
 *      dedicated window directly below the kernel image)
 *
 * Interface contract: byte-for-byte identical to
 * src/arch/x86_64/alirt_mm.h (alirt_mm_init / alirt_addr_valid /
 * alirt_modules_start / alirt_modules_end / alirt_is_module_space).
 *
 * init_mm handling is identical to x86_64: it is not exported on any
 * supported kernel, so every consumer resolves it through kallsyms via
 * alirt_mm_init() once, right after alirt_resolve_kln() (compat.h).
 * Until that succeeds - and whenever it cannot (init_mm is a data
 * symbol, so it only appears in kallsyms with CONFIG_KALLSYMS_ALL) -
 * alirt_addr_valid() degrades to always-false instead of walking a
 * NULL mm.
 *
 * Page-table walk, per MMU configuration:
 *
 *   Classic 2-level (no CONFIG_ARM_LPAE; the only layout before v3.3
 *   and still common on ARMv5/ARMv6):
 *     pgd (PTRS_PER_PGD=2048, 2MB each, folded pud) -> pmd (folded,
 *     PTRS_PER_PMD=1; each pgd slot is two hardware first-level
 *     descriptors) -> pte (512 Linux PTEs covering 2MB).
 *     The pmd/pgd slot value is the RAW hardware first-level
 *     descriptor: type bits [1:0] == 0b10 means a 1MB section (or
 *     16MB supersection when PMD_SECT_SUPER, bit 18, is set) and the
 *     entry is a LEAF; 0b01 means a coarse page-table pointer.  Linux
 *     replicates a supersection descriptor across all 16 consecutive
 *     first-level slots, so validating leaf coverage in 1MB
 *     SECTION_SIZE steps stays correct without inspecting bit 18.
 *
 *   LPAE 3-level (CONFIG_ARM_LPAE; Cortex-A7/A15+, headers present
 *   since v3.3):
 *     pgd (PTRS_PER_PGD=4, 1GB each) -> pmd (PTRS_PER_PMD=512, 2MB
 *     each) -> pte.  The pmd slot value is the raw LPAE level-2
 *     descriptor: type bits [1:0] == 0b01 (PMD_TYPE_SECT) means a 2MB
 *     block and is a LEAF; 0b11 (PMD_TYPE_TABLE) means a page table.
 *     PMD_TYPE_MASK/PMD_TYPE_SECT carry the right values for each
 *     configuration, so a single test covers both MMU types.
 *
 * Version notes (all verified against kernel.org stable tags):
 *   - pgd_offset/pud_offset/pmd_offset/pte_offset_kernel exist on
 *     every version: ARM defined them in asm/pgtable.h through v5.4
 *     (pgtable.h:182/:206 at v5.4); from v5.8 on the generic fallbacks
 *     in include/linux/pgtable.h (present since v4.11) take over.  We
 *     include <linux/pgtable.h> on >= 4.11 and <asm/pgtable.h>
 *     otherwise; semantics are identical (both index mm->pgd and use
 *     pmd_page_vaddr()).
 *   - pud_offset() takes a pgd_t * through v5.4 (4level-fixup.h /
 *     old pgtable-nopud.h) and a p4d_t * from v5.5 on (ARM dropped
 *     4level-fixup.h between v5.4 and v5.5; the new nopud folds p4d
 *     and provides p4d_offset via pgtable-nop4d.h).  The p4d step is
 *     therefore compiled in only on >= 5.5.
 *   - pgd_none/pgd_present are trivially true on every folded
 *     configuration (all 32-bit ARM layouts); emptiness is caught at
 *     the pmd level (classic) or the pud level (LPAE), matching
 *     in-tree follow_pte() semantics.
 *   - pmd_present exists on every version: asm/pgtable.h carried a
 *     common "(pmd_val(pmd))" definition through v4.4 (valid on both
 *     MMU types: a valid descriptor is never zero); from v4.19 the
 *     per-level headers define it (2-level: pmd_val; LPAE:
 *     L_PMD_SECT_VALID, bit 0, introduced in v4.6).
 *   - pte_present exists on every version (L_PTE_PRESENT; pte_isset()
 *     form from v4.4 on).  pte_offset_kernel() - never kmap-based -
 *     works under CONFIG_HIGHPTE and remains visible to out-of-tree
 *     modules on 6.5+.
 *   - PMD_TYPE_MASK / PMD_TYPE_SECT come from asm/pgtable-hwdef.h
 *     (v2.6.32) or asm/pgtable-*level-hwdef.h (v3.3+), always
 *     reachable via <asm/pgtable.h>.
 *
 * Module space: unlike x86_64, ARM 32-bit does NOT place modules in
 * the general vmalloc area.  arch/arm/kernel/module.c's module_alloc()
 * allocates from a dedicated window immediately below PAGE_OFFSET on
 * every version (verified: __get_vm_area(size, VM_ALLOC,
 * MODULES_VADDR, MODULES_END) at v2.6.32:47; __vmalloc_node_range(...
 * MODULES_VADDR, MODULES_END, ...) at v4.4:43 and v6.1:46).
 * asm/memory.h defines the bounds on all versions:
 *   MODULES_VADDR = PAGE_OFFSET - SZ_16M (or - SZ_8M under
 *                   CONFIG_THUMB2_KERNEL, Thumb-2 relocation limit)
 *   MODULES_END   = PAGE_OFFSET - PMD_SIZE with CONFIG_HIGHMEM
 *                   (pkmap shares the tail), else PAGE_OFFSET
 * i.e. a ~14-16MB window (6-8MB for Thumb-2) ending at the kernel
 * image.  Residual risk: since v4.4's CONFIG_ARM_MODULE_PLTS fallback,
 * an oversized module may spill into [VMALLOC_START, VMALLOC_END)
 * (module.c falls back to that range when the window is exhausted);
 * such modules sit outside this scan range (see report).
 *
 * !CONFIG_MMU: there are no page tables to walk; alirt_addr_valid()
 * degrades to always-false and alirt_mm_init() reports -ENODEV, while
 * the module-space macros still follow asm/memory.h's nommu bounds.
 */
#ifndef ALIRT_ARCH_ARMV7_MM_H
#define ALIRT_ARCH_ARMV7_MM_H

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/mm.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
/*
 * Generic pgtable definitions with #ifndef-guarded fallbacks
 * (pte_offset_kernel/pgd_offset/pmd_offset/pud_offset).  ARM's own
 * definitions in asm/pgtable.h win where present (<= v5.4); from v5.8
 * ARM relies on these generic versions.  Includes <asm/pgtable.h>.
 */
#  include <linux/pgtable.h>
#else
#  include <asm/pgtable.h>
#endif

#include <asm/memory.h>		/* MODULES_VADDR / MODULES_END */

#ifdef CONFIG_MMU

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
 * Leaf coverage of a pmd-level section/block:
 *   classic 2-level: 1MB SECTION_SIZE (supersections are replicated
 *                    across 16 first-level slots, so 1MB stepping
 *                    remains correct)
 *   LPAE 3-level:      2MB SECTION_SIZE (block)
 * SECTION_SIZE carries the right value in pgtable-2level.h /
 * pgtable-3level.h (and in the unified asm/pgtable.h at v2.6.32).
 */
#if defined(CONFIG_ARM_LPAE)
#  define ALIRT_PMD_LEAF_SIZE	SECTION_SIZE	/* 2MB block */
#else
#  define ALIRT_PMD_LEAF_SIZE	SECTION_SIZE	/* 1MB section */
#endif

/*
 * Walk the page tables to verify that [addr, addr+size) is fully mapped.
 * Handles both ARM MMU configurations - classic 2-level (section
 * mappings at the pmd level) and LPAE 3-level (2MB block mappings) -
 * as well as pte-level mappings (vmalloc/module space).  Returns false
 * as soon as any intermediate page-table entry is missing.
 */
static inline bool alirt_addr_valid(unsigned long addr, size_t size)
{
	pgd_t *pgd;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)
	p4d_t *p4d;	/* ARM dropped 4level-fixup.h: pud_offset() takes p4d_t * */
#endif
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	unsigned long end_addr;

	/* Unresolvable init_mm (see alirt_mm_init): fail safe, never
	 * walk a NULL mm. */
	if (unlikely(!alirt_mm_init_mm))
		return false;
	pgd = pgd_offset(alirt_mm_init_mm, addr);
	if (unlikely(!pgd) || unlikely(pgd_none(*pgd)) || unlikely(!pgd_present(*pgd)))
		return false;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)
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

	/*
	 * Leaf descriptor: a classic 1MB section (type 0b10; supersection
	 * included) or an LPAE 2MB block (type 0b01).  PMD_TYPE_MASK /
	 * PMD_TYPE_SECT carry the per-configuration values, so one test
	 * serves both MMU types (table pointers are 0b01 classic /
	 * 0b11 LPAE and never match).
	 */
	if ((pmd_val(*pmd) & PMD_TYPE_MASK) == PMD_TYPE_SECT) {
		end_addr = (addr & ~(ALIRT_PMD_LEAF_SIZE - 1)) +
			   ALIRT_PMD_LEAF_SIZE - 1;
		goto end;
	}

	pte = pte_offset_kernel(pmd, addr);
	if (unlikely(!pte) || unlikely(!pte_present(*pte)))
		return false;

	end_addr = (((addr >> PAGE_SHIFT) + 1) << PAGE_SHIFT) - 1;

end:
	if (end_addr >= addr + size - 1)
		return true;

	return alirt_addr_valid(end_addr + 1, size - (end_addr - addr + 1));
}

#else /* !CONFIG_MMU */

static inline int alirt_mm_init(unsigned long (*kln)(const char *name))
{
	(void)kln;
	return -ENODEV;
}

static inline bool alirt_addr_valid(unsigned long addr, size_t size)
{
	(void)addr;
	(void)size;
	return false;
}

#endif /* CONFIG_MMU */

/*
 * ARM 32-bit module mapping space: the dedicated window below the
 * kernel image (see the file header for the per-version definitions
 * and the CONFIG_ARM_MODULE_PLTS fallback caveat).
 */
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

#endif /* ALIRT_ARCH_ARMV7_MM_H */
