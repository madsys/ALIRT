/* SPDX-License-Identifier: GPL-3.0-only */
/*
 * ALIRT — mips address-space adaptation layer
 *
 * Provides, across Linux 3.10 ~ 6.12+ on both MIPS32 and MIPS64
 * (including XPA), the same contract as src/arch/x86_64/alirt_mm.h:
 *   1. Kernel virtual-address validity checks (multi-level page-table
 *      walk, fault-safe)
 *   2. The module mapping space
 *
 * init_mm handling is identical to the x86_64 header: it is never
 * referenced by name (it is not exported on any supported kernel),
 * every consumer resolves it once through kallsyms via
 * alirt_mm_init(); until then alirt_addr_valid() fails safe.
 *
 * Page-table walk notes (verified against kernel.org stable tree,
 * v3.10 / v4.4 / v4.19 / v5.4 / v5.15 / v6.1 / v6.6 / v6.12):
 *
 *   - MIPS folds page-table levels through the asm-generic nop4d /
 *     nopud / nopmd headers, included from
 *     arch/mips/include/asm/pgtable-{32,64}.h.  The selection
 *     condition changed over time but always reduces to "one nop
 *     header per missing level": v3.10-v5.4 test CONFIG_PAGE_SIZE_*
 *     directly (v4.11-v5.9 wrap them in the __ARCH_USE_5LEVEL_HACK
 *     chain, whose nop4d-hack.h / 5level-fixup.h headers supply the
 *     same trivial p4d_* macros as the later nop4d.h), and from
 *     v5.5 on the chain is written in terms of CONFIG_PGTABLE_LEVELS
 *     (==2 -> nopmd, ==3 -> nopud, else nop4d).  Note the v5.4
 *     4-level (4K pages + CONFIG_MIPS_VA_BITS_48) case selects no
 *     nop header at all and trips the consistency #error in
 *     asm-generic/pgtable.h upstream, i.e. such kernels do not
 *     build; 4-level became viable with the v5.5 chain.
 *   - pgd_none()/pgd_present() therefore exist on every MIPS config
 *     but are the trivial folded macros (return 0 / 1): the real
 *     top-level check on MIPS lives one level down, because empty
 *     pgd/pmd entries point at the invalid_pmd_table /
 *     invalid_pte_table sentinel tables and MIPS defines its own
 *     pmd_none()/pmd_present() (pmd_val() != invalid_pte_table) in
 *     pgtable-{32,64}.h on every version, folded or not.
 *   - A real, non-trivial PUD level exists only for 4-level configs
 *     (CONFIG_MIPS_VA_BITS_48 with 4K pages, viable from v5.5);
 *     there MIPS defines pud_none()/pud_present() (pud_val() !=
 *     invalid_pmd_table).  MIPS guards those with
 *     #ifndef __PAGETABLE_PMD_FOLDED, so they also exist on 3-level
 *     configs (where they duplicate the pmd check harmlessly); only
 *     2-level configs lack them, and those also lack a PUD level.
 *     This header references pud_none()/pud_present() only when
 *     __PAGETABLE_PUD_FOLDED is undefined (the macro the kernel's
 *     own folding headers define exactly when the PUD level is
 *     folded), i.e. only on 4-level configs where the macros exist.
 *   - 4.11 split the generic walk onto a folded p4d level; before
 *     that pud_offset() takes (pgd_t *, addr) and no p4d_t exists.
 *   - pte_present() is _PAGE_PRESENT based in all CPU variants on
 *     all versions.  With CONFIG_PHYS_ADDR_T_64BIT && CONFIG_CPU_MIPS32
 *     (XPA) pte_t carries {pte_low, pte_high} and pte_present() reads
 *     pte_low, so XPA needs - and gets - no special casing here; the
 *     generic macros hide it (pgtable.h v3.10-v6.12, both branches).
 *   - pmd_trans_huge() exists on MIPS since v3.10 but only under
 *     CONFIG_TRANSPARENT_HUGEPAGE, and is a plain _PAGE_HUGE bit
 *     test; _PAGE_HUGE is a low software bit (< PAGE_SHIFT, under
 *     CONFIG_MIPS_HUGE_TLB_SUPPORT), so page-aligned next-level table
 *     pointers can never alias it.  pmd_present() is the sentinel
 *     comparison and stays true for a huge leaf.  Huge PMDs are THP /
 *     hugetlb only; the vmalloc/module area is always mapped with
 *     base pages, so this branch is defence in depth, as on x86_64.
 *   - pte_offset_kernel() is defined by pgtable-{32,64}.h through
 *     v5.4 and by the generic default in include/linux/pgtable.h
 *     from v5.8 (MIPS stopped defining it in 5.8+); both reduce to
 *     (pte_t *)pmd_page_vaddr(*pmd) + pte_index(), and
 *     pmd_page_vaddr(pmd) == pmd_val(pmd) holds on all versions.
 *     Because unpopulated levels point at the statically allocated
 *     invalid_*_table sentinels, the walk never dereferences an
 *     unmapped page-table page.
 *
 * Module mapping space (verified against arch/mips/kernel/module.c
 * and arch/mips/include/asm/pgtable-64.h on the same versions):
 *
 *   - MIPS64 kernels built with -msym32 (KBUILD_64BIT_SYM32, added by
 *     arch/mips/Makefile when the load address is below CKSEG0 and the
 *     toolchain supports it) define MODULE_START = CKSSEG and
 *     MODULE_END = FIXADDR_START - 2 * PAGE_SIZE in pgtable-64.h
 *     under exactly the condition used by arch/mips/kernel/module.c's
 *     module_alloc() override (v3.10 through v6.9).  Testing
 *     #ifdef MODULE_START after including <asm/pgtable.h> reproduces
 *     the kernel's own decision, including the CONFIG_MODULES term.
 *   - Every other kernel (all MIPS32, MIPS64 without -msym32, and -
 *     from v6.10, when MIPS lost its module_alloc() override and the
 *     execmem default range took over, see mm/execmem.c - all MIPS64)
 *     allocates modules from the VMALLOC area, i.e. the generic
 *     module_alloc() range VMALLOC_START .. VMALLOC_END.
 *     v6.10 renamed MODULE_START/MODULE_END to MODULES_VADDR/
 *     MODULES_END (same values, still guarded by KBUILD_64BIT_SYM32)
 *     but module allocation no longer uses them; they remain defined
 *     for arch/mips/mm/fault.c only.  This header therefore
 *     deliberately does NOT scan MODULES_VADDR on 6.10+.
 *   - The full 64-bit ranges span up to ~1TB ((1 << cpu_vmbits) -
 *     4GB), which is un-scannable within mod_hunter's hard cap
 *     (MH_SCAN_HARD_CAP * MH_SCAN_STEP = 2GB of address space);
 *     vmalloc/execmem first-fit packs allocations at the low end, so
 *     the scan covers a conservative 256MB window there.  The MIPS32
 *     VMALLOC range is ~896MB (56M steps at 0x10) and is scanned in
 *     full.
 */
#ifndef ALIRT_ARCH_MIPS_MM_H
#define ALIRT_ARCH_MIPS_MM_H

#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/errno.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
/*
 * From 5.8 the generic page-table API lives in linux/pgtable.h, which
 * includes <asm/pgtable.h> itself (and pulls in the MIPS nop* folding
 * chain).  On 5.8-6.4 MIPS's own pgtable.h still appends
 * <asm-generic/pgtable.h>; from 6.1 that file is gone and
 * linux/pgtable.h is the only aggregator - either way this one
 * include yields every macro used below.
 */
#  include <linux/pgtable.h>
#else
#  include <asm/pgtable.h>
#endif

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
 * Walk the page tables to verify that [addr, addr+size) is fully
 * mapped.  Level folding (2/3/4 levels: 64K/16K pages, 4K/8K pages,
 * and 4K+VA48 pages) is handled by the kernel's own asm-generic nop*
 * headers, so the same code covers MIPS32 (pgd -> pte), MIPS64
 * 3-level (pgd -> pmd -> pte) and MIPS64 4-level (pgd -> pud -> pmd ->
 * pte), plus XPA, without further conditionals.  Returns false as soon
 * as any intermediate page-table entry is missing.
 */
static inline bool alirt_addr_valid(unsigned long addr, size_t size)
{
#if !defined(CONFIG_MMU)
	(void)addr;
	(void)size;
	return false;
#else
	pgd_t *pgd;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
	p4d_t *p4d;
#endif
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	unsigned long end_addr;

	/* Unresolvable init_mm (see alirt_mm_init): fail safe, never
	 * walk a NULL mm. */
	if (unlikely(!alirt_mm_init_mm))
		return false;

	/* On MIPS these are the trivial folded macros (always present /
	 * never bad); the first real check happens at the pmd level. */
	pgd = pgd_offset(alirt_mm_init_mm, addr);
	if (unlikely(!pgd) || unlikely(pgd_none(*pgd)) || unlikely(!pgd_present(*pgd)))
		return false;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
	/* p4d is always folded into pgd on MIPS (no 5-level paging);
	 * trivial check, kept for structural parity with the x86_64
	 * walk. */
	p4d = p4d_offset(pgd, addr);
	if (unlikely(!p4d) || unlikely(p4d_none(*p4d)) || unlikely(!p4d_present(*p4d)))
		return false;
	pud = pud_offset(p4d, addr);
#ifndef __PAGETABLE_PUD_FOLDED
	/*
	 * Only reached when the PUD level is real (MIPS64 4-level,
	 * CONFIG_MIPS_VA_BITS_48, viable from v5.5): MIPS then defines
	 * genuine pud_none()/pud_present() (sentinel comparison against
	 * invalid_pmd_table).  On folded configs those macros may not
	 * exist at all, which is exactly what __PAGETABLE_PUD_FOLDED
	 * tells us (it is defined by nopud.h / nop4d-hack.h / 4level-
	 * fixup.h whenever the PUD level is folded).
	 */
	if (unlikely(!pud) || unlikely(pud_none(*pud)) || unlikely(!pud_present(*pud)))
		return false;
#endif
#else
	/* pre-4.11: no p4d level, and MIPS had no real PUD level yet
	 * (VA48 arrived in 5.4), so there is nothing to check here. */
	pud = pud_offset(pgd, addr);
#endif

	/*
	 * First real check on every MIPS config: empty pmd entries point
	 * at the invalid_pte_table sentinel (MIPS pmd_none/pmd_present,
	 * defined unconditionally in pgtable-{32,64}.h; when pmd is
	 * folded this compares the pgd entry itself).
	 */
	pmd = pmd_offset(pud, addr);
	if (unlikely(!pmd) || unlikely(pmd_none(*pmd)) || unlikely(!pmd_present(*pmd)))
		return false;

	/*
	 * Huge PMD leaf (THP / hugetlb).  MIPS provides pmd_trans_huge()
	 * from v3.10 onwards but only under CONFIG_TRANSPARENT_HUGEPAGE;
	 * it is a plain _PAGE_HUGE bit test on a low software bit, so a
	 * page-aligned next-level table pointer can never set it.
	 */
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	if (pmd_trans_huge(*pmd)) {
		end_addr = (((addr >> PMD_SHIFT) + 1) << PMD_SHIFT) - 1;
		goto end;
	}
#endif

	/* pte_offset_kernel() is the out-of-tree-safe variant on every
	 * version (generic default on 5.8+, arch macro before that; see
	 * the file header). */
	pte = pte_offset_kernel(pmd, addr);
	if (unlikely(!pte) || unlikely(!pte_present(*pte)))
		return false;

	end_addr = (((addr >> PAGE_SHIFT) + 1) << PAGE_SHIFT) - 1;

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
end:
#endif
	if (end_addr >= addr + size - 1)
		return true;

	return alirt_addr_valid(end_addr + 1, size - (end_addr - addr + 1));
#endif /* CONFIG_MMU */
}

/*
 * Module mapping space.  The #ifdef MODULE_START test mirrors the
 * kernel's own module_alloc() decision (see the file header): MIPS64
 * + KBUILD_64BIT_SYM32 kernels (v3.10 - v6.9) allocate modules in
 * [MODULE_START, MODULE_END) = [CKSSEG, FIXADDR_START - 2P); every
 * other kernel allocates modules from the VMALLOC area.
 */
#ifdef CONFIG_MMU
/*
 * Full 64-bit ranges reach ~1TB, far beyond the mod_hunter scan hard
 * cap (128M steps x 0x10 = 2GB of address space); vmalloc/execmem
 * first-fit packs allocations at the low end, so a conservative 256MB
 * window is scanned there.  Must stay below the hard cap: 256MB at
 * step 0x10 is 16M steps.
 */
#  define ALIRT_MIPS_MOD_SCAN_SIZE	(256UL << 20)

#  if defined(MODULE_START)
	/* 64-bit, -msym32, v3.10 - v6.9 */
#    define ALIRT_MOD_START	MODULE_START
#    define ALIRT_MOD_END	(MODULE_START + ALIRT_MIPS_MOD_SCAN_SIZE)
#  elif defined(CONFIG_64BIT)
	/*
	 * 64-bit without -msym32 on any version, and every 64-bit kernel
	 * from v6.10 onwards (arch module_alloc override removed; modules
	 * come from the execmem default range = the VMALLOC area).
	 */
#    define ALIRT_MOD_START	VMALLOC_START
#    define ALIRT_MOD_END	(VMALLOC_START + ALIRT_MIPS_MOD_SCAN_SIZE)
#  else
	/*
	 * MIPS32: no MODULE_START on any version; generic module_alloc()
	 * uses the whole VMALLOC range.  ~896MB = 56M steps at 0x10,
	 * under the mod_hunter hard cap, so scan it in full.
	 */
#    define ALIRT_MOD_START	VMALLOC_START
#    define ALIRT_MOD_END	VMALLOC_END
#  endif
#else /* !CONFIG_MMU */
#  define ALIRT_MOD_START	0UL
#  define ALIRT_MOD_END		0UL
#endif /* CONFIG_MMU */

static inline unsigned long alirt_modules_start(void)
{
	return ALIRT_MOD_START;
}

static inline unsigned long alirt_modules_end(void)
{
	return ALIRT_MOD_END;
}

static inline bool alirt_is_module_space(const void *p)
{
	return (unsigned long)p >= ALIRT_MOD_START &&
	       (unsigned long)p < ALIRT_MOD_END;
}

#endif /* ALIRT_ARCH_MIPS_MM_H */
