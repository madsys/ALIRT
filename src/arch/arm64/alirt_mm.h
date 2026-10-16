/* SPDX-License-Identifier: GPL-3.0-only */
/*
 * ALIRT — arm64 (AArch64) address-space adaptation layer
 *
 * Drop-in replacement for the x86_64 header of the same name: the public
 * interface (alirt_mm_init / alirt_addr_valid / alirt_modules_start /
 * alirt_modules_end / alirt_is_module_space) is byte-for-byte identical,
 * so integration only has to switch the include path.
 *
 * Coverage: Linux 3.7 (first arm64 kernel) through 7.2+, all page sizes
 * (4K / 16K / 64K) and all translation-table depths (2 ~ 5 levels).
 *
 * Design notes, all verified against kernel.org sources:
 *
 *  1. init_mm is resolved through kallsyms exactly like the x86_64 layer
 *     (init_mm is not exported on any supported kernel; see the file
 *     header there).  Until alirt_mm_init() succeeds, alirt_addr_valid()
 *     degrades to always-false and never dereferences a NULL mm.
 *
 *  2. Descriptor model.  On arm64 a zero-valued entry at any level is an
 *     invalid/unpopulated descriptor, and every valid descriptor (table,
 *     block or page) has bit 0 set.  "mapped" therefore reduces to
 *     entry != 0 at the upper levels and pte_present() at the leaf.
 *
 *  3. Folded levels.  arm64 folds unused translation levels into their
 *     parent via <asm-generic/pgtable-nop{4d,pud,md}.h>:
 *       - 3.7 - 3.x : folded headers pulled in by
 *         asm/pgtable-{2,3}level-types.h (asm/page.h)
 *       - 4.0       : asm/pgtable-types.h (introduced)
 *       - 5.8+      : same, plus a real p4d API on top
 *     The level count is CONFIG_ARM64_PGTABLE_LEVELS on 3.7-4.0 and was
 *     renamed to the generic CONFIG_PGTABLE_LEVELS in 4.1; ALIRT_PGTABLE_
 *     LEVELS below abstracts the two.  The Kconfig table is authoritative:
 *       4K : VA39 = 3, VA48 = 4, VA52 = 5 (VA52/4K since ~6.7, in 6.12)
 *       16K: VA36 = 2, VA47 = 3, VA48/52 = 4
 *       64K: VA42 = 2, VA48/52 = 3
 *     The walk simply uses the generic p?d_offset()/p?d_none() macros; the
 *     nop* headers and/or arch code make them exist for every level count,
 *     so no page-size conditionals are needed here.  Note the nop* headers
 *     provide *vacuous* none-tests for the levels they fold away (e.g.
 *     pgd_none() = { return 0; } in pgtable-nopud.h); the real entry check
 *     then happens one step down, on the same underlying entry.
 *     Top-level checking is folding-aware (see alirt_addr_valid): on
 *     2-4-level builds the raw pgd slot IS the top entry, but on 5-level
 *     builds (4K+VA52) pgd_index() covers bits [51:48] — constant across
 *     kernel space — so when the tables are runtime-folded (no LVA52) the
 *     pgd slot is stale and the real top entry is the folded p4d selected
 *     inside p4d_offset(); the raw pgd value is only tested when
 *     pgtable_l5_enabled() is true.
 *
 *  4. The p4d level.  arm64 grew a p4d-aware pud_offset() in 5.8
 *     (pud_offset_phys() switched from pgd_page_paddr() to
 *     p4d_page_paddr(), LPA2 preparation).  From 5.8 on the p4d step is
 *     walked unconditionally: p4d_offset()/p4d_none() exist for every
 *     config (real p4d when CONFIG_PGTABLE_LEVELS > 4, folded via
 *     pgtable-nop4d.h otherwise; on 6.12+ the arch definitions are
 *     runtime-folding aware via pgtable_l4_enabled()).  Before 5.8 the
 *     p4d type does not exist at all and pud_offset() takes pgd_t *.
 *
 *  5. Block (huge page / section) mappings.  The kernel linear map is
 *     built from block descriptors: PMD blocks (2M @4K, 32M @16K,
 *     512M @64K) whenever CONFIG_PGTABLE_LEVELS > 2, PUD blocks
 *     (1G @4K, 64G @16K) when > 3 (possible since 3.17, when 48-bit VA
 *     introduced the 4-level shape), and 512G p4d blocks with 52-bit VA
 *     when > 4.  A block descriptor matches (val & PMD_TYPE_MASK) ==
 *     PMD_TYPE_SECT at any level (the 2-bit descriptor encoding is
 *     level-independent), which is what pmd_sect()/pud_sect() test.
 *     pmd_sect()/pud_sect() exist since 3.16/3.17 for every config (the
 *     arch stubs them to 0 where a level is folded); on 3.7-3.15 only
 *     PMD blocks can occur (the PUD level is always folded there), so
 *     the PUD block test collapses to false and the PMD test uses the
 *     raw PMD_TYPE_* bits, which asm/pgtable-hwdef.h defines unguarded
 *     on every version since 3.7.  For CONFIG_PGTABLE_LEVELS <= 2 the
 *     PMD level is folded into the pgd entry, PMD_SHIFT is undefined,
 *     and the raw descriptor test is applied to the folded entry.
 *     A candidate under a block descriptor is validated exactly like
 *     arm64's own kern_addr_valid(): the descriptor's PFN plus the
 *     candidate's offset inside the block must pass pfn_valid().
 *     A block maps contiguous physical RAM by construction, so on
 *     success the walk skips the whole block; blocks covering
 *     nonexistent physical memory (kernel-image slot padding, vmemmap
 *     holes) fail the PFN check.  Genuine modules are pte-mapped, but
 *     the scan window ([THIS_MODULE-1G, THIS_MODULE+1G)) also spans
 *     the kernel image (partly block-mapped, e.g. .data holding
 *     init_mm) and the direct map.
 *
 *  6. Leaf check.  pte_present() exists on every arm64 kernel from 3.7
 *     through 7.2 (it tests PTE_VALID; from 4.4 on it additionally
 *     admits PTE_PROT_NONE, from 6.12 on pte_present_invalid() swap
 *     markers).  pte_valid() does NOT exist on 3.7-3.15 (verified: absent
 *     in v3.7/v3.10, present from v3.16), so it cannot be used portably.
 *     All three extensions only widen the test for entries that never
 *     occur in the module space (PROT_NONE is a user-addressing artefact,
 *     swapped-out pages are never kernel modules), so pte_present() is
 *     the correct cross-version "mapped and kernel-readable" predicate:
 *     on arm64 EL1 reads ignore AP[] and PXN/UXN, hence any valid
 *     descriptor is readable by this code.
 */
#ifndef ALIRT_ARCH_ARM64_MM_H
#define ALIRT_ARCH_ARM64_MM_H

#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/errno.h>
#include <linux/module.h>	/* THIS_MODULE (module-layout anchor below) */

#include <asm/pgtable.h>	/* p?d_offset / p?d_none / pte_present / *_TYPE_* */
#include <asm/memory.h>		/* MODULES_VADDR / MODULES_END (all versions) */

/*
 * Translation-table depth.  arm64 used its own CONFIG_ARM64_PGTABLE_LEVELS
 * (Kconfig) until the symbol was renamed to the generic
 * CONFIG_PGTABLE_LEVELS in 4.1 (verified: v4.0 Kconfig vs v4.1 Kconfig).
 */
#if defined(CONFIG_ARM64_PGTABLE_LEVELS)
#  define ALIRT_PGTABLE_LEVELS CONFIG_ARM64_PGTABLE_LEVELS
#else
#  define ALIRT_PGTABLE_LEVELS CONFIG_PGTABLE_LEVELS
#endif

/*
 * Resolved address of the init_mm data symbol (see note 1).  Per-TU
 * static, same ownership model as the x86_64 header.
 */
static struct mm_struct *alirt_mm_init_mm;

/* Saved kln pointer for the deferred self-test (alirt_selftest_once). */
static unsigned long (*alirt_kln_saved)(const char *name);

/*
 * Resolve init_mm through kallsyms.  @kln is a working
 * kallsyms_lookup_name (see alirt_resolve_kln() in compat.h; NULL is
 * tolerated).  Returns 0 on success; until then, and on failure,
 * alirt_addr_valid() reports every address as unvalidated.
 *
 * The init-time walker self-test is NOT run here: calling
 * alirt_addr_valid() before its definition needs a forward
 * declaration, and old GCC (<= 7, the Ubuntu 16.04/18.04 era images in
 * CI) rejects a forward-declared always_inline function that refers to
 * itself recursively ("inlining failed in call to always_inline
 * 'alirt_addr_valid': recursive inlining").  It runs once, deferred,
 * at the first alirt_modules_start() call instead (see
 * alirt_selftest_once).
 */
static inline int alirt_mm_init(unsigned long (*kln)(const char *name))
{
	if (!kln)
		return -EINVAL;
	alirt_mm_init_mm = (struct mm_struct *)kln("init_mm");
	alirt_kln_saved = kln;

	return alirt_mm_init_mm ? 0 : -ENOENT;
}

/*
 * Block-descriptor (section) predicates, per level.  Only levels that
 * physically exist (ALIRT_PGTABLE_LEVELS) can hold blocks; folded levels
 * are skipped and the entry is re-examined at the deepest real level,
 * where the level-independent type encoding still identifies a block
 * (the span then comes from that level's shift).
 *
 * Block (section) descriptors are identified by the level-independent
 * 2-bit type encoding, (val & *_TYPE_MASK) == *_TYPE_SECT — exactly
 * what pmd_sect()/pud_sect() tested from 3.16/3.17 until they were
 * removed in 7.2 (pmd_leaf()/pud_leaf() took over).  The raw test is
 * used here instead: PMD_TYPE_MASK/PMD_TYPE_SECT are defined unguarded
 * in asm/pgtable-hwdef.h on every kernel since 3.7, and PUD_TYPE_MASK/
 * PUD_TYPE_SECT since the 3.17 48-bit VA series (i.e. whenever the PUD
 * level can physically exist — the only configs where the PUD test is
 * expanded).  The call sites below additionally gate on
 * ALIRT_PGTABLE_LEVELS, which is what keeps the PUD test out of builds
 * whose PUD level is folded.
 */
#define alirt_pmd_is_block(pmd) \
	((pmd_val(pmd) & PMD_TYPE_MASK) == PMD_TYPE_SECT)
#if ALIRT_PGTABLE_LEVELS > 3
#  define alirt_pud_is_block(pud) \
	((pud_val(pud) & PUD_TYPE_MASK) == PUD_TYPE_SECT)
#else
#  define alirt_pud_is_block(pud) 0
#endif

/*
 * Walk the page tables for the mapping that covers @addr.  Handles
 * every arm64 translation-table shape (2-5 levels, 4K/16K/64K pages,
 * runtime-folded LPA2 tables on 6.x); on success stores the first
 * address past the mapping in *@next (PAGE_SIZE for a pte leaf, the
 * block size for a validated block) and returns true, and returns
 * false as soon as any intermediate page-table entry is missing.
 *
 * Leaf validity is the arm64 kern_addr_valid() rule: a descriptor is
 * accepted only when the PFN it maps for @addr passes pfn_valid().
 * Page-table walking alone cannot tell whether the mapped physical
 * page actually exists — the kernel-image slot, the module region
 * after RANDOMIZE_MODULE_REGION_FULL and vmemmap holes all contain
 * descriptors that translate to nonexistent memory, and reading them
 * takes a synchronous external abort.  pfn_valid() rejects exactly
 * those (observed on 4.19/5.4/5.10: a scan-time deref at such an
 * address oops'd the guest) while accepting everything genuinely
 * RAM-backed, including the block-mapped .data page holding init_mm.
 */
static inline bool alirt_page_mapped(unsigned long addr, unsigned long *next)
{
	pgd_t *pgd;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	p4d_t *p4d;
#endif
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	/* Kernel threads have current->mm == NULL; the kernel address
	 * space is identical for every mm, so use init_mm (swapper_pg_dir).
	 * Unresolvable (see alirt_mm_init): fail safe, never walk a NULL
	 * mm. */
	if (unlikely(!alirt_mm_init_mm))
		return false;
	pgd = pgd_offset(alirt_mm_init_mm, addr);
	/* Top-level validity, folding-aware.  A zero entry is an invalid
	 * descriptor at every arm64 level, but WHICH slot holds the top
	 * entry depends on the runtime fold state on 5-level builds
	 * (4K pages + VA52/LPA2, 6.7+): pgd_index() covers bits [51:48],
	 * which are constant across the whole kernel half of the address
	 * space, so on hardware without LVA52 (tables folded at runtime)
	 * it selects a stale slot — the true top entry is the folded p4d
	 * chosen inside p4d_offset() (pgd_to_folded_p4d, indexed by bits
	 * [47:39]).  Only test the raw pgd slot when l5 is enabled (or on
	 * 2-4-level builds, where pgd_index is the true top index and the
	 * p4d level is compile-time folded into the pgd, making the raw
	 * pgd value the top entry — the nop* folding the file header note 3
	 * describes).  The p4d_none() test below then validates the real
	 * top entry in every configuration. */
	if (unlikely(!pgd))
		return false;
#if ALIRT_PGTABLE_LEVELS > 4
	if (pgtable_l5_enabled() && unlikely(!pgd_val(*pgd)))
		return false;
#else
	if (unlikely(!pgd_val(*pgd)))
		return false;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	/* 5.8+ : pud_offset() takes p4d_t *.  p4d_offset()/p4d_none() exist
	 * for every level count (folded via pgtable-nop4d.h, runtime-fold
	 * aware on 6.12+); when the p4d level is folded the checks pass
	 * through to the real top entry selected here. */
	p4d = p4d_offset(pgd, addr);
	if (unlikely(!p4d) || unlikely(p4d_none(*p4d)))
		return false;

	/* p4d-level block (512G, 4K pages + 52-bit VA): only exists when
	 * the p4d level is real; P4D_SHIFT/P4D_TYPE_* are defined under the
	 * same CONFIG_PGTABLE_LEVELS > 4 guard in asm/pgtable-hwdef.h.
	 * Blocks are rejected (see the function header). */
#  if ALIRT_PGTABLE_LEVELS > 4
	if (unlikely((p4d_val(*p4d) & P4D_TYPE_MASK) == P4D_TYPE_SECT))
		return false;
#  endif
	pud = pud_offset(p4d, addr);
#else
	/* 3.7-5.7 : no p4d API, pud_offset() takes pgd_t * and the p4d
	 * level is folded into the pgd by construction. */
	pud = pud_offset(pgd, addr);
#endif
	if (unlikely(!pud) || unlikely(pud_none(*pud)))
		return false;

	/* PUD-level block (1G @4K, 64G @16K): only when the PUD level
	 * physically exists.  Accepted when the candidate's PFN inside the
	 * block passes pfn_valid(); the whole block is then skipped (see
	 * note 5).  The PFN is extracted from the descriptor itself -
	 * (val & PHYS_MASK) >> PAGE_SHIFT - exactly what the arch's
	 * pud_pfn() computes, without depending on its availability. */
#if ALIRT_PGTABLE_LEVELS > 3
	if (unlikely(alirt_pud_is_block(*pud))) {
		unsigned long pfn = (pud_val(*pud) & PHYS_MASK) >> PAGE_SHIFT;

		pfn += (addr & ~PUD_MASK) >> PAGE_SHIFT;
		if (unlikely(!pfn_valid(pfn)))
			return false;
		*next = (addr & PUD_MASK) + PUD_SIZE;
		return true;
	}
#endif

	pmd = pmd_offset(pud, addr);
	if (unlikely(!pmd) || unlikely(pmd_none(*pmd)))
		return false;

	/* PMD-level block (2M @4K, 32M @16K, 512M @64K): same rule as the
	 * PUD block above.  With 2-level tables the PMD level is folded
	 * into the pgd entry, PMD_MASK/PMD_SIZE are undefined, and the raw
	 * descriptor test is used there; such folded top-level blocks are
	 * conservatively rejected (the scan window never needs them). */
#if ALIRT_PGTABLE_LEVELS > 2
	if (unlikely(alirt_pmd_is_block(*pmd))) {
		unsigned long pfn = (pmd_val(*pmd) & PHYS_MASK) >> PAGE_SHIFT;

		pfn += (addr & ~PMD_MASK) >> PAGE_SHIFT;
		if (unlikely(!pfn_valid(pfn)))
			return false;
		*next = (addr & PMD_MASK) + PMD_SIZE;
		return true;
	}
#else
	if (unlikely((pmd_val(*pmd) & PMD_TYPE_MASK) == PMD_TYPE_SECT))
		return false;
#endif

	/* Leaf.  pte_present() exists on every arm64 kernel 3.7-7.2 and
	 * is true exactly for valid (bit 0 set) page descriptors among the
	 * entries that can occur in kernel space (see note 6).  The
	 * pfn_valid() gate is what keeps a descriptor that translates to
	 * nonexistent physical memory from being dereferenced (see the
	 * function header). */
	pte = pte_offset_kernel(pmd, addr);
	if (unlikely(!pte) || unlikely(!pte_present(*pte)))
		return false;
	if (unlikely(!pfn_valid((pte_val(*pte) & PHYS_MASK) >> PAGE_SHIFT)))
		return false;

	*next = (addr & PAGE_MASK) + PAGE_SIZE;
	return true;
}

/*
 * Verify that [addr, addr+size) is fully mapped.  Iterates page by page
 * through alirt_page_mapped(); expressed as a loop rather than tail
 * recursion because old GCC (<= 7, the Ubuntu 16.04/18.04 era CI
 * images) rejects recursive always_inline functions outright
 * ("inlining failed in call to always_inline 'alirt_page_mapped':
 * recursive inlining") even when the recursive call sits inside the
 * function's own complete definition (observed on aarch64 4.4 with gcc
 * 5.4).
 */
static inline bool alirt_addr_valid(unsigned long addr, size_t size)
{
	unsigned long end = addr + size;

	while (addr < end) {
		unsigned long next;

		if (!alirt_page_mapped(addr, &next) || next <= addr)
			return false;
		addr = next;
	}
	return true;
}

/*
 * One-shot walker self-test, run from the first alirt_modules_start()
 * call (immediately before the first real scan).  Deferred there —
 * instead of running inside alirt_mm_init() — because at that point
 * alirt_addr_valid() is fully defined and no forward declaration is
 * needed (old GCC rejects the forward-declared recursive always_inline;
 * see alirt_mm_init).  Probes the walker against three known-mapped
 * landmarks — init_mm itself (kernel-image .data), our own struct
 * module (execmem/module range, KASLR-placed), and linux_banner
 * (.rodata) — so a walker that silently rejects everything fails loudly
 * here instead of producing an empty scan report.  Quiet on success;
 * warns (once) with per-landmark results otherwise.
 */
static inline void alirt_selftest_once(unsigned long (*kln)(const char *))
{
	static bool alirt_selftest_done;
	unsigned long tm, bn, sw;
	int vim, vtm, vbn;

	if (alirt_selftest_done)
		return;
	alirt_selftest_done = true;
	if (!kln)
		return;

	tm = (unsigned long)THIS_MODULE;
	bn = kln("linux_banner");
	sw = kln("swapper_pg_dir");
	vim = alirt_mm_init_mm ? alirt_addr_valid((unsigned long)alirt_mm_init_mm, 64) : -1;
	vtm = alirt_addr_valid(tm, 64);
	vbn = bn ? alirt_addr_valid(bn, 64) : -1;
	if (!vim || !vtm || (bn && !vbn))
		pr_warn("alirt: arm64 self-test FAILED: init_mm=%px(valid=%d,"
			"pgd=%px) this_module=%lx(valid=%d) banner=%lx(valid=%d)"
			" swapper=%lx\n",
			alirt_mm_init_mm, vim,
			alirt_mm_init_mm ? alirt_mm_init_mm->pgd : NULL,
			tm, vtm, bn, vbn, sw);
}

/* arm64 module mapping space.
 *
 * MODULES_VADDR / MODULES_END are defined in asm/memory.h on every
 * version, but since the module_alloc() randomization era (the
 * module_direct_base/module_plt_base bounding boxes, arch/arm64
 * 4.6-6.8 kernel/module.c, arch/arm64/mm/init.c execmem setup 6.9+)
 * they no longer describe where modules actually land: with KASLR the
 * kernel image sits at KIMAGE_VADDR + offset inside a 2G range, and
 * modules are first-fit allocated from a per-boot randomized bounding
 * box containing the image (a 128M direct-branch box, or the full 2G
 * PLT box when CONFIG_RANDOMIZE_MODULE_REGION_FULL=y — which
 * defconfig enables, printing "2G module region forced by
 * RANDOMIZE_MODULE_REGION_FULL" at boot).  That box can lie entirely
 * ABOVE MODULES_END (observed in CI: 0 candidates on the 6.12/6.18/7.2
 * runtime jobs even though the scanned window exactly matched the
 * compile-time [MODULES_VADDR, MODULES_END) range and the candidate
 * gate was fixed), so a scanner limited to the fixed window is blind
 * on every randomized boot.
 *
 * mod_hunter itself is a module allocated from the same execmem/vmalloc
 * range, and mod_hunter.c's MH_SCAN_HARD_CAP (2G / MH_SCAN_STEP steps)
 * cannot cover the whole 4G+ span the box can occupy anyway.  Anchor
 * the window on our own struct module instead: [THIS_MODULE - 1G,
 * THIS_MODULE + 1G) always contains every module co-allocated with us
 * (first-fit allocations are adjacent — the CI loads hide_self right
 * before mod_hunter), and covers half of the randomized box in the
 * worst case.  THIS_MODULE is NULL only for built-in code, which
 * mod_hunter never is; fall back to the fixed window defensively.
 */
static inline unsigned long alirt_modules_start(void)
{
	unsigned long tm = (unsigned long)THIS_MODULE;

	/* First scan about to start: run the deferred walker self-test. */
	alirt_selftest_once(alirt_kln_saved);
	return tm ? tm - (1UL << 30) : MODULES_VADDR;
}

static inline unsigned long alirt_modules_end(void)
{
	unsigned long tm = (unsigned long)THIS_MODULE;
	return tm ? tm + (1UL << 30) : MODULES_END;
}

static inline bool alirt_is_module_space(const void *p)
{
	return (unsigned long)p >= alirt_modules_start() &&
	       (unsigned long)p < alirt_modules_end();
}

/*
 * mod_hunter.c's mh_ptr_high_or_zero() rejects any candidate list pointer
 * below VMALLOC_START — an x86-centric gate.  Since the arm64 VA-layout
 * consolidation (6.9+) VMALLOC_START == MODULES_END, i.e. the entire
 * dedicated module window [MODULES_VADDR, MODULES_END) sits below it, so
 * every genuine struct module (mod_hunter itself included) was rejected
 * and the scan reported zero candidates.  Pointer validity is already
 * enforced per-arch by alirt_addr_valid(), and the sext48/57 shape check
 * that follows accepts both the module window (0xffff80...) and the
 * direct map (0xffff00...), so lower the first gate to "any non-NULL
 * pointer".  This header is included last in mod_hunter.c (after
 * <linux/vmalloc.h>), and nothing above this point in the file uses the
 * macro, so neutralizing it here affects only the candidate gate.
 */
#undef VMALLOC_START
#define VMALLOC_START 0UL

#endif /* ALIRT_ARCH_ARM64_MM_H */
