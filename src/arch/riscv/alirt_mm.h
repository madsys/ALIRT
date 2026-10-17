/* SPDX-License-Identifier: GPL-3.0-only */
/*
 * ALIRT — riscv address-space adaptation layer
 *
 * Provides, across 4.19 ~ 7.2 (rv64 sv39/sv48/sv57, rv32 sv32):
 *   1. Kernel virtual-address validity checks (multi-level page-table
 *      walk, fault-safe)
 *   2. The module mapping space (version-dependent, see below)
 *
 * Contract and init_mm handling are identical to the x86_64 layer in
 * src/arch/x86_64/alirt_mm.h: init_mm is not exported on any supported
 * kernel, so every consumer resolves it through kallsyms by calling
 * alirt_mm_init() once, right after alirt_resolve_kln() (compat.h).
 * Until that succeeds - and whenever it cannot (init_mm is a data
 * symbol, so it only appears in kallsyms with CONFIG_KALLSYMS_ALL) -
 * alirt_addr_valid() degrades to always-false instead of walking a
 * NULL mm.
 *
 * Page-table walk, per version (all verified against upstream tags):
 *
 *   4.19 ~ 5.15  PGTABLE_LEVELS=3 (rv64, sv39 only; VA_BITS is a
 *                 compile-time Kconfig constant) / 2 (rv32, sv32).
 *                 p4d and pud are compile-time folded
 *                 (asm-generic/pgtable-nop4d.h / -nopud.h, the latter
 *                 included unconditionally by asm/pgtable.h), pmd is
 *                 folded too on rv32 (pgtable-32.h includes
 *                 asm-generic/pgtable-nopmd.h).  riscv's own
 *                 pgd_offset()/pte_offset_kernel() live in
 *                 asm/pgtable.h up to v5.4; from v5.10 (creation of
 *                 include/linux/pgtable.h in the 5.9 mm cleanup) the
 *                 #ifndef-guarded generic versions take over.  All of
 *                 these are macros or static inlines - module-safe.
 *   6.1 ~ 6.5     PGTABLE_LEVELS=5; sv48/sv57 are selected at runtime
 *                 via the EXPORT_SYMBOL'ed bools pgtable_l4_enabled /
 *                 pgtable_l5_enabled.  pud_offset()/p4d_offset() are
 *                 still static inline in asm/pgtable-64.h - the plain
 *                 macro chain keeps working.
 *   6.6 ~ 6.18    pud_offset()/p4d_offset() became OUT-OF-LINE
 *                 functions in arch/riscv/mm/pgtable.c and are NOT
 *                 exported, so an out-of-tree module referencing them
 *                 fails to load ("Unknown symbol pud_offset").  They
 *                 are re-expanded here, exactly as the vmlinux
 *                 functions do, from header inlines only.
 *   7.2           EXPORT_SYMBOL_GPL(pud_offset/p4d_offset) returned,
 *                 but the manual expansion is kept: it is identical in
 *                 behaviour and avoids a GPL-export dependency.
 *
 * Fault-safety note: on folded levels the asm-generic *_none()/
 * *_present() helpers are compile-time constant 0/1, so the top-level
 * pgd entry is validated against the architectural V bit
 * (_PAGE_PRESENT) directly before any pointer is chased; every chase
 * below only follows an entry whose V bit was verified.
 *
 * Huge mappings: riscv has no pmd_leaf() before v5.10 (and no huge
 * kernel mappings to miss: THP support only arrived with
 * HAVE_ARCH_TRANSPARENT_HUGEPAGE in v5.15, and huge vmalloc
 * (CONFIG_HAVE_ARCH_HUGE_VMAP) in v6.6), so the leaf branches are
 * compiled out there.  pmd_leaf()/pud_leaf() are riscv header inlines
 * on all later versions and cover PMD (2M) and PUD (1G) leafs; they
 * are rv64-only (rv32 folds pmd/pud into the pgd).
 *
 * Module space, per version (arch/riscv, verified):
 *   4.19 ~ 5.4    no MODULES_VADDR and no arch module_alloc, so the
 *                 generic kernel/module.c allocation is used, which
 *                 runtime-verified on v5.4.290 places at
 *                 PFN_ALIGN(_end) - SZ_2G, growing up to VMALLOC_END
 *                 (= PAGE_OFFSET - 1, inclusive) - i.e. the 2GB
 *                 span below the kernel image, NOT the vmalloc bottom
 *                 (the boot-time ioremaps land there).  The floor is
 *                 recomputed from kallsyms; _end is a data symbol, so
 *                 it needs CONFIG_KALLSYMS_ALL (present in the CI
 *                 config).  Without it the static top-2GB window
 *                 [VMALLOC_END + 1 - SZ_2G, VMALLOC_END + 1) of the
 *                 vmalloc area is scanned instead.
 *   5.10 ~ 5.12   module_alloc = __vmalloc_node_range(
 *                 max(PFN_ALIGN(&_end - SZ_2G), VMALLOC_START),
 *                 VMALLOC_END, ...): a runtime floor in the vmalloc
 *                 area.  The same 2GB window from that floor is used.
 *   5.13+ (rv64)  dedicated window below the kernel image:
 *                 [PFN_ALIGN(&_end) - SZ_2G, PFN_ALIGN(&_start)).
 *                 Both bounds are runtime values (they reference the
 *                 link symbols _start/_end), so they are recomputed
 *                 here from kallsyms; without CONFIG_KALLSYMS_ALL the
 *                 conservative fixed fallback
 *                 [KERNEL_LINK_ADDR - SZ_2G, KERNEL_LINK_ADDR) is
 *                 used (the floor equals 6.1+'s MODULES_LOWEST_VADDR).
 *   rv32 (all)    no dedicated window before 6.12 (and
 *                 MODULES_VADDR/END = VMALLOC_START/END from 6.12);
 *                 the whole vmalloc area (<= 512MB) is scanned.
 */
#ifndef ALIRT_ARCH_RISCV_MM_H
#define ALIRT_ARCH_RISCV_MM_H

#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/version.h>

#include <asm/pgtable.h>

/* 2GB, spelled out to avoid depending on <linux/sizes.h> inclusion
 * details in arch headers of the oldest supported kernels. */
#define ALIRT_RISCV_SZ_2G	(1UL << 31)

/*
 * Resolved address of the init_mm data symbol (see the file header).
 * Per-translation-unit static: each including module owns its copy and
 * feeds it via alirt_mm_init().
 */
static struct mm_struct *alirt_mm_init_mm;

/* Defined below; alirt_mm_init() self-tests the mm fallback through it. */
static inline bool alirt_addr_valid(unsigned long addr, size_t size);

/*
 * Module mapping space, filled in by alirt_mm_init().  Zero (empty
 * range) until then - alirt_is_module_space() is simply false, which
 * is the safe pre-init answer.
 */
static unsigned long alirt_mod_start;
static unsigned long alirt_mod_end;

/*
 * Resolve init_mm through kallsyms and derive the module mapping
 * space (see the file header for the per-version ranges).
 * @kln is a working kallsyms_lookup_name (see alirt_resolve_kln() in
 * compat.h; NULL is tolerated).  Returns 0 on success; until then,
 * and on failure, alirt_addr_valid() reports every address as
 * unvalidated.
 */
static inline int alirt_mm_init(unsigned long (*kln)(const char *name))
{
	if (!kln)
		return -EINVAL;
	alirt_mm_init_mm = (struct mm_struct *)kln("init_mm");
	if (!alirt_mm_init_mm) {
		/*
		 * init_mm is a KALLSYMS_ALL-only data symbol and can be
		 * unresolvable (riscv 5.10 has no HAVE_KPROBES, and >= 5.9
		 * kernel_read cannot open /proc/kallsyms).  Every mm's
		 * kernel half is identical - a user task's own page table
		 * must translate kernel addresses, that is how kernel
		 * faults in syscall context are serviced - so the current
		 * mm is a valid substitute for the walk.  Gate the
		 * substitution on the THIS_MODULE self-test: if this mm's
		 * kernel half cannot map our own struct module, stay
		 * unvalidated rather than walk a foreign layout.
		 */
		struct mm_struct *mm = current->active_mm;

		if (mm) {
			alirt_mm_init_mm = mm;
#if defined(MODULE) && defined(THIS_MODULE)
			if (THIS_MODULE &&
			    !alirt_addr_valid((unsigned long)THIS_MODULE,
					      sizeof(*THIS_MODULE)))
				alirt_mm_init_mm = NULL;
			else
#endif
				pr_warn("alirt: riscv init_mm unresolvable; "
					"using current->active_mm for the "
					"kernel-half walk\n");
		}
	}

#if defined(CONFIG_64BIT)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 13, 0)
	/*
	 * Dedicated module window directly below the kernel image
	 * (arch/riscv/include/asm/pgtable.h):
	 *   MODULES_VADDR = PFN_ALIGN(&_end) - SZ_2G
	 *   MODULES_END   = PFN_ALIGN(&_start)
	 * _start (a text symbol) and _end (a data symbol, so it needs
	 * CONFIG_KALLSYMS_ALL) are recomputed from kallsyms.  Without
	 * them, degrade to the conservative fixed window one 2GB span
	 * below the kernel link address (identical to the floor of
	 * 6.1+'s MODULES_LOWEST_VADDR = KERNEL_LINK_ADDR - SZ_2G).
	 */
	{
		unsigned long start_sym = kln("_start");
		unsigned long end_sym = kln("_end");

		if (start_sym && end_sym) {
			alirt_mod_end = (start_sym + PAGE_SIZE - 1) & PAGE_MASK;
			alirt_mod_start = ((end_sym + PAGE_SIZE - 1) & PAGE_MASK)
					  - ALIRT_RISCV_SZ_2G;
		} else {
			alirt_mod_start = KERNEL_LINK_ADDR - ALIRT_RISCV_SZ_2G;
			alirt_mod_end = KERNEL_LINK_ADDR;
		}
	}
# elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	/*
	 * module_alloc() = __vmalloc_node_range(
	 *	max(PFN_ALIGN(&_end - SZ_2G), VMALLOC_START), VMALLOC_END)
	 * (arch/riscv/kernel/module.c): the vmalloc area growing up from
	 * a runtime floor.  Scan a conservative 2GB window from that
	 * floor; VMALLOC_END is inclusive on these kernels.
	 */
	{
		unsigned long end_sym = kln("_end");

		if (end_sym) {
			unsigned long floor;

			alirt_mod_start = VMALLOC_START;
			floor = ((end_sym + PAGE_SIZE - 1) & PAGE_MASK)
				- ALIRT_RISCV_SZ_2G;
			if (floor > alirt_mod_start)
				alirt_mod_start = floor;
			alirt_mod_end = alirt_mod_start + ALIRT_RISCV_SZ_2G;
			if (alirt_mod_end > VMALLOC_END + 1)
				alirt_mod_end = VMALLOC_END + 1;
		} else {
			/*
			 * No _end (symbol resolution unavailable - e.g. riscv
			 * 5.10 has neither KPROBES nor a readable /proc/kallsyms
			 * since 5.9's kernel_read restriction): the runtime floor
			 * PFN_ALIGN(_end) - SZ_2G sits in the TOP of the vmalloc
			 * area for any realistically sized kernel image, so the
			 * static top-2GB window is the right conservative guess
			 * (same fallback as the 4.19 ~ 5.4 branch below; the
			 * vmalloc bottom is taken by boot-time ioremaps, not
			 * modules).
			 */
			alirt_mod_start = VMALLOC_END + 1 - ALIRT_RISCV_SZ_2G;
			alirt_mod_end = VMALLOC_END + 1;
		}
	}
# else
	/*
	 * 4.19 ~ 5.4: no arch module_alloc, so the generic kernel/module.c
	 * allocation is used; runtime-verified on v5.4.290 (CI dump):
	 * modules start exactly at PFN_ALIGN(_end) - SZ_2G and grow up to
	 * VMALLOC_END (= PAGE_OFFSET - 1, inclusive) - the 2GB span below
	 * the kernel image.  The vmalloc bottom is taken by the boot-time
	 * ioremaps (uart, plic, pci ecam), NOT by modules.  _end needs
	 * CONFIG_KALLSYMS_ALL; without it, fall back to the static
	 * top-2GB window of the vmalloc area, which matches the observed
	 * placement for any realistically sized kernel image.
	 */
	{
		unsigned long end_sym = kln("_end");

		if (end_sym) {
			alirt_mod_start =
				((end_sym + PAGE_SIZE - 1) & PAGE_MASK)
				- ALIRT_RISCV_SZ_2G;
			if (alirt_mod_start < VMALLOC_START)
				alirt_mod_start = VMALLOC_START;
		} else {
			alirt_mod_start = VMALLOC_END + 1 - ALIRT_RISCV_SZ_2G;
		}
		alirt_mod_end = VMALLOC_END + 1;
	}
# endif
#else
	/*
	 * rv32: module allocations come out of the vmalloc area on every
	 * supported version (6.12+ formalizes it as
	 * MODULES_VADDR/MODULES_END = VMALLOC_START/VMALLOC_END).  The
	 * whole region is at most ~512MB, inside the scanner's cap.
	 * VMALLOC_END switched from inclusive (<= 5.15, PAGE_OFFSET - 1)
	 * to exclusive (6.1+, PAGE_OFFSET).
	 */
	alirt_mod_start = VMALLOC_START;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	alirt_mod_end = VMALLOC_END;
#else
	alirt_mod_end = VMALLOC_END + 1;
#endif
#endif

	return alirt_mm_init_mm ? 0 : -ENOENT;
}

/*
 * Walk the page tables for the single mapping that covers @addr and
 * report its extent.  Handles rv64 sv39 (3-level) / sv48 (4-level) /
 * sv57 (5-level) and rv32 sv32 (2-level); on 6.1+ the sv48/sv57 levels
 * are folded at runtime via pgtable_l4_enabled/pgtable_l5_enabled.  On
 * success *@next receives the first address past the mapping covering
 * @addr (PAGE_SIZE for a pte leaf, 2MB for a pmd leaf, 1GB for a pud
 * leaf) and true is returned; on failure *@next is untouched and false
 * is returned as soon as any intermediate page-table entry is missing.
 *
 * Iterative by construction: this function is self-recursive in
 * spirit (a missing leaf used to tail-recurse into the next sub-range),
 * and old GCC (<= 7, e.g. the gcc 7.5 on the 5.4-era builders) refuses
 * to inline any function that calls itself, even through a tail call,
 * with "error: recursive inlining".  The range walk therefore lives in
 * alirt_addr_valid() below, which loops over successive mappings.
 */
static inline bool alirt_page_mapped(unsigned long addr, unsigned long *next)
{
	pgd_t *pgd;
	p4d_t *p4d;
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
	/* The top entry is validated against the architectural V bit:
	 * with compile-time folded levels (all kernels < 6.1, and rv32
	 * always) pgd_none()/pgd_present() are asm-generic constants
	 * 0/1, so the macros would let a missing top-level table through
	 * and the chase below would dereference garbage. */
	if (unlikely(!pgd) || unlikely(!(pgd_val(*pgd) & _PAGE_PRESENT)))
		return false;

#if defined(CONFIG_64BIT) && LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	/*
	 * pud_offset()/p4d_offset() are out-of-line and unexported since
	 * v6.6 (arch/riscv/mm/pgtable.c), so a module cannot call them.
	 * Re-expand them exactly, from header inlines over the runtime
	 * sv48/sv57 switches; the fold cases return the un-indexed parent
	 * entry, matching PTRS_PER_PxD == 1 semantics.
	 */
	if (pgtable_l5_enabled)
		p4d = pgd_pgtable(*pgd) + p4d_index(addr);
	else
		p4d = (p4d_t *)pgd;
	if (unlikely(!p4d_present(*p4d)))
		return false;
	if (pgtable_l4_enabled)
		pud = p4d_pgtable(*p4d) + pud_index(addr);
	else
		pud = (pud_t *)p4d;
	if (unlikely(!pud_present(*pud)))
		return false;
#else
	/* 4.19 ~ 6.5 (and rv32 always): p4d_offset()/pud_offset() are
	 * asm-generic folded inlines or, on 6.1 ~ 6.5 rv64, static
	 * inlines over the runtime sv48/sv57 switches - all module-safe. */
	p4d = p4d_offset(pgd, addr);
	if (unlikely(!p4d) || unlikely(!p4d_present(*p4d)))
		return false;
	pud = pud_offset(p4d, addr);
	if (unlikely(!pud) || unlikely(!pud_present(*pud)))
		return false;
#endif

#if defined(CONFIG_64BIT) && LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	/* pud_leaf() arrived with the hugetlb helpers in v5.10; it also
	 * catches a folded sv39 pgd entry that is a 1GB direct-map leaf.
	 * PUD-sized mappings span 1GB (PUD_SHIFT == 30 on every rv64
	 * kernel, including the runtime-folded 6.1+ ones). */
	if (pud_leaf(*pud)) {
		*next = ((addr >> PUD_SHIFT) + 1) << PUD_SHIFT;
		return true;
	}
#endif

	pmd = pmd_offset(pud, addr);
	if (unlikely(!pmd) || unlikely(pmd_none(*pmd)) ||
	    unlikely(!pmd_present(*pmd)))
		return false;

#if defined(CONFIG_64BIT) && LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
	/* pmd_leaf() covers THP (from v5.15) and huge vmalloc/ioremap
	 * (from v6.6) PMD mappings; earlier kernels have neither, and
	 * riscv gained the helper itself only in v5.10.  rv32 folds pmd
	 * into the pgd and provides no pmd_leaf().  PMD mappings span
	 * 2MB (PMD_SHIFT == 21 on every rv64 kernel). */
	if (pmd_leaf(*pmd)) {
		*next = ((addr >> PMD_SHIFT) + 1) << PMD_SHIFT;
		return true;
	}
#endif

	pte = pte_offset_kernel(pmd, addr);
	/* The pfn_valid() gate rejects ioremap()ped device memory.  On
	 * 4.19 ~ 5.4 module_alloc() is the generic vmalloc_exec() whose
	 * first-fit range starts at VMALLOC_START, exactly where the
	 * boot-time ioremaps (uart, plic, pci ecam, ...) also land; the
	 * vmalloc region therefore mixes RAM-backed module pages with
	 * device pages, and riscv PTEs carry no attribute to tell them
	 * apart (no cacheability/attribute bits in the PTE).  The scanner
	 * treats "mapped" as "safe to dereference as struct module", so
	 * an ioremap page inside the module window must not validate: on
	 * bare metal (and QEMU, which raises access faults for loads from
	 * unimplemented physical addresses) reading it can fault or hit
	 * device side effects.  Modules are always RAM-backed, so
	 * requiring a struct page costs nothing for the intended use.
	 * riscv defaults to FLATMEM, where pfn_valid() is pfn_base <=
	 * pfn < pfn_base + max_mapnr, i.e. exactly "is RAM". */
	if (unlikely(!pte) || unlikely(!pte_present(*pte)) ||
	    unlikely(!pfn_valid(pte_pfn(*pte))))
		return false;

	*next = (addr & PAGE_MASK) + PAGE_SIZE;
	return true;
}

/*
 * Walk the page tables to verify that [addr, addr+size) is fully mapped.
 * Iterates alirt_page_mapped() over successive mappings; PMD (2M) and
 * PUD (1G) leafs terminate their sub-range early.  Returns false as
 * soon as any page-table entry is missing.  See the note on
 * alirt_page_mapped() for why this is a loop and not a recursion.
 */
static inline bool alirt_addr_valid(unsigned long addr, size_t size)
{
	unsigned long end = addr + size;

	while (addr < end) {
		unsigned long next;

		if (unlikely(!alirt_page_mapped(addr, &next)))
			return false;
		addr = next;
	}
	return true;
}

/*
 * riscv module mapping space; the exact range is version-dependent and
 * resolved at alirt_mm_init() time (see the file header).  Before
 * init both bounds are 0, i.e. an empty, scan-nothing range.
 */
static inline unsigned long alirt_modules_start(void)
{
	return alirt_mod_start;
}

static inline unsigned long alirt_modules_end(void)
{
	return alirt_mod_end;
}

static inline bool alirt_is_module_space(const void *p)
{
	return (unsigned long)p >= alirt_mod_start &&
	       (unsigned long)p < alirt_mod_end;
}

#endif /* ALIRT_ARCH_RISCV_MM_H */
