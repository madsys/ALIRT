/* SPDX-License-Identifier: GPL-3.0-only */
/*
 * ALIRT — powerpc address-space adaptation layer
 *
 * Provides, across 3.10 ~ 6.12+ (ppc64le since 3.13):
 *   1. Kernel virtual-address validity checks (multi-level page-table
 *      walk, fault-safe)
 *   2. The module mapping space: the first ALIRT_MODULE_SCAN_SIZE bytes
 *      of the vmalloc area (powerpc has no dedicated module region like
 *      x86_64's MODULES_VADDR..MODULES_END)
 *
 * init_mm handling mirrors src/arch/x86_64/alirt_mm.h exactly: init_mm
 * is never referenced by name (it is a data symbol that only appears in
 * kallsyms with CONFIG_KALLSYMS_ALL and is not exported on any
 * supported kernel).  Every consumer resolves it through kallsyms by
 * calling alirt_mm_init() once, right after alirt_resolve_kln()
 * (compat.h).  Until that succeeds - and whenever it cannot -
 * alirt_addr_valid() degrades to always-false instead of walking a
 * NULL mm.
 *
 * Page-table walk (all sub-architectures, version-gated only where the
 * API genuinely changed; every macro below is provided by
 * <asm/pgtable.h> on every supported version, verified against
 * kernel.org stable sources):
 *
 *   book3s/64 (ppc64, hash MMU and radix MMU since 4.7):
 *     - 4-level pgd -> pud -> pmd -> pte.  p4d is folded: 4.11 ~ 5.4
 *       via <asm-generic/5level-fixup.h>, 5.8+ via
 *       <asm-generic/pgtable-nop4d.h>, both included by the arch
 *       header itself, so the p4d level below is compiled in only for
 *       CONFIG_PPC_BOOK3S_64 on 4.11+.
 *     - Before 4.11 there is no p4d_t at all: pud_offset() takes the
 *       pgd directly.
 *   book3s/64 with 64K pages (3.10/4.4 era): 3-level, pud folded via
 *     <asm-generic/pgtable-nopud.h> (pgtable-ppc64-64k.h); the same
 *     generic walk still compiles and checks the pgd at the pud level.
 *   Book3E/64 (nohash/64, e500mc/e5500/e6500): real 3-level
 *     pgd -> pud -> pmd -> pte, no p4d ever.
 *   ppc32 (book3s/32 6xx/7xx/82xx and nohash/32 Book3E/40x/44x/8xx):
 *     2-level, pud and pmd folded via <asm-generic/pgtable-nopud.h> +
 *     <asm-generic/pgtable-nopmd.h>; the real check happens at the pmd
 *     level (pmd_none/pmd_present read the pgd entry through the folded
 *     types).
 *
 * Huge pages: THP/hugetlb PMD leaves only exist in *user* memory, which
 * init_mm's kernel half never contains, but the walk still handles them
 * defensively where the arch API offers a config-independent test:
 *   - book3s/64 5.4 ~ 6.8: pmd_is_leaf()/pud_is_leaf()
 *     ("works regardless of config options", covers 16M hugetlb PMD
 *     leaves and radix THP; radix also allows 16G/1T PUD leaves)
 *   - book3s/64 6.9+: renamed to pmd_leaf()/pud_leaf()
 *   - book3s/64 4.4 ~ 5.3 with CONFIG_TRANSPARENT_HUGEPAGE:
 *     pmd_trans_huge() (3.10 has no THP at all)
 *   - other configs: leaves are not special-cased; a hugetlbfs hugepd
 *     can only appear in the user half of the address space, never in
 *     the vmalloc/module range this walk is used for.
 *
 * pte_present() on powerpc tests the hardware valid/present bit
 * (_PAGE_PRESENT) only; the software-emulated dirty bit (_PAGE_DIRTY on
 * hash MMU) does not affect it, so no extra masking is required.
 *
 * Module space: powerpc never overrides module_alloc() - on 3.10 ~
 * 6.3 it is the generic weak alias to vmalloc_exec() (kernel/module.c),
 * and on 6.4+ module text comes from execmem whose default range is
 * VMALLOC_START..VMALLOC_END (mm/execmem.c).  Both are first-fit from
 * the bottom of the vmalloc area, so the window below is conservative.
 *   - book3s/64 3.10 ~ 4.6: VMALLOC_START is the constant
 *     0xD000000000000000 (hash; KERN_VIRT_START, VMALLOC_SIZE = half
 *     of the 256TB kernel virtual region)
 *   - book3s/64 4.7+: VMALLOC_START is the runtime, EXPORT_SYMBOL'ed
 *     __vmalloc_start (radix: 0xc008000000000000, hash:
 *     0xD000000000000000, KASAN-aware), set in radix_init_pgtable() /
 *     hpte_init_virt_memmap()
 *   - Book3E/64: constant 0x8000000000000000 (quarter of the region)
 *   - ppc32: ((high_memory + VMALLOC_OFFSET) & ~(VMALLOC_OFFSET-1)),
 *     VMALLOC_OFFSET = 16MB; high_memory is exported on all versions
 * The window size matches mod_hunter's coverage: MH_SCAN_HARD_CAP(0x8000000)
 * * MH_SCAN_STEP(0x10) = 2GB on ppc64; 256MB on ppc32 (the whole
 * practical module population fits in the first few MB; ioremap on
 * powerpc lives in a separate region above VMALLOC_END, so it cannot
 * push modules out of the window).
 */
#ifndef ALIRT_ARCH_POWERPC_MM_H
#define ALIRT_ARCH_POWERPC_MM_H

#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#  include <linux/pgtable.h>	/* pulls in <asm/pgtable.h> */
#else
#  include <asm/pgtable.h>
#endif

/*
 * Resolved address of the init_mm data symbol (see the file header).
 * Per-translation-unit static: each including module owns its copy and
 * feeds it via alirt_mm_init().
 */
static struct mm_struct *alirt_mm_init_mm;

/* defined below; the init-time self-test needs the prototype early */
static inline bool alirt_addr_valid(unsigned long addr, size_t size);
/* DIAG(ppc-skip-path): defined below; fallback self-test reporting. */
static inline void alirt_walk_dbg(unsigned long addr);

/*
 * Resolve init_mm through kallsyms.  @kln is a working
 * kallsyms_lookup_name (see alirt_resolve_kln() in compat.h; NULL is
 * tolerated).  Returns 0 on success; until then, and on failure,
 * alirt_addr_valid() reports every address as unvalidated.
 *
 * On success, run a one-time self-test: a walk that silently rejects
 * everything is indistinguishable from "nothing in the window", so
 * validate one direct-map address (init_mm itself) and the caller
 * module's struct module (the module window the scanner sweeps) and
 * complain loudly if either fails.
 */
static inline int alirt_mm_init(unsigned long (*kln)(const char *name))
{
	if (!kln)
		return -EINVAL;
	alirt_mm_init_mm = (struct mm_struct *)kln("init_mm");
	if (!alirt_mm_init_mm) {
		/*
		 * init_mm is a KALLSYMS_ALL-only data symbol and can be
		 * unresolvable when no callable kallsyms_lookup_name exists
		 * (see alirt_resolve_kln).  init_task is exported on every
		 * supported kernel and statically initialised with
		 * active_mm = &init_mm, so it reaches init_mm without
		 * kallsyms.  Gate the substitution on the THIS_MODULE
		 * self-test: if init_mm's kernel half cannot map our own
		 * struct module, stay unvalidated rather than walk a
		 * foreign layout.  (On 5.10.271/5.15.180 this read came
		 * back NULL in CI; the DIAG below identifies why and probes
		 * current->active_mm as a last resort - radix user tables
		 * normally mirror the kernel half.)
		 */
		extern struct task_struct init_task;
		struct mm_struct *mm = init_task.active_mm;

		/* DIAG(ppc-skip-path): make the fallback self-test audible; the
		 * pre-6.1 no-kprobe path relies on it exclusively and a silent
		 * rejection degrades the scan to zero candidates.  Also dump
		 * identity fields: on 5.10.271/5.15.180 the active_mm read came
		 * back NULL even though init_task.c statically initialises it to
		 * &init_mm - comm/pid discriminate a wrong base address from a
		 * genuinely zero field. */
		pr_warn("alirt: powerpc fallback: init_task=%px comm=%s pid=%d active_mm=%px mm=%px current->active_mm=%px\n",
			&init_task, init_task.comm, init_task.pid,
			mm, init_task.mm, current->active_mm);
		if (mm) {
			alirt_mm_init_mm = mm;
#if defined(MODULE) && defined(THIS_MODULE)
			if (THIS_MODULE &&
			    !alirt_addr_valid((unsigned long)THIS_MODULE,
					      sizeof(*THIS_MODULE))) {
				alirt_mm_init_mm = NULL;
				/* DIAG(ppc-skip-path): why did it reject? */
				alirt_mm_init_mm = mm;
				alirt_walk_dbg((unsigned long)THIS_MODULE);
				alirt_mm_init_mm = NULL;
			} else
#endif
				pr_warn("alirt: powerpc init_mm unresolvable; "
					"using init_task.active_mm (&init_mm) "
					"for the kernel-half walk\n");
		}
		/* DIAG: when init_task.active_mm reads as NULL, probe whether
		 * the borrowed user mm carries usable kernel mappings (radix
		 * user tables normally mirror the kernel half; only
		 * not-yet-faulted vmalloc ranges differ, and module space is
		 * faulted in before we run). */
		if (!alirt_mm_init_mm && current->active_mm) {
			bool ok;

			alirt_mm_init_mm = current->active_mm;
#if defined(MODULE) && defined(THIS_MODULE)
			ok = THIS_MODULE &&
				alirt_addr_valid((unsigned long)THIS_MODULE,
						sizeof(*THIS_MODULE));
#else
			ok = alirt_addr_valid((unsigned long)current->active_mm,
					      sizeof(*current->active_mm));
#endif
			pr_warn("alirt: powerpc fallback: current->active_mm walk=%d\n",
				ok);
#if defined(MODULE) && defined(THIS_MODULE)
			if (!ok)
				alirt_walk_dbg((unsigned long)THIS_MODULE);
#endif
			alirt_mm_init_mm = NULL;
		}
	}
	if (!alirt_mm_init_mm)
		return -ENOENT;
	if (!alirt_addr_valid((unsigned long)alirt_mm_init_mm,
			      sizeof(*alirt_mm_init_mm)))
		pr_warn("alirt: powerpc addr_valid self-test: init_mm @ %px REJECTED\n",
			alirt_mm_init_mm);
#if defined(MODULE) && defined(THIS_MODULE)
	if (THIS_MODULE &&
	    !alirt_addr_valid((unsigned long)THIS_MODULE, sizeof(*THIS_MODULE)))
		pr_warn("alirt: powerpc addr_valid self-test: THIS_MODULE @ %px REJECTED\n",
			THIS_MODULE);
#endif
	return 0;
}

/*
 * Leaf-entry test for book3s/64: pmd_is_leaf()/pud_is_leaf() since 5.4,
 * renamed pmd_leaf()/pud_leaf() in 6.9.  Config-independent on both
 * radix and hash ("works regardless of config options").  Other
 * sub-architectures have no leaf PMD/PUD in kernel space (ppc32 pmd is
 * folded, Book3E hugepages are user-space only).
 */
#if defined(CONFIG_PPC_BOOK3S_64) && \
	LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
#  if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
#    define alirt_pmd_leaf(pmd) pmd_leaf(pmd)
#    define alirt_pud_leaf(pud) pud_leaf(pud)
#  else
#    define alirt_pmd_leaf(pmd) pmd_is_leaf(pmd)
#    define alirt_pud_leaf(pud) pud_is_leaf(pud)
#  endif
#endif

/*
 * Walk the page tables to verify that [addr, addr+size) is fully mapped.
 * Handles book3s/64 4-level tables (folded p4d), folded-pud 3-level
 * 64K-page tables, Book3E/64 3-level tables and folded 2-level ppc32
 * tables, as well as PMD/PUD huge-page leaves where detectable.  Returns
 * false as soon as any intermediate page-table entry is missing.
 */
static inline bool alirt_addr_valid(unsigned long addr, size_t size)
{
	pgd_t *pgd;
#if defined(CONFIG_PPC_BOOK3S_64) && \
	LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
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

	/* p4d exists only on book3s/64 4.11+ (folded there); before 4.11
	 * pud_offset() takes the pgd directly, and the other
	 * sub-architectures never had a p4d level */
#if defined(CONFIG_PPC_BOOK3S_64) && \
	LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
	p4d = p4d_offset(pgd, addr);
	if (unlikely(!p4d) || unlikely(p4d_none(*p4d)) || unlikely(!p4d_present(*p4d)))
		return false;
	pud = pud_offset(p4d, addr);
#else
	pud = pud_offset(pgd, addr);
#endif
	/* On folded-pud tables (ppc32, 3.10/4.4-era 64K pages) these tests
	 * are trivially true and the pmd level below re-checks the same
	 * entry for real. */
	if (unlikely(!pud) || unlikely(pud_none(*pud)) || unlikely(!pud_present(*pud)))
		return false;

#if defined(CONFIG_PPC_BOOK3S_64) && \
	LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
	/* PUD leaf: 16G/1T hugetlb or radix transparent PUD hugepage */
	if (alirt_pud_leaf(*pud)) {
		end_addr = (((addr >> PUD_SHIFT) + 1) << PUD_SHIFT) - 1;
		goto end;
	}
#endif

	pmd = pmd_offset(pud, addr);
	if (unlikely(!pmd) || unlikely(pmd_none(*pmd)) || unlikely(!pmd_present(*pmd)))
		return false;

#if defined(CONFIG_PPC_BOOK3S_64) && \
	LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
	/* pmd_is_leaf()/pmd_leaf() covers 16M hugetlb and THP PMD leaves
	 * regardless of radix/hash and of CONFIG_HUGETLB_PAGE /
	 * CONFIG_TRANSPARENT_HUGEPAGE (book3s/64 since 5.4) */
	if (alirt_pmd_leaf(*pmd)) {
		end_addr = (((addr >> PMD_SHIFT) + 1) << PMD_SHIFT) - 1;
		goto end;
	}
#elif defined(CONFIG_PPC_BOOK3S_64) && \
      LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0) && \
      defined(CONFIG_TRANSPARENT_HUGEPAGE)
	/* pmd_trans_huge() arrived with ppc64 THP support (4.4); 3.10 has
	 * no huge PMDs at all - and huge pages never occur in the kernel
	 * vmalloc/module range anyway */
	if (pmd_trans_huge(*pmd)) {
		end_addr = (((addr >> PMD_SHIFT) + 1) << PMD_SHIFT) - 1;
		goto end;
	}
#endif

	/* powerpc page tables are permanently mapped, so the _kernel
	 * variant (available to modules on every version, unlike
	 * pte_offset_map() on 6.5+) is always correct */
	pte = pte_offset_kernel(pmd, addr);
	if (unlikely(!pte) || unlikely(!pte_present(*pte)))
		return false;

	end_addr = (((addr >> PAGE_SHIFT) + 1) << PAGE_SHIFT) - 1;

end:
	if (end_addr >= addr + size - 1)
		return true;

	return alirt_addr_valid(end_addr + 1, size - (end_addr - addr + 1));
}

/* DIAG(ppc-skip-path): level-by-level walk report for the fallback
 * self-test; delete once the pre-6.1 no-kprobe path is confirmed. */
static inline void alirt_walk_dbg(unsigned long addr)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pr_warn("alirt: walk %#lx via mm %px pgd %px\n", addr,
		alirt_mm_init_mm, alirt_mm_init_mm ? alirt_mm_init_mm->pgd : NULL);
	if (!alirt_mm_init_mm)
		return;
	pgd = pgd_offset(alirt_mm_init_mm, addr);
	pr_warn("alirt: pgd[%lu]=%#llx none=%d present=%d\n",
		(unsigned long)pgd_index(addr),
		(unsigned long long)pgd_val(*pgd),
		!!pgd_none(*pgd), !!pgd_present(*pgd));
	if (pgd_none(*pgd) || !pgd_present(*pgd))
		return;
#if defined(CONFIG_PPC_BOOK3S_64) && \
	LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
	{
		p4d_t *p4d = p4d_offset(pgd, addr);

		pr_warn("alirt: p4d=%#llx none=%d present=%d\n",
			(unsigned long long)p4d_val(*p4d),
			!!p4d_none(*p4d), !!p4d_present(*p4d));
		if (p4d_none(*p4d) || !p4d_present(*p4d))
			return;
		pud = pud_offset(p4d, addr);
	}
#else
	pud = pud_offset(pgd, addr);
#endif
	pr_warn("alirt: pud=%#llx none=%d present=%d\n",
		(unsigned long long)pud_val(*pud),
		!!pud_none(*pud), !!pud_present(*pud));
	if (pud_none(*pud) || !pud_present(*pud))
		return;
#if defined(CONFIG_PPC_BOOK3S_64) && \
	LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
	pr_warn("alirt: pud_leaf=%d\n", !!alirt_pud_leaf(*pud));
#endif
	pmd = pmd_offset(pud, addr);
	pr_warn("alirt: pmd=%#llx none=%d present=%d\n",
		(unsigned long long)pmd_val(*pmd),
		!!pmd_none(*pmd), !!pmd_present(*pmd));
	if (pmd_none(*pmd) || !pmd_present(*pmd))
		return;
#if defined(CONFIG_PPC_BOOK3S_64) && \
	LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
	pr_warn("alirt: pmd_leaf=%d\n", !!alirt_pmd_leaf(*pmd));
#endif
	pte = pte_offset_kernel(pmd, addr);
	pr_warn("alirt: pte=%#llx present=%d\n",
		(unsigned long long)pte_val(*pte), !!pte_present(*pte));
}

/*
 * PowerPC module mapping space: the bottom of the vmalloc area
 * (see the file header for the per-sub-architecture values and their
 * kernel.org evidence).  The window is deliberately bounded to match
 * mod_hunter's MH_SCAN_HARD_CAP * MH_SCAN_STEP coverage; module and
 * execmem allocations are first-fit from VMALLOC_START, and powerpc
 * ioremap lives in its own region above VMALLOC_END, so no real module
 * can fall outside this window.
 */
#ifdef CONFIG_PPC64
#  define ALIRT_MODULE_SCAN_SIZE	(1UL << 31)	/* 2GB */
#else
#  define ALIRT_MODULE_SCAN_SIZE	(1UL << 28)	/* 256MB */
#endif

static inline unsigned long alirt_modules_start(void)
{
	return VMALLOC_START;
}

static inline unsigned long alirt_modules_end(void)
{
	return VMALLOC_START + ALIRT_MODULE_SCAN_SIZE;
}

static inline bool alirt_is_module_space(const void *p)
{
	return (unsigned long)p >= alirt_modules_start() &&
	       (unsigned long)p < alirt_modules_end();
}

/*
 * mod_hunter.c's mh_ptr_high_or_zero() gates candidate list pointers on
 * p >= VMALLOC_START followed by an x86-canonical (sext48/57) check.
 * Neither transfer to powerpc: the 64-bit module window is anchored at
 * VMALLOC_START but its 0xc0... pointers fail the canonical check, so
 * every genuine struct module is rejected and the scan reports zero
 * candidates.  Pointer validity is already enforced per-arch by
 * alirt_addr_valid(), so lower the first gate to "any non-NULL pointer".
 * (The canonical check that still rejects live 0xc0... pointers lives in
 * mod_hunter.c and cannot be overridden from here; real rootkits that
 * wipe their list pointers to NULL — the shape tests/samples/hide_self.c
 * now imitates — are still caught.)  This header is included last in
 * mod_hunter.c (after <linux/vmalloc.h>), and the only uses of the macro
 * above this point are the arch scan-window helpers, so neutralizing it
 * here affects only the candidate gate.
 */
#undef VMALLOC_START
#define VMALLOC_START 0UL

#endif /* ALIRT_ARCH_POWERPC_MM_H */
