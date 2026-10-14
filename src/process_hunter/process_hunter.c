// SPDX-License-Identifier: GPL-3.0-only
/*
 * process_hunter.c - ALIRT hidden process hunter (v0.5.1)
 *
 * SLUB-era re-implementation of the original process_hunter idea: walk
 * every object slot in the kernel's "task_struct" kmem cache and
 * cross-compare the live-looking ones against the global task list built
 * by for_each_process().  A task_struct that sits in a slab but whose pid
 * is not on the task list is reported with "Warning<--" (hidden process).
 *
 * Lineage:
 *   - madsys, process_hunter.c (ALIRT 0.4.2, 2.6.5-2.6.12 era).  The
 *     original walked the SLAB allocator's kmem_list3/slab internals,
 *     which no longer exist: every supported kernel today uses SLUB.
 *     This file keeps the original detection semantics (slab objects vs.
 *     task list cross-check, three-column /proc/showprocess report,
 *     "Warning<--" hidden marker) but speaks to three generations of
 *     SLUB internals:
 *
 *       era 1 (2.6.32 - 5.16): a slab is a struct page hung on
 *               kmem_cache_node->{partial,full}; metadata lives in
 *               page->{lru|slab_list,freelist,inuse,objects}.  All of
 *               these are public header fields on every version.
 *       era 2 (5.17 - 6.1):   struct slab reuses the struct page bits:
 *               list node first, then slab_cache, freelist, counters
 *               (verified against mm/slab.h v5.17 and v6.0).
 *       era 3 (6.2+):         struct slab reordered: slab_cache first,
 *               then the slab_list/freelist union (verified against
 *               mm/slab.h v6.3 and v6.6).  The freelist/counters offsets
 *               are identical in both generations, and the
 *               slab_cache == owner invariant lets us pick the right
 *               layout at runtime instead of trusting version numbers.
 *
 * Output follows the original /proc/showprocess contract: three columns
 * (name/pid/state), hidden processes flagged with "Warning<--" at end of
 * line, mirrored to both the seq_file (trusted, copy_to_user based) and
 * the kernel log - the same dual-channel policy as mod_hunter.
 *
 * Known limitations (also reported in the scan header):
 *   - Without CONFIG_SLUB_DEBUG the full-slab list does not exist in
 *     kmem_cache_node at all; with it, node->full is populated only for
 *     caches carrying SLAB_STORE_USER (i.e. slub_debug enabled).  Full
 *     and per-cpu slabs are then invisible to this scan; detection still
 *     works for task_structs sitting on partial slabs.
 *   - With CONFIG_SLAB_FREELIST_HARDENED the per-slab freelist pointers
 *     are obfuscated, so free-slot filtering is disabled and the report
 *     says "free-filter unavailable, expect noise".  Comm/pid/state
 *     heuristics act as the second-stage filter instead.
 *   - Per-memcg kmem caches (3.10 - 5.8) are covered by scanning every
 *     cache named "task_struct" / "task_struct(<id>)" found in the
 *     slab_caches list, which avoids depending on the several different
 *     memcg_cache_params layouts.  From 5.9 on per-memcg caches were
 *     removed upstream, so only the root cache exists anyway.
 *
 * Supported: x86_64, Linux 2.6.32 - 6.12+, CONFIG_SLUB.  Any other
 * combination fails module load with -ENODEV (or does not compile),
 * never panics.
 *
 * Copyright (C) 2005 madsys, 2025 ALIRT
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/stat.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/bitops.h>
#include <linux/kallsyms.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
/* linux/sched/signal.h (for_each_process) was split out of
 * linux/sched.h in 4.11; older kernels provide both from sched.h. */
#include <linux/sched/signal.h>
#endif

#include "compat.h"

#if defined(CONFIG_X86_64)
/*
 * init_mm is resolved through kallsyms by alirt_mm_init() at module
 * init (it is not exported on any supported kernel; see alirt_mm.h).
 * Until then alirt_addr_valid() degrades to always-false, so nothing
 * here may run before ph_init() has resolved the symbol.
 */
#include "alirt_mm.h"
#define PH_HAVE_MM 1
#endif

/*
 * This is a SLUB-era implementation.  Refuse to build against the old
 * SLAB/SLOB layouts (CONFIG_SLAB disappeared upstream in 6.5, leaving
 * SLUB as the only allocator, so the guard only bites on old trees).
 */
#if !defined(CONFIG_SLUB)
#error "process_hunter requires CONFIG_SLUB (SLAB/SLOB layouts unsupported)"
#endif

/*
 * Header visibility of the SLUB core structures, verified file by file
 * against kernel.org sources:
 *   - struct kmem_cache / struct kmem_cache_cpu: public in
 *     <linux/slub_def.h> on every version from 2.6.32 through 6.11
 *     (verified v2.6.32/v3.10/v4.4/v4.19/v5.4/v5.15/v6.1).
 *     <linux/slab.h> includes slub_def.h only through v3.17 (under
 *     CONFIG_SLUB); from v3.18 on it must be included explicitly.
 *     6.12 removed the SLAB allocator and with it <linux/slub_def.h>;
 *     kmem_cache lives in the private mm/slab.h, kmem_cache_node in
 *     mm/slub.c, and no public header defines them any more.
 *   - struct kmem_cache_node: public in <linux/slub_def.h> from 2.6.32
 *     through 3.9 (verified v2.6.32/v2.6.35/v2.6.37/v3.0/v3.5/v3.9;
 *     layout identical to the copy below), moved into the private
 *     mm/slab.h in v3.10, whose SLUB branch is verbatim identical
 *     across v3.10 .. v6.1 (list_lock, nr_partial, partial, then the
 *     CONFIG_SLUB_DEBUG nr_slabs/total_objects/full tail).  6.12 moved
 *     it into mm/slub.c.
 * So: up to 6.11 we pair the real kmem_cache from <linux/slub_def.h>
 * with the private node copy below (which is layout-identical to the
 * real node on every version, public era or private era); on 6.12+ the
 * layout-verified private copies below stand in for both.  Field order
 * was verified verbatim against v6.12 mm/slab.h (struct kmem_cache) and
 * v6.12 mm/slub.c (struct kmem_cache_node), including the order of
 * every conditional field, so the offsets of the fields we consume
 * (size/offset/name/node[]; list_lock/partial/full) match the real
 * objects for any combination of the config switches that shift them
 * (SLUB_TINY, SLUB_CPU_PARTIAL, SLUB_DEBUG, SYSFS,
 * FREELIST_HARDENED/RANDOM, NUMA, KASAN_GENERIC, HARDENED_USERCOPY).
 * The CONFIG_SLAB branch that shares kmem_cache_node on 3.x-6.1 SLAB
 * configs is irrelevant here - this file refuses to build without
 * CONFIG_SLUB.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include <linux/reciprocal_div.h>
#include <linux/kasan.h>

struct ph_kmem_cache_node {
	/* v6.12 mm/slub.c: list_lock, nr_partial, partial; the SLUB_DEBUG
	 * extras sit between partial and the trailing fields, and their
	 * presence shifts nothing we consume beyond this struct — but the
	 * SLUB_DEBUG members DO shift nothing here either; what matters is
	 * that they are part of the real layout, so keep them conditional
	 * exactly as the original. */
	spinlock_t list_lock;
	unsigned long nr_partial;
	struct list_head partial;
#ifdef CONFIG_SLUB_DEBUG
	atomic_long_t nr_slabs;
	atomic_long_t total_objects;
	struct list_head full;
#endif
};

struct ph_kmem_cache {
#ifndef CONFIG_SLUB_TINY
	struct kmem_cache_cpu __percpu *cpu_slab;
#endif
	slab_flags_t flags;
	unsigned long min_partial;
	unsigned int size;		/* Object size including meta data */
	unsigned int object_size;	/* Object size without meta data */
	struct reciprocal_value reciprocal_size;
	unsigned int offset;		/* Free pointer offset */
#ifdef CONFIG_SLUB_CPU_PARTIAL
	unsigned int cpu_partial;
	unsigned int cpu_partial_slabs;
#endif
	/* struct kmem_cache_order_objects is a single unsigned int x */
	unsigned int oo;
	unsigned int min;
	gfp_t allocflags;
	int refcount;
	void (*ctor)(void *);
	unsigned int inuse;
	unsigned int align;
	unsigned int red_left_pad;
	const char *name;
	struct list_head list;
#ifdef CONFIG_SYSFS
	struct kobject kobj;
#endif
#ifdef CONFIG_SLAB_FREELIST_HARDENED
	unsigned long random;
#endif
#ifdef CONFIG_NUMA
	unsigned int remote_node_defrag_ratio;
#endif
#ifdef CONFIG_SLAB_FREELIST_RANDOM
	unsigned int *random_seq;
#endif
#ifdef CONFIG_KASAN_GENERIC
	struct kasan_cache kasan_info;
#endif
#ifdef CONFIG_HARDENED_USERCOPY
	unsigned int useroffset;
	unsigned int usersize;
#endif
	struct ph_kmem_cache_node *node[MAX_NUMNODES];
};

typedef struct ph_kmem_cache ph_kcache;
typedef struct ph_kmem_cache_node ph_knode;
#else
#include <linux/slub_def.h>	/* real struct kmem_cache, kmem_cache_cpu */

struct ph_kmem_cache_node {
	/* Below 6.12 the real node is layout-identical to this copy on
	 * every version: public in <linux/slub_def.h> 2.6.32-3.9, private
	 * in mm/slab.h 3.10-6.1 (SLUB branch verbatim identical across
	 * v2.6.32/v2.6.35/v2.6.37/v3.0/v3.5/v3.9/v3.10/v4.4/v4.19/v5.4/
	 * v5.15/v6.1).  Only the fields through "partial" are consumed;
	 * the SLUB_DEBUG tail is kept conditional so "full" stays at the
	 * right offset when CONFIG_SLUB_DEBUG=y. */
	spinlock_t list_lock;
	unsigned long nr_partial;
	struct list_head partial;
#ifdef CONFIG_SLUB_DEBUG
	atomic_long_t nr_slabs;
	atomic_long_t total_objects;
	struct list_head full;
#endif
};

typedef struct kmem_cache ph_kcache;
typedef struct ph_kmem_cache_node ph_knode;
#endif /* >= 6.12 */

#define PH_VERSION		"0.5.1"

#define PH_PROC_NAME		"showprocess"	/* keep the original name */
#define PH_PROC_MODE		S_IRUSR

#define PH_PID_MAX		(4 * 1024 * 1024)	/* pid_max_limit (64-bit) */
#define PH_PIDMAP_BYTES		(PH_PID_MAX / 8)	/* 512 KiB bitmap */
#define PH_MAX_FINDINGS		4096
#define PH_MAX_CACHES		16	/* root + memcg-era children */
#define PH_MAX_SLABS_PER_LIST	4096	/* hard cap, anti-corruption */
#define PH_MAX_OBJS_PER_SLAB	4096	/* hard cap, anti-corruption */
#define PH_STATE_MASK		0x3fffUL	/* generous task state mask */

/*
 * A located "task_struct" cache.  More than one exists on 3.10 - 5.8
 * kernels with memcg kmem accounting (per-memcg children named
 * "task_struct(<css_id>)"); they are found via the slab_caches walk.
 */
static ph_kcache *ph_caches[PH_MAX_CACHES];
static unsigned int ph_nr_caches;

/*
 * tasklist_lock is deliberately NOT used: it stopped being exported
 * long ago (verified: no EXPORT_SYMBOL(tasklist_lock) in kernel/fork.c
 * on 2.6.32, 3.0, 4.4 or 6.1), so an extern reference would fail to
 * link on every supported kernel.  RCU is sufficient: the tasks list
 * is unlinked with list_del_rcu() and struct task_struct is freed only
 * after an RCU grace period on every kernel in range (verified in
 * kernel/exit.c v2.6.32 and v6.1).  ph_collect() documents the exact
 * lock pairing.
 */

/* ------------------------------------------------------------------ */
/* kernel version compatibility shims (local to this module, same      */
/* policy as mod_hunter: compat.h first, local fallback second)        */
/* ------------------------------------------------------------------ */

/* 5.14 renamed task_struct.state to __state */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
#define ph_task_state(t)	((t)->__state)
#else
#define ph_task_state(t)	((t)->state)
#endif

/*
 * kmem_cache node access.
 *  - 2.6.32 .. 2.6.36: node[] exists only under CONFIG_NUMA, otherwise
 *    the node is embedded as s->local_node (verified against slub_def.h
 *    v2.6.32/v2.6.35/v2.6.36; 2.6.37 switched to an unconditional
 *    node[] array, which every later version keeps).
 *  - 2.6.37 and later:  s->node[n], NULL for nodes without a
 *    kmem_cache_node (offline nodes, bootstrapping).
 */
static ph_knode *ph_cache_node(ph_kcache *s, int n)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 36)
#ifdef CONFIG_NUMA
	return (ph_knode *)s->node[n];
#else
	return n == 0 ? (ph_knode *)&s->local_node : NULL;
#endif
#else
	return (ph_knode *)s->node[n];
#endif
}

#ifdef PH_HAVE_MM

/* ------------------------------------------------------------------ */
/* symbol resolution (kallsyms_lookup_name is not exported on 5.7+)    */
/* ------------------------------------------------------------------ */

static unsigned long (*ph_kln)(const char *name);

/* ------------------------------------------------------------------ */
/* pointer sanity helpers                                              */
/* ------------------------------------------------------------------ */

static __always_inline u64 ph_sext(u64 addr, u8 bits)
{
	return ((s64)addr << (64 - bits)) >> (64 - bits);
}

/*
 * A pointer is accepted when NULL, LIST_POISON, or a canonical kernel
 * high-half address (direct map or vmalloc area, 4- or 5-level paging).
 */
static bool ph_kptr_ok(const void *p)
{
	unsigned long a = (unsigned long)p;

	if (!p)
		return true;
	if (p == LIST_POISON1 || p == LIST_POISON2)
		return true;
	if (a < PAGE_OFFSET)
		return false;
	return ph_sext(a, 48) == a || ph_sext(a, 57) == a;
}

/* comm heuristic: printable, non-empty, NUL terminated within limit */
static bool ph_comm_valid(const char *comm)
{
	size_t i;

	if (!comm)
		return false;
	for (i = 0; i < TASK_COMM_LEN; i++) {
		if (comm[i] == '\0')
			return i != 0;
		if (comm[i] < 0x20 || comm[i] > 0x7e)
			return false;
	}
	/* full-length name without NUL: accept, bounded copy */
	return true;
}

/*
 * Heuristic struct task_struct recognition (modernised port of the
 * original 0.4.2 pid/state sanity checks, plus list-pointer checks):
 *   - comm printable
 *   - pid within [1, 4M]
 *   - state within a generous mask
 *   - tasks.next/prev canonical kernel pointers or LIST_POISON
 */
static bool ph_looks_like_task(const struct task_struct *t)
{
	if (!ph_comm_valid(t->comm))
		return false;
	if (t->pid < 1 || t->pid > PH_PID_MAX)
		return false;
	if (ph_task_state(t) & ~PH_STATE_MASK)
		return false;
	if (!ph_kptr_ok(t->tasks.next) || !ph_kptr_ok(t->tasks.prev))
		return false;
	return true;
}

/* ------------------------------------------------------------------ */
/* task state names (ported from the original parse_state)             */
/* ------------------------------------------------------------------ */

static const char *ph_parse_state(unsigned long state)
{
	switch (state) {
	case TASK_RUNNING:
		return "TASK_RUNNING";
	case TASK_INTERRUPTIBLE:
		return "TASK_INTERRUPTIBLE";
	case TASK_UNINTERRUPTIBLE:
		return "TASK_UNINTERRUPTIBLE";
#ifdef TASK_IDLE
	case TASK_IDLE:
		return "TASK_IDLE";
#endif
	case TASK_STOPPED:
		return "TASK_STOPPED";
#ifdef TASK_TRACED
	case TASK_TRACED:
		return "TASK_TRACED";
#endif
#if defined(TASK_ZOMBIE)
	case TASK_ZOMBIE:
		return "TASK_ZOMBIE";
#elif defined(EXIT_ZOMBIE)
	case EXIT_ZOMBIE:
		return "EXIT_ZOMBIE";
#endif
#if defined(EXIT_DEAD)
	case EXIT_DEAD:
		return "EXIT_DEAD";
#elif defined(TASK_DEAD)
	case TASK_DEAD:
		return "TASK_DEAD";
#endif
	default:
		return "strange state!";
	}
}

/* ------------------------------------------------------------------ */
/* slab descriptor access, three SLUB generations                      */
/* ------------------------------------------------------------------ */

/*
 * Unified view of a slab descriptor for the walker below.  Only the list
 * node and back-pointer offsets differ between the struct slab
 * generations; the freelist/counters words sit at the same offsets in
 * both (verified), as does the "first object at page address" rule that
 * SLUB has kept since 2.6.22.
 */
struct ph_slab_ops {
	unsigned int list_off;	/* offset of the list_head in the slab */
	unsigned int cache_off;	/* struct slab era: offset of slab_cache */
	bool layout_known;	/* era 2/3 only: offsets validated */
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0)

#define PH_ERA_PAGE 1

/* era 1: the slab list node offset inside struct page */
static unsigned int ph_page_list_off(void)
{
	/* "slub: use slab_list instead of lru" (Tobin Harding) merged in
	 * 5.2; before that slab pages hang on page->lru. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
	return offsetof(struct page, slab_list);
#else
	return offsetof(struct page, lru);
#endif
}

/*
 * Probe the layout on the first reachable node.  Era 1 needs no probe:
 * all fields come from public headers.  Returns 1 when the ops are
 * usable, 0 when there was nothing to probe against (all lists empty -
 * the caller moves on to the next node), and a negative value when the
 * layout was probed but did not match any known generation.
 */
static int ph_slab_ops_init(struct ph_slab_ops *ops, ph_kcache *s,
			    ph_knode *node)
{
	ops->list_off = ph_page_list_off();
	ops->cache_off = 0;
	ops->layout_known = true;
	return 1;
}

static bool ph_slab_belongs(void *slab, ph_kcache *s,
			    const struct ph_slab_ops *ops)
{
	return PageSlab((struct page *)slab);
}

static unsigned int ph_slab_objects(const void *slab)
{
	return ((const struct page *)slab)->objects;
}

static unsigned int ph_slab_inuse(const void *slab)
{
	return ((const struct page *)slab)->inuse;
}

static void *ph_slab_freelist(const void *slab)
{
	return ((const struct page *)slab)->freelist;
}

#else /* >= 5.17: struct slab.  mm/slab.h is not an exported header, so
       * the module carries its own prefix copies of both generations;
       * the right one is picked at runtime against the slab_cache ==
       * owner invariant before any list is walked. */

/*
 * 5.17 .. 6.1 generation: list node first, then slab_cache.
 * (verified against mm/slab.h v5.17 and v6.0)
 */
struct ph_slab_gen1 {
	unsigned long __page_flags;
	struct list_head slab_list;
	struct kmem_cache *slab_cache;
	void *freelist;		/* offset 32 on x86_64 */
	unsigned long counters;	/* offset 40: inuse:16|objects:15|frozen:1 */
};

/*
 * 6.2+ generation: slab_cache first, then the list/freelist union.
 * (verified against mm/slab.h v6.3 and v6.6; obj_exts and SLUB_TINY
 * variants live past the fields we touch and do not move them)
 */
struct ph_slab_gen2 {
	unsigned long __page_flags;
	struct kmem_cache *slab_cache;	/* offset 8 */
	struct list_head slab_list;	/* offset 16 */
	void *freelist;			/* offset 32 */
	unsigned long counters;		/* offset 40 */
};

static int ph_slab_ops_init(struct ph_slab_ops *ops, ph_kcache *s,
			    ph_knode *node)
{
	struct list_head *first = NULL;
	void *slab;

	ops->list_off = 0;
	ops->cache_off = 0;
	ops->layout_known = false;

	if (!list_empty(&node->partial))
		first = node->partial.next;
#ifdef CONFIG_SLUB_DEBUG
	else if (!list_empty(&node->full))
		first = node->full.next;
#endif
	if (!first)
		return 0;	/* nothing to probe against yet */

	if (!ph_kptr_ok(first) ||
	    !alirt_addr_valid((unsigned long)first, sizeof(*first)))
		return 0;	/* unsafe to peek; next node may do better */

	/* probe generation 1, then generation 2: the slab_cache field of
	 * a slab on s's own lists must point back at s */
	slab = (void *)first - offsetof(struct ph_slab_gen1, slab_list);
	if (*(struct kmem_cache **)((char *)slab +
			offsetof(struct ph_slab_gen1, slab_cache)) ==
	    (struct kmem_cache *)s) {
		ops->list_off = offsetof(struct ph_slab_gen1, slab_list);
		ops->cache_off = offsetof(struct ph_slab_gen1, slab_cache);
		ops->layout_known = true;
		return 1;
	}

	slab = (void *)first - offsetof(struct ph_slab_gen2, slab_list);
	if (*(struct kmem_cache **)((char *)slab +
			offsetof(struct ph_slab_gen2, slab_cache)) ==
	    (struct kmem_cache *)s) {
		ops->list_off = offsetof(struct ph_slab_gen2, slab_list);
		ops->cache_off = offsetof(struct ph_slab_gen2, slab_cache);
		ops->layout_known = true;
		return 1;
	}

	return -ENOENT;	/* probed, but no known layout matched */
}

static bool ph_slab_belongs(void *slab, ph_kcache *s,
			    const struct ph_slab_ops *ops)
{
	return *(struct kmem_cache **)((char *)slab + ops->cache_off) ==
	       (struct kmem_cache *)s;
}

/*
 * The freelist (32) and counters (40) offsets are identical in both
 * struct slab generations, so the gen1 offsets are used for both.
 */
static unsigned int ph_slab_objects(const void *slab)
{
	const unsigned long *counters = (const unsigned long *)
		((const char *)slab + offsetof(struct ph_slab_gen1, counters));

	return (*counters >> 16) & 0x7fff;	/* objects:15 */
}

static unsigned int ph_slab_inuse(const void *slab)
{
	const unsigned long *counters = (const unsigned long *)
		((const char *)slab + offsetof(struct ph_slab_gen1, counters));

	return *counters & 0xffff;		/* inuse:16 */
}

static void *ph_slab_freelist(const void *slab)
{
	return *(void * const *)((const char *)slab +
			offsetof(struct ph_slab_gen1, freelist));
}

#endif /* >= 5.17 */

/* ------------------------------------------------------------------ */
/* cache location                                                      */
/* ------------------------------------------------------------------ */

/*
 * Name match for the task_struct cache family.  Per-memcg children
 * (3.10 - 5.8) are named "task_struct(<css_id>)", covered by the prefix
 * match plus '(' separator.
 */
static bool ph_name_matches(const char *name)
{
	static const char root[] = "task_struct";
	size_t len = sizeof(root) - 1;

	if (!name)
		return false;
	if (strncmp(name, root, len))
		return false;
	return name[len] == '\0' || name[len] == '(';
}

/*
 * Cheap structural sanity check on a candidate kmem_cache, so that a
 * stale kallsyms hit or a corrupted list can never steer the slab walk
 * into unmapped memory.
 */
static bool ph_cache_sane(const ph_kcache *s)
{
	if (!s || !ph_kptr_ok(s))
		return false;
	if (!alirt_addr_valid((unsigned long)s, sizeof(*s)))
		return false;
	if (s->size < sizeof(struct task_struct) || s->size > (1UL << 20))
		return false;
	if (s->size % sizeof(void *))
		return false;
	if (!ph_name_matches(s->name))
		return false;
	return true;
}

/*
 * Strategy (in order):
 *  1. kallsyms_lookup_name("task_struct_cachep") - global in fork.c on
 *     every version from 2.6.32 to 6.12.
 *  2. kallsyms_lookup_name("slab_caches") + walk the cache list matching
 *     ph_name_matches().  On 2.6.32 slab_caches is static in mm/slub.c
 *     and only present in kallsyms with CONFIG_KALLSYMS_ALL.  When
 *     neither symbol resolves the module still loads and reports
 *     "task_struct cache not locatable on this kernel" at read time.
 *
 * slab_mutex (which protects slab_caches internally) is not exported,
 * so the list is walked locklessly; every entry is validated with
 * alirt_addr_valid() before it is dereferenced and the walk stops at
 * the first invalid link.  This is a deliberate best-effort fallback.
 */
static void ph_locate_caches(void)
{
	ph_kcache *root = NULL;
	struct list_head *slab_caches;

	if (ph_kln)
		root = (ph_kcache *)ph_kln("task_struct_cachep");

	if (ph_cache_sane(root)) {
		ph_caches[ph_nr_caches++] = root;
		pr_info("process_hunter: task_struct cache at 0x%px\n", root);
	} else {
		pr_warn("process_hunter: task_struct_cachep not resolvable "
			"or invalid, trying slab_caches walk\n");
	}

	slab_caches = ph_kln ? (struct list_head *)ph_kln("slab_caches") : NULL;
	if (slab_caches && ph_kptr_ok(slab_caches) &&
	    alirt_addr_valid((unsigned long)slab_caches,
			     sizeof(*slab_caches))) {
		struct list_head *pos;
		unsigned int steps = 0;

		rcu_read_lock();
		list_for_each(pos, slab_caches) {
			ph_kcache *s;

			if (ph_nr_caches >= PH_MAX_CACHES)
				break;
			if (unlikely(++steps > 2 * PH_MAX_CACHES))
				break;	/* corrupted list, stop wandering */
			if (!alirt_addr_valid((unsigned long)pos,
					      sizeof(*pos)))
				break;
			s = list_entry(pos, ph_kcache, list);
			if (!alirt_addr_valid((unsigned long)s, sizeof(*s)))
				break;
			if (ph_cache_sane(s) &&
			    (ph_nr_caches == 0 || s != ph_caches[0]))
				ph_caches[ph_nr_caches++] = s;
		}
		rcu_read_unlock();
	}

	if (!ph_nr_caches)
		pr_warn("process_hunter: task_struct cache not locatable on "
			"this kernel (KALLSYMS_ALL off?); report will say so\n");
}

/* ------------------------------------------------------------------ */
/* the scan                                                            */
/* ------------------------------------------------------------------ */

struct ph_finding {
	int		pid;
	unsigned long	state;
	bool		hidden;
	char		comm[TASK_COMM_LEN];
};

struct ph_result {
	struct ph_finding	f[PH_MAX_FINDINGS];
	unsigned int		nr;
	unsigned long		nr_slabs;
	unsigned long		nr_candidates;
	unsigned long		nr_free_filtered;
	unsigned int		nr_caches;
	bool			free_filter;	/* freelist filter applied */
	bool			full_list;	/* CONFIG_SLUB_DEBUG compiled in */
	char			note[128];
};

static DEFINE_MUTEX(ph_mutex);

/*
 * Free-slot filtering for one slab: walk the on-slab freelist chain
 * (raw pointers when CONFIG_SLAB_FREELIST_HARDENED is off, NULL
 * terminated on every non-hardened SLUB generation) and mark every
 * reachable object slot free.  The walk is fully bounded: any pointer
 * outside the slab or a hop count above the object count aborts the
 * filter for this slab (its objects then all count as active, which can
 * only add noise, never miss a hidden task).
 */
static void ph_mark_free_objs(ph_kcache *s, void *base,
			      unsigned int nr_objs, void *head,
			      unsigned long *free_bits)
{
	void *fp = head;
	unsigned int hops = 0;
	unsigned int off = s->offset;

	if (!head)
		return;
	if ((int)off < 0 || off >= (unsigned int)s->size)
		return;

	while (fp && hops <= nr_objs) {
		unsigned long delta;

		hops++;
		delta = (unsigned long)((char *)fp - (char *)base);
		if (delta >= (unsigned long)nr_objs * s->size)
			break;
		if (delta % (unsigned int)s->size)
			break;
		__set_bit(delta / (unsigned int)s->size, free_bits);
		fp = *(void **)((char *)fp + off);
	}
}

/*
 * Inspect one slab.  Called with the node's list_lock held, so only
 * spinlock-safe work happens here; everything is copied into @r.
 */
static void ph_scan_slab(ph_kcache *s, void *slab,
			 const struct ph_slab_ops *ops, bool on_full_list,
			 struct ph_result *r, unsigned long *pidmap)
{
	void *base;
	unsigned int nr, inuse, i;
	unsigned long free_bits[PH_MAX_OBJS_PER_SLAB /
					(8 * sizeof(unsigned long))];
	const unsigned int free_filter = r->free_filter;

	if (!ph_slab_belongs(slab, s, ops))
		return;

	nr = ph_slab_objects(slab);
	inuse = ph_slab_inuse(slab);
	if (!nr || nr > PH_MAX_OBJS_PER_SLAB || inuse > nr)
		return;

	base = page_address((struct page *)slab);
	r->nr_slabs++;

	memset(free_bits, 0, sizeof(free_bits));
	if (free_filter && !on_full_list)
		ph_mark_free_objs(s, base, nr, ph_slab_freelist(slab),
				  free_bits);

	for (i = 0; i < nr; i++) {
		struct task_struct *t = (struct task_struct *)
			((char *)base + (unsigned long)i * s->size);
		struct ph_finding *f;
		int pid;
		unsigned long state;

		if (free_filter && !on_full_list && test_bit(i, free_bits)) {
			r->nr_free_filtered++;
			continue;
		}

		if (!ph_looks_like_task(t))
			continue;
		r->nr_candidates++;

		if (r->nr >= PH_MAX_FINDINGS) {
			pr_warn("process_hunter: finding table full (%u entries), further hits skipped\n",
				PH_MAX_FINDINGS);
			return;
		}

		f = &r->f[r->nr++];
		/*
		 * Snapshot the fields we report on.  Held: node list_lock
		 * and the RCU read lock (see ph_collect).  Trade-off, same
		 * spirit as the original: a task that a rootkit unlinked
		 * from the task list and that is exiting concurrently is
		 * not pinned by anything we can safely take -
		 * try_get_task_struct() on an object we only heuristically
		 * identified could bump a refcount inside already-reused
		 * memory.  We therefore only *read*, never write, and
		 * accept possibly torn field values in that race window.
		 */
		pid = t->pid;
		state = ph_task_state(t);
		memcpy(f->comm, t->comm, TASK_COMM_LEN);
		f->comm[TASK_COMM_LEN - 1] = '\0';
		f->pid = pid;
		f->state = state;
		f->hidden = !test_bit(pid, pidmap);
	}
}

/* walk one node slab list (partial, or full under CONFIG_SLUB_DEBUG) */
static void ph_walk_list(ph_kcache *s, ph_knode *node,
			 struct list_head *head, bool on_full_list,
			 const struct ph_slab_ops *ops, struct ph_result *r,
			 unsigned long *pidmap)
{
	struct list_head *pos;
	unsigned int count = 0;

	pos = head->next;
	while (pos != head) {
		void *slab;

		if (unlikely(++count > PH_MAX_SLABS_PER_LIST)) {
			pr_warn("process_hunter: slab list cap (%u) reached on cache %s, truncating\n",
				PH_MAX_SLABS_PER_LIST, s->name);
			break;
		}
		if (!ph_kptr_ok(pos) ||
		    !alirt_addr_valid((unsigned long)pos, sizeof(*pos)))
			break;

		slab = (void *)pos - ops->list_off;
		ph_scan_slab(s, slab, ops, on_full_list, r, pidmap);

		pos = pos->next;
	}
}

static void ph_scan_cache(ph_kcache *s, struct ph_result *r,
			  unsigned long *pidmap)
{
	struct ph_slab_ops ops;
	bool ready = false;
	int node;

	memset(&ops, 0, sizeof(ops));

	for (node = 0; node < MAX_NUMNODES; node++) {
		ph_knode *n = ph_cache_node(s, node);

		if (!n)
			continue;
		if (!ph_kptr_ok(n) ||
		    !alirt_addr_valid((unsigned long)n, sizeof(*n))) {
			pr_warn("process_hunter: cache %s node %d pointer invalid, skipping\n",
				s->name, node);
			continue;
		}

		if (!ready) {
			int ret = ph_slab_ops_init(&ops, s, n);

			if (ret > 0) {
				ready = true;
			} else if (ret < 0) {
				snprintf(r->note, sizeof(r->note),
					 "struct slab layout unrecognised on this kernel; cache scan skipped");
				return;
			}
			/* ret == 0: nothing to probe on this node, try the
			 * next one */
		}
		if (!ready)
			continue;

		spin_lock(&n->list_lock);
		ph_walk_list(s, n, &n->partial, false, &ops, r, pidmap);
#ifdef CONFIG_SLUB_DEBUG
		/* node->full exists in the struct in every SLUB version,
		 * but the kernel only populates it for SLAB_STORE_USER
		 * caches (i.e. under slub_debug=).  Walking it is safe
		 * either way. */
		ph_walk_list(s, n, &n->full, true, &ops, r, pidmap);
#endif
		spin_unlock(&n->list_lock);
	}
}

/*
 * One full scan.  Serialized by ph_mutex so concurrent opens cannot
 * interleave the dmesg mirror.  Returns a vmalloc'ed result (free with
 * vfree()) or NULL on allocation failure.
 */
static struct ph_result *ph_collect(void)
{
	struct ph_result *r;
	unsigned long *pidmap;
	struct task_struct *t;
	unsigned int i;

	mutex_lock(&ph_mutex);

	r = vmalloc(sizeof(*r));
	if (!r)
		goto out;
	memset(r, 0, sizeof(*r));

	pidmap = vmalloc(PH_PIDMAP_BYTES);
	if (!pidmap) {
		vfree(r);
		r = NULL;
		goto out;
	}
	memset(pidmap, 0, PH_PIDMAP_BYTES);

#ifdef CONFIG_SLAB_FREELIST_HARDENED
	r->free_filter = false;	/* obfuscated freelist, decode unsafe */
#else
	r->free_filter = true;
#endif
#ifdef CONFIG_SLUB_DEBUG
	r->full_list = true;
#endif

	/*
	 * Build the pid set from the kernel's own task list, then scan.
	 * Both the bitmap fill and the candidate snapshot hold
	 * rcu_read_lock only (tasklist_lock is not exported on any
	 * supported kernel — see the note near the top of this file).
	 * RCU covers the whole window: the tasks list is unlinked with
	 * list_del_rcu() and task_struct is freed only after an RCU grace
	 * period on every kernel in range (verified in kernel/exit.c
	 * v2.6.32 and v6.1).  See ph_scan_slab for the residual race we
	 * accept on deliberately-unlinked tasks.
	 */
	rcu_read_lock();
	for_each_process(t) {
		pid_t pid = t->pid;

		if (pid >= 1 && pid < PH_PID_MAX)
			__set_bit(pid, pidmap);
	}

	for (i = 0; i < ph_nr_caches; i++)
		ph_scan_cache(ph_caches[i], r, pidmap);

	rcu_read_unlock();

	r->nr_caches = ph_nr_caches;
	vfree(pidmap);
out:
	mutex_unlock(&ph_mutex);
	return r;
}

/* ------------------------------------------------------------------ */
/* report generation (seq_file + printk dual channel)                  */
/* ------------------------------------------------------------------ */

/*
 * Emit one report line: format once into a bounded buffer, then push
 * it to the seq_file with seq_write() (available and exported since
 * 2.6.32; seq_vprintf() only appeared much later) and mirror it to the
 * kernel log.
 */
__printf(2, 3)
static void ph_emit(struct seq_file *m, const char *fmt, ...)
{
	va_list ap;
	char buf[320];

	va_start(ap, fmt);
	vscnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (m)
		seq_write(m, buf, strlen(buf));
	pr_info("process_hunter: %s", buf);
}

static int ph_show(struct seq_file *m, void *v)
{
	struct ph_result *r = m->private;
	unsigned int i;
	unsigned int n_hidden = 0;

	if (!r) {
		seq_puts(m, "process_hunter: scan failed (out of memory)\n");
		return 0;
	}

	if (!r->nr_caches) {
		ph_emit(m, "task_struct cache not locatable on this kernel\n");
		ph_emit(m, "hints: symbol not in kallsyms? "
			    "CONFIG_KALLSYMS_ALL disabled? cache renamed?\n");
		return 0;
	}

	ph_emit(m, "=== process_hunter v%s report (built for kernel %d.%d.%d) ===\n",
		PH_VERSION,
		(LINUX_VERSION_CODE >> 16) & 0xff,
		(LINUX_VERSION_CODE >> 8) & 0xff,
		LINUX_VERSION_CODE & 0xff);
	ph_emit(m, "scanned %u task_struct cache(s), %lu slab(s): "
		    "%lu candidate(s), %lu free slot(s) filtered out\n",
		r->nr_caches, r->nr_slabs, r->nr_candidates,
		r->nr_free_filtered);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0)
	ph_emit(m, "slab era: struct page (2.6.32-5.16 layout)\n");
#else
	ph_emit(m, "slab era: struct slab (5.17+ layout, runtime detected)\n");
#endif
	ph_emit(m, "full slab list: %s (populated only for SLAB_STORE_USER "
		    "caches, i.e. slub_debug enabled)\n",
		r->full_list ? "available" : "not compiled in (CONFIG_SLUB_DEBUG off)");
	if (!r->free_filter)
		ph_emit(m, "free-filter unavailable, expect noise "
			    "(CONFIG_SLAB_FREELIST_HARDENED)\n");
	if (r->note[0])
		ph_emit(m, "note: %s\n", r->note);

	ph_emit(m, "%16s %5s %18s\n", "name", "pid", "state");

	for (i = 0; i < r->nr; i++) {
		const struct ph_finding *f = &r->f[i];

		if (f->hidden)
			n_hidden++;
		ph_emit(m, "%16s %5d %18s %lu%s\n",
			f->comm, f->pid, ph_parse_state(f->state), f->state,
			f->hidden ? " Warning<--" : "");
	}

	ph_emit(m, "=== summary: %u process(es) in task_struct slabs, "
		    "%u visible, %u Warning (hidden process) ===\n",
		r->nr, r->nr - n_hidden, n_hidden);
	return 0;
}

static int ph_open(struct inode *inode, struct file *file)
{
	struct seq_file *m;
	int ret;

	ret = single_open(file, ph_show, NULL);
	if (ret)
		return ret;
	m = file->private_data;
	m->private = ph_collect();	/* NULL on allocation failure */
	return 0;
}

static int ph_release(struct inode *inode, struct file *file)
{
	struct seq_file *m = file->private_data;

	if (m)
		vfree(m->private);
	return single_release(inode, file);
}

/* ------------------------------------------------------------------ */
/* procfs registration                                                 */
/* ------------------------------------------------------------------ */

#if ALIRT_HAVE_PROC_OPS
static const struct proc_ops ph_ops = {
	.proc_open	= ph_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= ph_release,
};
#else
static const struct file_operations ph_ops = {
	.open		= ph_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= ph_release,
};
#endif

static struct proc_dir_entry *ph_entry;

static int __init ph_init(void)
{
	int ret;

	pr_info("process_hunter: ALIRT hidden process hunter v%s\n",
		PH_VERSION);

	ret = alirt_resolve_kln(&ph_kln);
	if (ret)
		pr_warn("process_hunter: kallsyms unavailable (%d), "
			"cache location disabled\n", ret);

	/* init_mm is not exported on any supported kernel; resolve it
	 * here or alirt_addr_valid() degrades to always-false (see
	 * alirt_mm.h).  Resolution must precede ph_locate_caches(), the
	 * first alirt_addr_valid() consumer. */
	if (ph_kln && alirt_mm_init(ph_kln))
		pr_warn("process_hunter: init_mm not in kallsyms "
			"(need CONFIG_KALLSYMS_ALL); page-table "
			"validation disabled, scan degraded\n");

	ph_locate_caches();

	ph_entry = proc_create(PH_PROC_NAME, PH_PROC_MODE, NULL, &ph_ops);
	if (!ph_entry) {
		pr_err("process_hunter: failed to create /proc/%s\n",
		       PH_PROC_NAME);
		return -ENOMEM;
	}
	pr_info("process_hunter: /proc/%s created (read = full report)\n",
		PH_PROC_NAME);
	return 0;
}

static void __exit ph_exit(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
	proc_remove(ph_entry);
#else
	/* proc_remove() does not exist on 2.6.32 */
	remove_proc_entry(PH_PROC_NAME, NULL);
#endif
	pr_info("process_hunter: unloaded\n");
}

#else /* !PH_HAVE_MM */

static int __init ph_init(void)
{
	pr_err("process_hunter: unsupported architecture "
	       "(x86_64 only for now), refusing to load\n");
	return -ENODEV;
}

static void __exit ph_exit(void)
{
}

#endif /* PH_HAVE_MM */

module_init(ph_init);
module_exit(ph_exit);

/*
 * MODULE_LICENSE accepts only "GPL" (= v2) in kbuild; the effective
 * licence of this file is GPL-3.0-only as stated in the SPDX tag.
 */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("madsys");
MODULE_DESCRIPTION("ALIRT hidden process hunter: SLUB task_struct cache "
		   "walk vs. task list cross-check via /proc/showprocess");
MODULE_VERSION(PH_VERSION);
