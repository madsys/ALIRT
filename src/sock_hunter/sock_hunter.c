// SPDX-License-Identifier: GPL-3.0-only
/*
 * sock_hunter.c - ALIRT hidden socket hunter (v0.6.0)
 *
 * Passive enumerator of struct sock objects straight out of the SLUB
 * caches that back the TCP/UDP/RAW protocol families ("TCP", "UDP",
 * "RAW", and since this rewrite also "TCPv6", "UDPv6", "RAWv6").
 * Sockets unlinked from every kernel hash table (i.e. invisible to
 * netstat/ss/proc) still occupy their slab object, so a cache walk
 * sees them. Findings are reported through a seq_file based
 * /proc/showsocks and mirrored to the kernel log.
 *
 * Acknowledgements / lineage:
 *   - madsys, AIRT (2005). The original sock_hunter walked the SLAB
 *     allocator of the Linux 2.4/2.6 era (slabs_full/slabs_partial
 *     lists plus the bufctl free chain) to find hidden sockets.
 *   - This file is the SLUB rewrite: the SLAB internals the original
 *     relied on are long gone, so the walker speaks SLUB instead,
 *     across the three slab container layouts the kernel has used:
 *         2.6.32 - 5.16 : struct page on kmem_cache_node.partial
 *         5.17   - 6.1  : struct slab, list node first (@8),
 *                         slab_cache @24 (mm/slab.h v5.17/v6.0/v6.1)
 *         6.2+          : struct slab, slab_cache first (@8),
 *                         list node @16 (mm/slab.h v6.2 .. v6.12)
 *
 * New in this ALIRT version (v0.5.2):
 *   - SLAB -> SLUB migration (three-era slab container support, see
 *     above; struct kmem_cache is taken from the public
 *     <linux/slub_def.h> up to 6.11 and from a layout-verified private
 *     copy on 6.12+ where SLAB removal moved it into mm/slab.h);
 *   - IPv6 support: the v6 caches (TCPv6/UDPv6/RAWv6) are walked and
 *     v6 local addresses printed, incl. ::ffff:a.b.c.d rendering of
 *     IPv4-mapped addresses; everything v6 is compiled out when the
 *     kernel has no IPv6 (see SH_HAVE_IPV6);
 *   - seq_file + dmesg dual-channel report via /proc/showsocks (same
 *     design as mod_hunter): the full report reaches userland through
 *     copy_to_user and cannot be suppressed by a rootkit that hijacks
 *     printk/dmesg;
 *   - verdict column is PASSIVE for every row: unlike hidden modules
 *     there is no global socket list to cross-validate against, so a
 *     row only means "this slab object looks like a live socket".
 *     Hidden ports must be confirmed by diffing against netstat/ss.
 *
 * Supported: Linux 2.6.32 - 6.12+ with CONFIG_SLUB. Kernels using the
 * classic SLAB (or SLOB) refuse module load with -ENODEV.
 * Any other failure mode degrades the report, never panics.
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
#include <linux/mutex.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/kobject.h>
#include <linux/cpumask.h>
#include <linux/kallsyms.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <linux/tcp.h>		/* struct tcp_sock */
#include <net/udp.h>		/* struct udp_sock */
#include <net/raw.h>		/* struct raw_sock */

#include "compat.h"

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
/*
 * <linux/ipv6.h> carries struct ipv6_pinfo (saddr is a direct field in
 * every supported version) and, inside IS_ENABLED(CONFIG_IPV6), the
 * inet6_sk() helper, which is inet_sk(sk)->pinet6 in all of them.
 * With CONFIG_IPV6=n the header still compiles and provides NULL
 * stub inet6_sk(), but we exclude the v6 code paths anyway so the
 * report can state "IPv6 not compiled in".
 */
#include <linux/ipv6.h>
#define SH_HAVE_IPV6 1
#endif

/*
 * kallsyms_lookup_name() stopped being exported in 5.7; the shared
 * resolver in compat.h (alirt_resolve_kln) handles the <5.7 direct
 * call and the 5.7+ kprobe trick.  Without symbol resolution the
 * module still loads but the report says the scan was skipped.
 */
static unsigned long (*sh_lookup_name)(const char *name);

static int sh_resolve_kallsyms(void)
{
	return alirt_resolve_kln(&sh_lookup_name);
}

#define SH_VERSION		"0.6.0"

#define SH_PROC_NAME		"showsocks"	/* keep the original name */
#define SH_PROC_MODE		S_IRUSR

/*
 * Hard caps, pure safety nets against corrupted slab metadata. A full
 * sock cache holds at most a few thousand objects on real systems.
 */
#define SH_MAX_CACHES		64
#define SH_MAX_SLABS		16384	/* per cache, partial + cpu slabs */
#define SH_MAX_OBJS_PER_SLAB	4096
#define SH_MAX_SOCKS		4096
#define SH_MAX_OBJ_BITS		SH_MAX_OBJS_PER_SLAB
#define SH_MAX_OBJ_WORDS	(SH_MAX_OBJ_BITS / BITS_PER_LONG)

/*
 * The slab container changed three times. Everything below that
 * touches a slab goes through sh_slabview so all eras stay in one
 * place.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0)
#define SH_SLAB_PAGE 1		/* node->partial links struct page (lru) */
#elif LINUX_VERSION_CODE < KERNEL_VERSION(6, 2, 0)
#define SH_SLAB_GEN1 1		/* 5.17-6.1: list node first, slab_cache last */
#else
#define SH_SLAB_GEN2 1		/* 6.2+: slab_cache first, list node second */
#endif

#ifdef CONFIG_SLUB

/* strscpy_pad() only exists since 4.3; strlcpy() covers the shim */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
#define strscpy_pad(d, s, n) strlcpy(d, s, n)
#endif

/* ================================================================== */
/* private copies of structs that went private                        */
/* ================================================================== */

/*
 * 5.17+: struct slab lives in the private mm/slab.h (it never had a
 * public definition) and was released in TWO layouts:
 *
 *   gen1 (5.17 - 6.1; verified verbatim against mm/slab.h v5.17, v6.0,
 *        v6.1): __page_flags@0, slab_list@8 (in a union with rcu_head
 *        and the CONFIG_SLUB_CPU_PARTIAL per-cpu-partial chain),
 *        slab_cache@24, freelist@32, counters@40
 *        (inuse:16 | objects:15 | frozen:1)
 *   gen2 (6.2+; verified verbatim against mm/slab.h v6.2 through
 *        v6.12): __page_flags@0, slab_cache@8, slab_list@16,
 *        freelist@32, counters@40.  Trailing fields (freelist ABA
 *        union, __page_type, refcount, memcg/obj_exts) are irrelevant
 *        here and omitted; none of them moves the fields above.
 *
 * SLAB_MATCH(compound_head, slab_list) makes the slab pointer equal to
 * the head struct page address in both generations, so the object base
 * is page_address((struct page *)slab).
 */
#if defined(SH_SLAB_GEN1) || defined(SH_SLAB_GEN2)
struct sh_slab_gen1 {
	unsigned long __page_flags;
	union {
		struct list_head slab_list;	/* @8 */
		struct {
			struct sh_slab_gen1 *next;	/* cpu partial chain */
			int slabs;
		};
	};
	struct kmem_cache *slab_cache;	/* @24 */
	void *freelist;			/* @32 */
	union {
		unsigned long counters;	/* @40 */
		struct {
			unsigned inuse:16;
			unsigned objects:15;
			unsigned frozen:1;
		};
	};
};

struct sh_slab_gen2 {
	unsigned long __page_flags;
	struct kmem_cache *slab_cache;	/* @8 */
	struct list_head slab_list;	/* @16 */
	void *freelist;			/* @32 */
	union {
		unsigned long counters;	/* @40 */
		struct {
			unsigned inuse:16;
			unsigned objects:15;
			unsigned frozen:1;
		};
	};
};

#  ifdef SH_SLAB_GEN1
typedef struct sh_slab_gen1 sh_slab_t;
#    define SH_SLAB_LIST_OFF	offsetof(struct sh_slab_gen1, slab_list)
#  else
typedef struct sh_slab_gen2 sh_slab_t;
#    define SH_SLAB_LIST_OFF	offsetof(struct sh_slab_gen2, slab_list)
#  endif
#endif /* SH_SLAB_GEN1 || SH_SLAB_GEN2 */

/*
 * 6.12 removed the SLAB allocator and moved struct kmem_cache (plus
 * struct slab, struct kmem_cache_node, struct kmem_cache_cpu) from the
 * public <linux/slub_def.h> into the private mm/slab.h. Up to 6.11 we
 * use the real kmem_cache/kmem_cache_cpu from <linux/slub_def.h> (see
 * the note below for the node); on 6.12+ this layout-verified private
 * copy stands in (verified verbatim against v6.12 mm/slab.h, including
 * the order of every conditional field).
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include <linux/reciprocal_div.h>
#include <linux/kasan.h>

struct sh_kmem_cache_cpu {
	/*
	 * Same leading layout as struct kmem_cache_cpu (freelist@0,
	 * tid@8, slab@16 on 64-bit; the freelist_aba_t union alternative
	 * has the same footprint on the 64-bit configs ALIRT targets).
	 * Only the slab field is consumed.
	 */
	void **freelist;
	unsigned long tid;
	sh_slab_t *slab;
};

struct sh_kmem_cache_node {
	/* v6.12 mm/slub.c: list_lock, nr_partial, partial; the
	 * SLUB_DEBUG extras are part of the real layout and must be
	 * kept conditional so "partial" stays at the right offset when
	 * CONFIG_SLUB_DEBUG=y. */
	spinlock_t list_lock;
	unsigned long nr_partial;
	struct list_head partial;
#ifdef CONFIG_SLUB_DEBUG
	atomic_long_t nr_slabs;
	atomic_long_t total_objects;
	struct list_head full;
#endif
};

struct sh_kmem_cache {
#ifndef CONFIG_SLUB_TINY
	struct sh_kmem_cache_cpu __percpu *cpu_slab;
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
	struct sh_kmem_cache_node *node[MAX_NUMNODES];
};
#endif /* >= 6.12 */

/* Real header definitions up to 6.11, private copies from 6.12 on.
 * <linux/slub_def.h> provides struct kmem_cache and struct kmem_cache_cpu
 * on every version from 2.6.32 through 6.11 (verified v2.6.32/v3.10/
 * v4.4/v4.19/v5.4/v5.15/v6.1; 6.12 removed the header).  struct
 * kmem_cache_node is public in slub_def.h only through v3.9 (verified
 * v2.6.32/v2.6.35/v2.6.37/v3.0/v3.5/v3.9, layout-identical to the copy
 * below); v3.10 moved it to the private mm/slab.h whose SLUB branch is
 * verbatim identical across v3.10 .. v6.1 (list_lock, nr_partial,
 * partial, then the CONFIG_SLUB_DEBUG nr_slabs/total_objects/full
 * tail), and 6.12 moved it into mm/slub.c (private copy above).  So
 * below 6.12 the private node copy stands in for the real type; only
 * the fields through "partial" are consumed, and the SLUB_DEBUG tail
 * is kept conditional so nothing shifts when it is enabled. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
#include <linux/slub_def.h>

struct sh_kmem_cache_node {
	spinlock_t list_lock;
	unsigned long nr_partial;
	struct list_head partial;
#ifdef CONFIG_SLUB_DEBUG
	atomic_long_t nr_slabs;
	atomic_long_t total_objects;
	struct list_head full;
#endif
};

typedef struct kmem_cache sh_kcache;
typedef struct sh_kmem_cache_node sh_knode;
typedef struct kmem_cache_cpu sh_kcpu;
#else
typedef struct sh_kmem_cache sh_kcache;
typedef struct sh_kmem_cache_node sh_knode;
typedef struct sh_kmem_cache_cpu sh_kcpu;
#endif

/* ================================================================== */
/* version-smoothed accessors                                          */
/* ================================================================== */

/*
 * struct inet_sock field rename ("sport/num/saddr/rcv_saddr" ->
 * "inet_sport/inet_num/inet_saddr/inet_rcv_saddr" plus sk_common
 * aliases) landed in 3.6, the same release that renamed
 * kmem_cache.objsize to object_size.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
#define SH_INET_NUM(sk)		(inet_sk(sk)->inet_num)
#define SH_INET_SPORT(sk)	(inet_sk(sk)->inet_sport)
#define SH_INET_SADDR(sk)	(inet_sk(sk)->inet_saddr)
#define SH_INET_RCV_SADDR(sk)	(inet_sk(sk)->inet_rcv_saddr)
static inline unsigned int sh_cache_objsize(const sh_kcache *s)
{
	return s->object_size;
}
#else
#define SH_INET_NUM(sk)		(inet_sk(sk)->num)
#define SH_INET_SPORT(sk)	(inet_sk(sk)->sport)
#define SH_INET_SADDR(sk)	(inet_sk(sk)->saddr)
#define SH_INET_RCV_SADDR(sk)	(inet_sk(sk)->rcv_saddr)
static inline unsigned int sh_cache_objsize(const sh_kcache *s)
{
	return s->objsize;
}
#endif

/*
 * Per-cpu kmem_cache_cpu access. 2.6.32 is special: cpu_slab is an
 * NR_CPUS-sized pointer array under CONFIG_SMP and a single embedded
 * struct otherwise. 3.0 switched to the __percpu pointer that is still
 * used today. CONFIG_SLUB_TINY (6.12+) has no per-cpu slab at all.
 */
static inline sh_kcpu *sh_cpu_slab(sh_kcache *s, int cpu)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0)
# ifdef CONFIG_SMP
	return s->cpu_slab[cpu];
# else
	return &s->cpu_slab;
# endif
#else
# ifndef CONFIG_SLUB_TINY
	return per_cpu_ptr(s->cpu_slab, cpu);
# else
	return NULL;
# endif
#endif
}

/* The "current slab" field of kmem_cache_cpu: page@8 pre-5.17 (real
 * header gives the name), slab from 5.17 on. */
static inline void *sh_cpu_slab_cur(const sh_kcpu *c)
{
#ifdef SH_SLAB_PAGE
	return c->page;
#else
	return c->slab;
#endif
}

/*
 * kmem_cache_node lookup, 2.6.x only has two layouts (verified against
 * include/linux/slub_def.h v2.6.32/v2.6.34/v2.6.35/v2.6.36/v2.6.37):
 *   - 2.6.32-2.6.34: local_node is unconditional (present under
 *     CONFIG_NUMA too; slub.c points node[local_node] at it);
 *   - 2.6.35-2.6.36: local_node only when !CONFIG_NUMA;
 *   - 2.6.37+: node[] is unconditional, local_node is gone.
 * In both NUMA layouts node[n] is NULL for nodes without memory, so a
 * plain node[] walk with NULL checks covers every <3.0 kernel; the
 * !NUMA kernels all keep local_node.
 */
static inline sh_knode *sh_get_node(sh_kcache *s, int nid)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0)
# ifdef CONFIG_NUMA
	return (sh_knode *)s->node[nid];
# else
	return (sh_knode *)&s->local_node;
# endif
#else
	return (sh_knode *)s->node[nid];
#endif
}

/* ================================================================== */
/* slab view: one abstraction over both container eras                */
/* ================================================================== */

struct sh_slabview {
	void *base;		/* first object address */
	void *freelist;		/* first free object, best effort */
	unsigned int objects;
	unsigned int inuse;
};

static inline void sh_slabview_fill(struct sh_slabview *v, const void *entry)
{
#ifdef SH_SLAB_PAGE
	const struct page *p = entry;

	v->base = page_address(p);
	v->freelist = p->freelist;
	v->objects = p->objects;
	v->inuse = p->inuse;
#else
	const sh_slab_t *sl = entry;

	v->base = page_address((struct page *)sl);
	v->freelist = sl->freelist;
	v->objects = sl->objects;
	v->inuse = sl->inuse;
#endif
}

/* A slab view is plausible: base mapped, object count sane. */
static inline bool sh_slabview_valid(const struct sh_slabview *v,
				     unsigned int csize)
{
	if (!v->base || !v->objects || v->objects > SH_MAX_OBJS_PER_SLAB)
		return false;
	if (!csize || (unsigned long)v->base & (sizeof(long) - 1))
		return false;
	return true;
}

/* ================================================================== */
/* socket recognition heuristics                                      */
/* ================================================================== */

enum sh_kind {
	SH_TCP4, SH_UDP4, SH_RAW4,
	SH_TCP6, SH_UDP6, SH_RAW6,
	SH_NR_KINDS
};

/*
 * Cache name candidates. Socket caches are created by proto_register()
 * from proto->name and have been "TCP"/"UDP"/"RAW" (v4) and
 * "TCPv6"/"UDPv6"/"RAWv6" (v6) from 2.6.32 through 6.12; the lowercase
 * *_sock spellings cover the pre-2.6.12 era for completeness. Match is
 * prefix + terminator: the next character must be NUL or '(' so that
 * "TCP" never matches "TCPv6" and a merged-alias name like
 * "TCP(aaaaaaa)" still matches. memcg sub-caches keep the same name and
 * sit on the same slab_caches list, so walking the global list covers
 * them naturally.
 */
static const char * const sh_cache_names[SH_NR_KINDS][4] = {
	[SH_TCP4] = { "TCP", "tcp_sock", NULL },
	[SH_UDP4] = { "UDP", "udp_sock", NULL },
	[SH_RAW4] = { "RAW", "raw_sock", NULL },
#ifdef SH_HAVE_IPV6
	[SH_TCP6] = { "TCPv6", "tcp6_sock", NULL },
	[SH_UDP6] = { "UDPv6", "udp6_sock", NULL },
	[SH_RAW6] = { "RAWv6", "raw6_sock", NULL },
#endif
};

static const char * const sh_kind_label[SH_NR_KINDS] = {
	[SH_TCP4] = "TCP",  [SH_UDP4] = "UDP",  [SH_RAW4] = "RAW",
#ifdef SH_HAVE_IPV6
	[SH_TCP6] = "TCP6", [SH_UDP6] = "UDP6", [SH_RAW6] = "RAW6",
#endif
};

static int sh_match_cache(const char *name)
{
	int k, i;

	if (!name)
		return -1;
	for (k = 0; k < SH_NR_KINDS; k++) {
		for (i = 0; sh_cache_names[k][i]; i++) {
			const char *cand = sh_cache_names[k][i];
			size_t len = strlen(cand);

			if (!strncmp(name, cand, len) &&
			    (name[len] == '\0' || name[len] == '('))
				return k;
		}
	}
	return -1;
}

/* Minimum object size per kind: the full protocol struct must fit. */
static unsigned int sh_kind_min_size(int kind)
{
	switch (kind) {
	case SH_TCP4:
#ifdef SH_HAVE_IPV6
	case SH_TCP6:
#endif
		return sizeof(struct tcp_sock);
	case SH_UDP4:
#ifdef SH_HAVE_IPV6
	case SH_UDP6:
#endif
		return sizeof(struct udp_sock);
	default:
		return sizeof(struct raw_sock);
	}
}

/*
 * Heuristic struct sock recognition:
 *   - family is AF_INET (v4 kinds) or AF_INET6 (v6 kinds)
 *   - type matches the kind (STREAM/DGRAM/RAW)
 *   - sk_state within the TCP state range (UDP/RAW sockets carry
 *     TCP_CLOSE=7 there in every supported version)
 *   - cache object size fits the protocol struct
 *   - bound non-RAW sockets satisfy ntohs(sport) == num (port and its
 *     network-order echo must agree)
 */
static bool sh_looks_like_sock(const struct sock *sk, int kind,
			       unsigned int objsize)
{
	if (kind < 0 || kind >= SH_NR_KINDS)
		return false;
	if (objsize < sh_kind_min_size(kind))
		return false;

#ifdef SH_HAVE_IPV6
	if (kind >= SH_TCP6) {
		if (sk->sk_family != 10 /* AF_INET6 */)
			return false;
	} else
#endif
	{
		if (sk->sk_family != AF_INET)
			return false;
	}

	switch (kind) {
	case SH_TCP4:
#ifdef SH_HAVE_IPV6
	case SH_TCP6:
#endif
		if (sk->sk_type != SOCK_STREAM)
			return false;
		break;
	case SH_UDP4:
#ifdef SH_HAVE_IPV6
	case SH_UDP6:
#endif
		if (sk->sk_type != SOCK_DGRAM)
			return false;
		break;
	default:
		if (sk->sk_type != SOCK_RAW)
			return false;
		break;
	}

	if (sk->sk_state > 12)	/* TCP_NEW_SYN_RECV is 12 on >= 4.6;
				   older kernels top out at CLOSING=11 */
		return false;

	if (sk->sk_type != SOCK_RAW && ntohs(SH_INET_SPORT(sk)) != SH_INET_NUM(sk))
		return false;

	return true;
}

#ifdef SH_HAVE_IPV6
static bool sh_addr6_any(const struct in6_addr *a)
{
	return !(a->s6_addr32[0] | a->s6_addr32[1] |
		 a->s6_addr32[2] | a->s6_addr32[3]);
}

static bool sh_addr6_v4mapped(const struct in6_addr *a)
{
	return !a->s6_addr32[0] && !a->s6_addr32[1] &&
		a->s6_addr32[2] == cpu_to_be32(0xffff);
}

/*
 * Local v6 address: prefer ipv6_pinfo.saddr when it is not anycast,
 * fall back to the receive address.  ipv6_pinfo.rcv_saddr was moved
 * into struct sock_common as skc_v6_rcv_saddr (exposed as
 * sk->sk_v6_rcv_saddr) in 3.13 — verified: ipv6_pinfo still carries
 * rcv_saddr in v3.12 and loses it in v3.13, where sock.h gains
 * skc_v6_rcv_saddr.  IPv4-mapped addresses print as ::ffff:a.b.c.d,
 * the kernel has no IN6_IS_ADDR_V4MAPPED helper in-kernel so the check
 * is done by hand.
 */
static void sh_v6_addr(const struct sock *sk, char *buf, size_t buflen)
{
	const struct ipv6_pinfo *p6 = inet6_sk(sk);
	struct in6_addr addr;
	const __be32 *v4;
	bool mapped;

	if (!p6) {
		scnprintf(buf, buflen, "<no-pinet6>");
		return;
	}
	addr = p6->saddr;
	if (sh_addr6_any(&addr)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
		addr = sk->sk_v6_rcv_saddr;
#else
		addr = p6->rcv_saddr;
#endif
	}
	mapped = sh_addr6_v4mapped(&addr);
	if (mapped) {
		v4 = &addr.s6_addr32[3];
		scnprintf(buf, buflen, "::ffff:%pI4", v4);
	} else {
		scnprintf(buf, buflen, "%pI6", &addr);
	}
}
#endif /* SH_HAVE_IPV6 */

/* ================================================================== */
/* collection engine                                                  */
/* ================================================================== */

struct sh_sockrec {
	unsigned long obj;		/* slab object address */
	char proto[8];
	char addr[48];			/* local address, ::ffff: aware */
	char state[20];			/* TCP state name / "-" / raw proto */
	unsigned int port;
};

struct sh_result {
	struct sh_sockrec	*socks;
	unsigned int		nr;
	unsigned int		cap;
	char			caches[SH_MAX_CACHES][32];
	unsigned int		nr_caches;
	unsigned long		slabs;
	unsigned long		objs;
	bool			kallsyms_ok;
	struct list_head	*slab_caches;
};

static DEFINE_MUTEX(sh_mutex);

/* defined with the report generators below */
static const char *sh_tcp_state_name(unsigned int st);

/*
 * Best-effort free-object marking: walk the SLUB freelist from its
 * head following the freepointer stored at object+s->offset, marking a
 * bitmap, and stop at the first pointer that is out of range, unaligned,
 * cyclic, or after "objects" steps. CONFIG_SLAB_FREELIST_HARDENED
 * obfuscates the pointers; an undecodable chain simply stops early,
 * leaving the rest of the bitmap clear (see risk notes in the report).
 */
static void sh_mark_freemap(const struct sh_slabview *v, unsigned int stride,
			    unsigned int foff, unsigned long *map)
{
	void *fp = v->freelist;
	unsigned int steps = 0;

	memset(map, 0, SH_MAX_OBJ_WORDS * sizeof(unsigned long));
	while (fp && steps < v->objects) {
		unsigned long off = (unsigned long)fp - (unsigned long)v->base;
		unsigned int idx;

		if (off % stride)
			break;
		idx = off / stride;
		if (idx >= v->objects || test_bit(idx, map))
			break;
		__set_bit(idx, map);
		fp = *(void **)((unsigned long)fp + foff);
		steps++;
	}
}

static void sh_scan_slab(struct sh_result *r, const struct sh_slabview *v,
			 sh_kcache *s, int kind)
{
	const unsigned int csize = s->size;
	const unsigned int foff = s->offset;
	const unsigned int objsize = sh_cache_objsize(s);
	unsigned long freemap[SH_MAX_OBJ_WORDS];
	unsigned int i;

	sh_mark_freemap(v, csize, foff, freemap);
	r->slabs++;

	for (i = 0; i < v->objects; i++) {
		struct sock *sk = (struct sock *)((unsigned long)v->base +
						  i * csize);
		struct sh_sockrec *rec;

		if (test_bit(i, freemap))
			continue;
		r->objs++;
		if (r->nr >= r->cap)
			return;
		if (!sh_looks_like_sock(sk, kind, objsize))
			continue;

		rec = &r->socks[r->nr++];
		rec->obj = (unsigned long)sk;
		strscpy_pad(rec->proto, sh_kind_label[kind],
			    sizeof(rec->proto));
		rec->port = SH_INET_NUM(sk);

		switch (kind) {
		case SH_TCP4:
#ifdef SH_HAVE_IPV6
		case SH_TCP6:
#endif
			scnprintf(rec->state, sizeof(rec->state), "%s",
				  sh_tcp_state_name(sk->sk_state));
			break;
		case SH_UDP4:
#ifdef SH_HAVE_IPV6
		case SH_UDP6:
#endif
			strscpy_pad(rec->state, "-", sizeof(rec->state));
			break;
		default:	/* RAW: the "state" column carries the
				   IP protocol number */
			scnprintf(rec->state, sizeof(rec->state), "proto=%u",
				  sk->sk_protocol);
			break;
		}

#ifdef SH_HAVE_IPV6
		if (kind >= SH_TCP6) {
			sh_v6_addr(sk, rec->addr, sizeof(rec->addr));
		} else
#endif
		{
			__be32 a = SH_INET_RCV_SADDR(sk);

			if (!a)
				a = SH_INET_SADDR(sk);
			scnprintf(rec->addr, sizeof(rec->addr), "%pI4", &a);
		}
	}
}

/*
 * Collect slab views of one cache: per-node partial lists (taken under
 * the node's list_lock; the list cannot change while we hold it, and
 * the metadata is copied out before we drop the lock) plus each cpu's
 * current slab (read once; a racing allocator can swap it, so every
 * view is validated before use - a torn read fails validation and is
 * skipped, never dereferenced further). The per-cpu partial chain is
 * deliberately not walked: it does not exist on !CONFIG_SLUB_CPU_PARTIAL
 * kernels and its node pointer moved repeatedly between versions; the
 * cpu current slab plus the node partials already cover the vast
 * majority of live objects (fully-freed slabs are gone anyway and
 * full slabs are the documented blind spot, see report).
 */
static void sh_collect_cache(struct sh_result *r, sh_kcache *s, int kind,
			     struct sh_slabview *views, unsigned int vcap)
{
	unsigned int csize = s->size;
	unsigned int nviews = 0;
	unsigned int i;
	int cpu;
#ifdef CONFIG_NUMA
	int nid;
#endif

#ifdef CONFIG_NUMA
	/*
	 * Walk every possible node id: node[nid] is NULL for nodes without
	 * memory (the cache struct is zero-allocated), so this is exactly
	 * what get_node()-based loops do.  nr_node_ids is deliberately not
	 * used — its export status varies between kernel versions and it
	 * does not exist at all on !NUMA builds.
	 */
	for (nid = 0; nid < MAX_NUMNODES; nid++) {
		sh_knode *n = sh_get_node(s, nid);
		unsigned long flags;

		if (!n || nviews >= vcap)
			continue;
		spin_lock_irqsave(&n->list_lock, flags);
#ifdef SH_SLAB_PAGE
		{
			struct page *p;

			list_for_each_entry(p, &n->partial, lru) {
				if (nviews >= vcap)
					break;
				sh_slabview_fill(&views[nviews++], p);
			}
		}
#else
		{
			/* struct slab era: the list node sits at a different
			 * offset in each generation, so walk the raw list
			 * and derive the slab pointer from SH_SLAB_LIST_OFF */
			struct list_head *pos = n->partial.next;

			while (pos != &n->partial) {
				if (nviews >= vcap)
					break;
				sh_slabview_fill(&views[nviews++],
						 (char *)pos - SH_SLAB_LIST_OFF);
				pos = pos->next;
			}
		}
#endif
		spin_unlock_irqrestore(&n->list_lock, flags);
	}
#else
	{
		sh_knode *n = sh_get_node(s, 0);
		unsigned long flags;

		if (n && nviews < vcap) {
			spin_lock_irqsave(&n->list_lock, flags);
#ifdef SH_SLAB_PAGE
			{
				struct page *p;

				list_for_each_entry(p, &n->partial, lru) {
					if (nviews >= vcap)
						break;
					sh_slabview_fill(&views[nviews++], p);
				}
			}
#else
			{
				struct list_head *pos = n->partial.next;

				while (pos != &n->partial) {
					if (nviews >= vcap)
						break;
					sh_slabview_fill(&views[nviews++],
							 (char *)pos - SH_SLAB_LIST_OFF);
					pos = pos->next;
				}
			}
#endif
			spin_unlock_irqrestore(&n->list_lock, flags);
		}
	}
#endif

	for_each_online_cpu(cpu) {
		sh_kcpu *c;
		void *cur;

		if (nviews >= vcap)
			break;
		c = sh_cpu_slab(s, cpu);
		if (!c)
			continue;
		cur = sh_cpu_slab_cur(c);
		if (!cur)
			continue;
#ifdef SH_SLAB_PAGE
		if (!PageSlab((struct page *)cur))
			continue;
#endif
		sh_slabview_fill(&views[nviews], cur);
		if (sh_slabview_valid(&views[nviews], csize))
			nviews++;
	}

	for (i = 0; i < nviews; i++) {
		if (!sh_slabview_valid(&views[i], csize))
			continue;
		sh_scan_slab(r, &views[i], s, kind);
		if (r->nr >= r->cap)
			break;
	}
}

/* ================================================================== */
/* report generation (seq_file + printk dual channel)                 */
/* ================================================================== */

/*
 * One format pass into a bounded buffer, then seq_write() (which exists
 * since 2.6.32; seq_vprintf() does not - it arrived much later) plus a
 * kernel-log mirror. All report lines fit comfortably in 320 bytes.
 */
__printf(2, 3)
static void sh_emit(struct seq_file *m, const char *fmt, ...)
{
	va_list ap;
	char buf[320];

	va_start(ap, fmt);
	vscnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (m)
		seq_write(m, buf, strlen(buf));
	pr_info("sock_hunter: %s", buf);
}

/*
 * TCP state names. TCP_NEW_SYN_RECV (12) only exists on >= 4.6; the
 * table is still sized 13 on older kernels, the slot simply stays
 * "UNKNOWN" there.
 */
static const char * const sh_tcp_states[13] = {
	[1] = "ESTABLISHED",	[2] = "SYN_SENT",	[3] = "SYN_RECV",
	[4] = "FIN_WAIT1",	[5] = "FIN_WAIT2",	[6] = "TIME_WAIT",
	[7] = "CLOSE",		[8] = "CLOSE_WAIT",	[9] = "LAST_ACK",
	[10] = "LISTEN",	[11] = "CLOSING",
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
	[12] = "NEW_SYN_RECV",
#endif
};

static const char *sh_tcp_state_name(unsigned int st)
{
	if (st < 13 && sh_tcp_states[st])
		return sh_tcp_states[st];
	return "UNKNOWN";
}

static int sh_show(struct seq_file *m, void *v)
{
	struct sh_result *r = m->private;
	unsigned int i;

	if (!r) {
		seq_puts(m, "sock_hunter: scan failed (out of memory)\n");
		return 0;
	}

	sh_emit(m, "=== sock_hunter v%s report (built for kernel %d.%d.%d) ===\n",
		SH_VERSION,
		(LINUX_VERSION_CODE >> 16) & 0xff,
		(LINUX_VERSION_CODE >> 8) & 0xff,
		LINUX_VERSION_CODE & 0xff);
	sh_emit(m, "data source: passive SLUB cache walk (socket objects in the protocol caches)\n");
	if (!r->kallsyms_ok)
		sh_emit(m, "WARNING: slab_caches symbol unavailable (need CONFIG_KALLSYMS_ALL"
			    " and, on 5.7+, CONFIG_KPROBES); scan skipped\n");
	if (r->nr_caches) {
		char line[200];
		size_t off = 0;

		off = scnprintf(line, sizeof(line), "caches walked:");
		for (i = 0; i < r->nr_caches && off < sizeof(line) - 34; i++)
			off += scnprintf(line + off, sizeof(line) - off, " %s",
					 r->caches[i]);
		sh_emit(m, "%s\n", line);
	} else if (r->kallsyms_ok) {
		sh_emit(m, "caches walked: none matched (no TCP/UDP/RAW caches?)\n");
	}
	sh_emit(m, "slabs scanned: %lu, objects scanned: %lu\n", r->slabs, r->objs);
#ifndef SH_HAVE_IPV6
	sh_emit(m, "IPv6: not compiled in (kernel has no IPv6 support)\n");
#endif
	sh_emit(m, "note: PASSIVE enumeration only - every row is a slab object that looks\n");
	sh_emit(m, "like a live socket; there is no kernel socket list to cross-check. Rows\n");
	sh_emit(m, "NOT shown by netstat/ss are the suspicious ones; confirm by hand.\n");
	sh_emit(m, "%-6s %-41s %-6s %-15s %-18s %s\n",
		"PROTO", "LOCAL-ADDRESS", "PORT", "STATE", "OBJECT", "VERDICT");

	for (i = 0; i < r->nr; i++) {
		const struct sh_sockrec *rec = &r->socks[i];

		sh_emit(m, "%-6s %-41s %-6u %-15s 0x%-16lx %s\n",
			rec->proto, rec->addr, rec->port, rec->state,
			rec->obj, "PASSIVE");
	}

	sh_emit(m, "=== summary: %u socket object(s) found ===\n", r->nr);
	return 0;
}

/*
 * One full collection run, serialized so concurrent opens cannot
 * interleave the dmesg mirror. Returns a vmalloc'ed result (free with
 * vfree()) or NULL on allocation failure.
 */
static struct sh_result *sh_collect(void)
{
	struct sh_result *r;
	struct sh_slabview *views;
	sh_kcache *s;

	mutex_lock(&sh_mutex);
	r = vmalloc(sizeof(*r));
	if (!r)
		goto out;
	memset(r, 0, sizeof(*r));
	r->cap = SH_MAX_SOCKS;
	r->socks = vmalloc(r->cap * sizeof(*r->socks));
	if (!r->socks) {
		vfree(r);
		r = NULL;
		goto out;
	}
	r->kallsyms_ok = sh_lookup_name != NULL;
	if (r->kallsyms_ok)
		r->slab_caches = (struct list_head *)
			sh_lookup_name("slab_caches");
	if (!r->slab_caches)
		r->kallsyms_ok = false;

	views = vmalloc(SH_MAX_SLABS * sizeof(*views));
	if (!views) {
		vfree(r->socks);
		vfree(r);
		r = NULL;
		goto out;
	}

	if (r->slab_caches) {
		list_for_each_entry(s, r->slab_caches, list) {
			int kind;
			unsigned int objsize;

			if (r->nr_caches >= SH_MAX_CACHES ||
			    r->nr >= r->cap)
				break;
			kind = sh_match_cache(s->name);
			if (kind < 0)
				continue;
			objsize = sh_cache_objsize(s);
			if (objsize < sh_kind_min_size(kind))
				continue;
			strscpy_pad(r->caches[r->nr_caches], s->name,
				    sizeof(r->caches[0]));
			r->nr_caches++;
			sh_collect_cache(r, s, kind, views, SH_MAX_SLABS);
		}
	}
	vfree(views);
out:
	mutex_unlock(&sh_mutex);
	return r;
}

/* ================================================================== */
/* /proc/showsocks                                                    */
/* ================================================================== */

static int sh_open(struct inode *inode, struct file *file)
{
	struct seq_file *m;
	int ret;

	ret = single_open(file, sh_show, NULL);
	if (ret)
		return ret;
	m = file->private_data;
	m->private = sh_collect();	/* NULL on allocation failure */
	return 0;
}

static int sh_release(struct inode *inode, struct file *file)
{
	struct seq_file *m = file->private_data;

	if (m) {
		struct sh_result *r = m->private;

		if (r) {
			vfree(r->socks);
			vfree(r);
		}
	}
	return single_release(inode, file);
}

#if ALIRT_HAVE_PROC_OPS
static const struct proc_ops sh_ops = {
	.proc_open	= sh_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= sh_release,
};
#else
static const struct file_operations sh_ops = {
	.open		= sh_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= sh_release,
};
#endif

static struct proc_dir_entry *sh_entry;

static int __init sh_init(void)
{
	int ret;

	pr_info("sock_hunter: ALIRT hidden socket hunter v%s\n", SH_VERSION);
	ret = sh_resolve_kallsyms();
	if (ret)
		pr_warn("sock_hunter: symbol resolution unavailable (%d);"
			" report will be degraded\n", ret);
	sh_entry = proc_create(SH_PROC_NAME, SH_PROC_MODE, NULL, &sh_ops);
	if (!sh_entry) {
		pr_err("sock_hunter: failed to create /proc/%s\n",
		       SH_PROC_NAME);
		return -ENOMEM;
	}
	pr_info("sock_hunter: /proc/%s created (read = full report)\n",
		SH_PROC_NAME);
	return 0;
}

static void __exit sh_exit(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
	proc_remove(sh_entry);
#else
	/* proc_remove() does not exist on 2.6.32 */
	remove_proc_entry(SH_PROC_NAME, NULL);
#endif
	pr_info("sock_hunter: unloaded\n");
}

#else /* !CONFIG_SLUB */

static int __init sh_init(void)
{
	pr_err("sock_hunter: kernel does not use CONFIG_SLUB"
	       " (classic SLAB is not supported), refusing to load\n");
	return -ENODEV;
}

static void __exit sh_exit(void)
{
}

#endif /* CONFIG_SLUB */

module_init(sh_init);
module_exit(sh_exit);

/*
 * MODULE_LICENSE accepts only "GPL" (= v2) in kbuild; the effective
 * licence of this file is GPL-3.0-only as stated in the SPDX tag.
 */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("madsys");
MODULE_DESCRIPTION("ALIRT hidden socket hunter: passive SLUB cache walk "
		   "(TCP/UDP/RAW + IPv6) via /proc/showsocks");
MODULE_VERSION(SH_VERSION);
