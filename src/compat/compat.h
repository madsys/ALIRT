/* SPDX-License-Identifier: GPL-3.0-only */
/*
 * ALIRT — kernel version compatibility layer (compat.h)
 *
 * Centralized adaptation for kernel API differences from 2.6.32 to
 * 6.12 and beyond. All ALIRT modules must include this header;
 * version conditionals must live here, not in module code.
 */
#ifndef ALIRT_COMPAT_H
#define ALIRT_COMPAT_H

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kallsyms.h>

/* ================================================================
 * 1. procfs file-operation interface
 *    2.6.32 ~ 5.5 : struct file_operations
 *    5.6+          : struct proc_ops
 * ================================================================ */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
#  define ALIRT_HAVE_PROC_OPS 1
#endif

/* ================================================================
 * 1b. String copy helper
 *     Kernel 7.2 removed strncpy(); strscpy() exists only since 4.3.
 *     One local implementation keeps every ALIRT module building on
 *     2.6.32 through 7.x without version conditionals.
 * ================================================================ */
static inline ssize_t alirt_strscpy(char *dst, const char *src, size_t size)
{
	size_t len;

	if (!size)
		return 0;
	len = strlen(src);
	if (len >= size)
		len = size - 1;
	memcpy(dst, src, len);
	dst[len] = '\0';
	return (ssize_t)len;
}

/* ================================================================
 * 2. struct module layout
 *    <= 4.4        : module_core / core_size / init_size / module_init
 *    4.5 ~ 6.3     : core_layout.{base,size} / init_layout.{base,size}
 *    6.4+          : mem[MOD_*] array (enum mod_mem_type)
 * ================================================================ */
static inline void *alirt_mod_core_base(const struct module *m)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	return m->mem[MOD_TEXT].base;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)
	return m->core_layout.base;
#else
	return m->module_core;
#endif
}

static inline unsigned long alirt_mod_core_size(const struct module *m)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	return m->mem[MOD_TEXT].size
	     + m->mem[MOD_RODATA].size
	     + m->mem[MOD_DATA].size
	     + m->mem[MOD_RO_AFTER_INIT].size;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)
	return m->core_layout.size;
#else
	return m->core_size;
#endif
}

static inline unsigned long alirt_mod_init_size(const struct module *m)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	return m->mem[MOD_INIT_TEXT].size
	     + m->mem[MOD_INIT_DATA].size
	     + m->mem[MOD_INIT_RODATA].size;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)
	return m->init_layout.size;
#else
	return m->init_size;
#endif
}

/* Base address of the init section (may be NULL; unusable once the
 * init section has been freed) */
static inline void *alirt_mod_init_base(const struct module *m)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	return m->mem[MOD_INIT_TEXT].base;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)
	return m->init_layout.base;
#else
	return m->module_init;
#endif
}

/*
 * module->exit only exists under CONFIG_MODULE_UNLOAD (especially on
 * old kernels — e.g. in 2.6.32's struct module, exit sits inside the
 * CONFIG_MODULE_UNLOAD conditional block); on kernels without module
 * unload support there is no such field, so treat it as NULL.
 */
static inline void *alirt_mod_exit(const struct module *m)
{
#ifdef CONFIG_MODULE_UNLOAD
	return (void *)m->exit;
#else
	return NULL;
#endif
}

/* ================================================================
 * 3. Symbol resolution
 *    kallsyms_lookup_name has not been exported since 5.7.
 *    alirt_resolve_kln() provides a unified entry point to resolve
 *    that very function: on older kernels call it directly; on 5.7+
 *    use the kprobe trick to obtain its address.
 *    Requires CONFIG_KPROBES; returns -ENODEV when unavailable and
 *    the caller must degrade gracefully (report only, no panic).
 *    Modules then use the obtained function pointer to resolve
 *    unexported data symbols such as "modules", "module_kset" and
 *    "slab_caches".
 * ================================================================ */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#  define ALIRT_KALLSYMS_NEEDS_KPROBE 1
#endif

/*
 * Resolve kallsyms_lookup_name itself. Returns 0 and sets *kln on
 * success; returns a negative errno and leaves *kln NULL on failure.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0) && defined(CONFIG_KPROBES)
#  include <linux/kprobes.h>
/* Address only; never actually probes. Note: pre_handler takes (kprobe *,
 * pt_regs *) on every supported version. */
static inline int alirt_kp_pre(struct kprobe *kp, struct pt_regs *regs)
{
	(void)kp;
	(void)regs;
	return 0;
}
#endif

static inline int alirt_resolve_kln(unsigned long (**kln)(const char *name))
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
	/* Every supported pre-5.7 kernel exports it (GPL) */
	*kln = kallsyms_lookup_name;
	return 0;
#elif defined(CONFIG_KPROBES)
	/*
	 * kprobe trick: register a kprobe that is never triggered;
	 * register_kprobe fills the symbol address into kp.addr.
	 */
	struct kprobe kp;
	int ret;

	memset(&kp, 0, sizeof(kp));
	kp.symbol_name = "kallsyms_lookup_name";
	kp.pre_handler = alirt_kp_pre;
	ret = register_kprobe(&kp);
	if (ret < 0)
		return ret;
	*kln = (unsigned long (*)(const char *name))kp.addr;
#if defined(CONFIG_PPC64) && defined(CONFIG_PPC64_ELF_ABI_V2)
	/*
	 * ppc64 ELFv2: kprobe_lookup_name() hands back either the function's
	 * LOCAL entry point (ppc_function_entry() skips the global entry) or,
	 * with CONFIG_KPROBES_ON_FTRACE, the ftrace site - which livepatch.h
	 * guarantees to lie within the first 16 bytes of the function, i.e.
	 * right after the -mprofile-kernel fentry stub.  Calling such an
	 * address directly runs the callee with the *caller's* TOC in r2 (a
	 * module's TOC lives in the module allocation), so the first
	 * TOC-relative load faults - seen in practice as a data-access oops
	 * inside kallsyms code with r2 pointing into the vmalloc area.
	 *
	 * The global entry is the fixed two-instruction prologue
	 *   addis r2,r12,<toc-8+0x8000>@ha   (0x3C4Cxxxx; linker may use
	 *                                     lis r2,  0x3C40xxxx)
	 *   addi  r2,r2,<toc-8>&0xffff       (0x3842xxxx)
	 * exactly as ppc_function_entry() in asm/code-patching.h identifies
	 * it (OP_RT_RA_MASK = 0xffff0000).  kp.addr is GE+8 (local entry)
	 * or at most GE+16 (ftrace site), so a scan window reaching 24
	 * bytes back from kp.addr always covers the prologue.  r12 is loaded
	 * with the target address by the caller-side indirect-call sequence,
	 * so calling the GE re-establishes the kernel TOC on entry.
	 */
	{
		unsigned long a = (unsigned long)*kln & ~3UL;
		unsigned long lo = a >= 24 ? a - 24 : 0;
		unsigned long cand;

		for (cand = lo; cand + 8 <= a + 8; cand += 4) {
			unsigned int i0 = *(unsigned int *)cand;
			unsigned int i1 = *(unsigned int *)(cand + 4);

			if (((i0 & 0xFFFF0000u) == 0x3C4C0000u ||   /* addis r2,r12 */
			     (i0 & 0xFFFF0000u) == 0x3C400000u) &&  /* lis   r2   */
			    (i1 & 0xFFFF0000u) == 0x38440000u)     /* addi  r2,r2 */
				break;
		}
		if (cand + 8 <= a + 8)
			*kln = (unsigned long (*)(const char *name))cand;
		/* else: no match; leave kp.addr as-is (no worse than before) */
	}
#endif
	unregister_kprobe(&kp);
	return *kln ? 0 : -ENOENT;
#else
	return -ENODEV;
#endif
}

/* ================================================================
 * 4. Miscellaneous
 * ================================================================ */

/* The __printf() attribute macro only joined kernel.h in 2.6.33; 2.6.32 lacks it */
#ifndef __printf
#  define __printf(a, b)	__attribute__((format(printf, a, b)))
#endif

/* LIST_POISON values are identical across all supported versions (2.6.32+) */
#ifndef LIST_POISON1
#  define LIST_POISON1  ((void *) 0x00100100)
#  define LIST_POISON2  ((void *) 0x00200200)
#endif

/* Add vma locks / module mutex differences here */

#endif /* ALIRT_COMPAT_H */
