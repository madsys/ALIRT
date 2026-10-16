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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
#  include <linux/fs.h>
#  include <linux/slab.h>
/*
 * Fallback name->addr lookup for kernels where the kprobe trick cannot
 * run at all (CONFIG_KPROBES=n - e.g. riscv 5.10, whose arch Kconfig has
 * no HAVE_KPROBES and therefore cannot enable KPROBES): parse
 * /proc/kallsyms.  Requires the reader to hold CAP_SYSLOG (root) or
 * kptr_restrict zeroes every address; insmod in the runtime test (and
 * forensic practice) runs as root.  Slow - a full table scan per lookup -
 * but only a handful of lookups run at module init, and a zero result
 * degrades every cross-check gracefully.
 */
/*
 * Read wrapper for the parser.  Since 5.9 __kernel_read refuses f_ops
 * exposing only ->read (procfs seq files such as /proc/kallsyms have no
 * ->read_iter), returning -EINVAL via warn_unsupported - so on >= 5.9 the
 * parser silently yields nothing and the caller's kprobe fallback takes
 * over.  A direct ->read fallback with set_fs(KERNEL_DS) is NOT
 * available: by 5.15 no architecture in the test matrix selects
 * CONFIG_SET_FS (arm64/mips/arm dropped it between 5.10 and 5.15; x86_64,
 * riscv and powerpc never had it in the 5.x kvec era), and the remaining
 * arches' access_ok() checks TASK_SIZE unconditionally, so a kernel buffer
 * would fail copy_to_user anyway.
 */
static inline ssize_t alirt_kread(struct file *filp, void *buf, size_t count,
				  loff_t *pos)
{
	return kernel_read(filp, buf, count, pos);
}

static inline unsigned long alirt_ks_lookup(const char *name)
{
	struct file *filp;
	char *tmp, *line;
	unsigned long addr = 0;
	loff_t pos = 0;
	ssize_t n;

	filp = filp_open("/proc/kallsyms", O_RDONLY, 0);
	if (IS_ERR(filp))
		return 0;
	tmp = kmalloc(1024, GFP_KERNEL);
	line = kmalloc(1024, GFP_KERNEL);
	if (!tmp || !line) {
		kfree(tmp);
		kfree(line);
		filp_close(filp, NULL);
		return 0;
	}
	{
		size_t llen = 0;

		while ((n = alirt_kread(filp, tmp, 1024, &pos)) > 0) {
			ssize_t i;

			for (i = 0; i < n; i++) {
				if (tmp[i] == '\n') {
					unsigned long a;
					char type;
					char nm[512];

					line[llen] = '\0';
					if (sscanf(line, "%lx %c %511s",
						   &a, &type, nm) == 3 &&
					    strcmp(nm, name) == 0) {
						addr = a;
						goto out;
					}
					llen = 0;
				} else if (llen < 1023) {
					line[llen++] = tmp[i];
				} else {
					llen = 0; /* oversized line: drop */
				}
			}
		}
	}
out:
	kfree(tmp);
	kfree(line);
	filp_close(filp, NULL);
	return addr;
}

/*
 * kallsyms_lookup_name-compatible wrapper for the parser path.
 *
 * "module_kset" (the 'struct kset *' variable in kernel/module main.c)
 * never needs the symbol table at all: every loaded module's kobject is
 * registered in that kset, so our own module carries a live pointer to
 * the kset VALUE.  Callers resolve the variable (to dereference it
 * once), so the value is parked in a module-local shadow and the
 * shadow's ADDRESS is returned instead.  This keeps the module-kset
 * cross-check alive on kernels where the parser is the only lookup:
 * riscv 5.10 has no HAVE_KPROBES, no exported kallsyms_lookup_name,
 * and since 5.9 __kernel_read refuses to open /proc/kallsyms - three
 * independent dead ends for every other name, but not for this one.
 */
static struct kset *alirt_module_kset_shadow;

static inline unsigned long alirt_kln_lookup(const char *name)
{
#if defined(CONFIG_MODULES)
	if (!strcmp(name, "module_kset") && THIS_MODULE->mkobj.kobj.kset) {
		alirt_module_kset_shadow = THIS_MODULE->mkobj.kobj.kset;
		return (unsigned long)&alirt_module_kset_shadow;
	}
	/*
	 * "modules" shadow: the frozen caller casts the return value to
	 * struct list_head * and walks from it.  When THIS_MODULE is the
	 * only entry left on the module list (hide_self has already
	 * list_del()ed itself before mod_hunter loads), its list.next IS
	 * the address of the (file-local, never exported) "modules" head
	 * in kernel/module*.c - the shadow returns that head directly, no
	 * dereference needed.  This is the only way to obtain the head on
	 * ppc64 >= 5.7, where the address also fails the caller's
	 * canonical-pointer gate (0xc0.. is neither 48- nor 57-bit
	 * sign-extended), so the module_kset shadow above cannot feed the
	 * kset cross-check there; the list cross-check stays alive via
	 * this shadow and yields HIGH (missing-from-list) verdicts.
	 * Guard against an unlinked THIS_MODULE (next == prev == &self)
	 * so a corner-case caller never gets our own list node as "head".
	 */
	if (!strcmp(name, "modules") &&
	    THIS_MODULE->list.next == THIS_MODULE->list.prev &&
	    THIS_MODULE->list.next != &THIS_MODULE->list)
		return (unsigned long)THIS_MODULE->list.next;
#endif
	return alirt_ks_lookup(name);
}
#endif /* >= 5.7 */

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
#else
/*
 * ppc64 ELFv2, 5.7 <= version < 6.1: skip the kprobe path entirely.
 * CONFIG_PPC64_ELF_ABI_V2 only exists since 6.1, so the era-correct
 * ELFv2 test below is CPU_LITTLE_ENDIAN (every LE ppc64 build is ELFv2;
 * big-endian was ELFv1 until the explicit 6.1 choice arrived, and CI
 * builds LE exclusively via build-kernel.sh).
 *
 * Why only pre-6.1: on 6.1+ the kprobe path below plus the global-entry
 * scan demonstrably resolves a callable kallsyms_lookup_name (matrix
 * green since v0.6.0), but on 5.10.271/5.15.180 kp.addr resolves an
 * address that is not safe to CALL from a module (observed oops inside
 * kallsyms_lookup_name at +0x44/+0x30, module TOC still in r2: with
 * KPROBES_ON_FTRACE kp.addr can be the ftrace site and the GE scan
 * finds no callable prologue).  The parser-wrapper below never calls
 * kernel text; its gaps on this path are closed arch-side: the module
 * list head reaches the caller through the "modules" shadow in
 * alirt_kln_lookup(), and init_mm through init_task.active_mm (see
 * src/arch/powerpc/alirt_mm.h).
 */
#if defined(CONFIG_PPC64) && defined(CONFIG_CPU_LITTLE_ENDIAN) && \
	LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	*kln = alirt_kln_lookup;
	return 0;
#endif
	/*
	 * >= 5.7 (non-ppc64, or ppc64 >= 6.1): prefer the /proc/kallsyms
	 * parser whenever it works.  The parser needs nothing but the
	 * symbol table, which is intact when root inserts the module.
	 * Pre-6.1 ppc64 never reaches this point (skipped above).
	 */
	if (alirt_ks_lookup("kallsyms_lookup_name")) {
		*kln = alirt_kln_lookup;
		return 0;
	}
#if defined(CONFIG_KPROBES)
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
	 * ppc64 ELFv2: kprobe_lookup_name() (arch/powerpc/kernel/kprobes.c)
	 * hands back any of three values:
	 *   - the LOCAL entry point  (ppc_function_entry() skipping the GE),
	 *   - the ftrace site        (with CONFIG_KPROBES_ON_FTRACE; the
	 *     ftrace location of the -mprofile-kernel stub, which can sit
	 *     BEFORE the TOC-setup prologue), or
	 *   - the GLOBAL entry itself.
	 * Calling any address that is not the global-entry prologue runs the
	 * callee with the *caller's* TOC in r2 (a module's TOC lives in the
	 * module allocation), so the first TOC-relative load dereferences
	 * garbage - seen in practice as a data-access oops inside kallsyms
	 * code (kallsyms_lookup_name+0x30, DAR in the vmalloc range).
	 *
	 * The global entry is the fixed two-instruction prologue
	 *   addis r2,r12,<toc-8+0x8000>@ha   (0x3C4Cxxxx; linker may use
	 *                                     lis r2,  0x3C40xxxx)
	 *   addi  r2,r2,<toc-8>&0xffff       (0x3842xxxx)
	 * exactly as ppc_function_entry() in asm/code-patching.h identifies
	 * it (OP_RT_RA_MASK = 0xffff0000).  It is self-relative to r12 (the
	 * indirect-call sequence loads r12 with the target address), so the
	 * prologue instruction pair is itself a valid entry point wherever it
	 * sits.  Scan BOTH directions around kp.addr: backward covers the
	 * local-entry case (prologue at kp.addr-8), forward covers the ftrace
	 * site inside the fentry stub (prologue after the stub, up to 56
	 * bytes ahead).  Backward matches win; when nothing matches, refuse
	 * to call the unresolved address instead of crashing the machine.
	 */
	{
		unsigned long a = (unsigned long)*kln & ~3UL;
		unsigned long lo = a >= 32 ? a - 32 : 0;
		unsigned long ge = 0;
		long cand;

		for (cand = (long)a; cand >= (long)lo; cand -= 4) {
			unsigned int i0 = *(unsigned int *)cand;
			unsigned int i1 = *(unsigned int *)(cand + 4);

			if (((i0 & 0xFFFF0000u) == 0x3C4C0000u ||   /* addis r2,r12 */
			     (i0 & 0xFFFF0000u) == 0x3C400000u) &&  /* lis   r2   */
			    (i1 & 0xFFFF0000u) == 0x38420000u) {  /* addi  r2,r2 */
				ge = (unsigned long)cand;
				break;
			}
		}
		if (!ge) {
			for (cand = (long)a + 4; cand <= (long)a + 56; cand += 4) {
				unsigned int i0 = *(unsigned int *)cand;
				unsigned int i1 = *(unsigned int *)(cand + 4);

				if (((i0 & 0xFFFF0000u) == 0x3C4C0000u ||
				     (i0 & 0xFFFF0000u) == 0x3C400000u) &&
				    (i1 & 0xFFFF0000u) == 0x38420000u) {
					ge = (unsigned long)cand;
					break;
				}
			}
		}
		if (ge) {
			*kln = (unsigned long (*)(const char *name))ge;
		} else {
			/* No match: never call the unverified kp.addr (that is
			 * the crash this scan exists to prevent).  *kln is
			 * cleared here; the caller-visible fallback to the
			 * /proc/kallsyms parser happens after unregister.
			 * Log the surrounding words - toolchains occasionally
			 * emit a different global-entry shape, and the exact
			 * bytes decide what the scan must accept next. */
			char buf[160];
			int n, j;

			*kln = NULL;
			n = scnprintf(buf, sizeof(buf),
				      "alirt: ppc64 GE scan: no entry prologue near %px; words:",
				      (void *)a);
			for (j = -16; j <= 32 && n < (int)sizeof(buf) - 10; j += 4)
				n += scnprintf(buf + n, sizeof(buf) - n, " %08x",
					       *(unsigned int *)(a + j));
			pr_warn("%s\n", buf);
		}
	}
#endif
	unregister_kprobe(&kp);
	/*
	 * kprobe path ran but no usable entry point came out of it (or the
	 * ppc64 prologue scan failed): fall back to the /proc/kallsyms
	 * parser rather than leaving the caller without any lookup.  When
	 * even that is unavailable (no root), *kln stays NULL and the
	 * caller degrades.
	 */
	if (!*kln)
		*kln = alirt_kln_lookup;
	return 0;
#else
	/* No KPROBES at all (e.g. riscv 5.10): /proc/kallsyms parser. */
	*kln = alirt_kln_lookup;
	return 0;
#endif
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
