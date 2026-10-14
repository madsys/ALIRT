// SPDX-License-Identifier: GPL-3.0-only
/*
 * mod_hunter.c - ALIRT hidden kernel module hunter (v0.5.1)
 *
 * Brute-force scanner for struct module objects in the module mapping
 * space, with three-way cross-validation against the kernel's own
 * bookkeeping (module list + module kset), seq_file based reporting
 * through /proc/showmodules and a modernised "reveal" write path.
 *
 * Acknowledgements / lineage:
 *   - madsys, "Finding hidden kernel modules (the extrem way)",
 *     Phrack 61-3 (2005). The original mod_hunter idea: walk the
 *     whole module mapping space and recognise struct module objects
 *     heuristically, so that neither list_unlink() nor kset scrubbing
 *     can hide a module from the scan.
 *     http://phrack.org/issues/61/3.html
 *   - g1inko / ksen-lin, nitara2, Phrack 71 (2024). The modern x86_64
 *     re-implementation (kernel 4.4 - 6.5) that the scanning engine in
 *     this file is merged from: page-table based address validation,
 *     struct module heuristics and the 0x10 scan step.
 *     https://github.com/ksen-lin/nitara2
 *
 * New in this ALIRT version (on top of the merged engine):
 *   - three-way cross-validation (brute scan vs. "modules" list vs.
 *     module kset) with CRITICAL / HIGH / MEDIUM / VISIBLE verdicts,
 *     aimed at rootkits of the KoviD class that unlink from the list,
 *     scrub sysfs kobjects, or wipe list pointers in-place;
 *   - /proc/showmodules is now a seq_file: the full report reaches
 *     userland through copy_to_user and cannot be suppressed by a
 *     rootkit that hijacks printk / dmesg. Everything is additionally
 *     mirrored to the kernel log for legacy pipelines;
 *   - "reveal" (echo 0x<addr> > /proc/showmodules): on < 4.0 kernels an
 *     opt-in (module parameter reveal=1) legacy re-link into the module
 *     list is kept, on >= 4.0 kernels the write path is analysis-only
 *     and defers the recovery decision to the analyst (dump with the
 *     ALIRT modumper tool and decide by hand);
 *   - compatibility layer compat.h + arch layer alirt_mm.h covering
 *     Linux 2.6.32 - 6.12+ on x86_64.  "modules" / "module_kset" are
 *     resolved through kallsyms at load (neither is exported), with
 *     graceful degradation of the cross-check when they are missing
 *     from the symbol table.
 *
 * Supported: x86_64, Linux 2.6.32 - 6.12+. Any other combination
 * fails module load with -ENODEV, never panics.
 *
 * Copyright (C) 2005 madsys, 2024 g1inko (ksen-lin), 2025 ALIRT
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/stat.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/kobject.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/version.h>

#include "compat.h"

#if defined(CONFIG_X86_64)
#include "alirt_mm.h"
#define MH_HAVE_MODULE_SPACE 1
#endif

#define MH_VERSION		"0.5.1"

#define MH_PROC_NAME		"showmodules"	/* keep the original name */
#define MH_PROC_MODE		(S_IRUSR | S_IWUSR)

#define MH_SCAN_STEP		0x10UL
#define MH_MAX_FINDINGS		512
/*
 * Hard upper bound for the scan loop. The x86_64 module space needs
 * (MODULES_END - MODULES_VADDR) / MH_SCAN_STEP ~= 99M steps; the cap is
 * a pure safety net against a corrupted address range, not a limiter.
 */
#define MH_SCAN_HARD_CAP	0x08000000UL
/*
 * Reject absurd core_size values.  module core images are allocated with
 * module_alloc() and are at most a few megabytes in practice; the bound
 * exists purely as a sanity filter for the brute-force scan.
 * NOTE: core_size is only page-aligned when the kernel was built with
 * CONFIG_DEBUG_SET_MODULE_RONX (3.x-4.16; renamed CONFIG_STRICT_MODULE_RWX
 * in 4.17, x86 default y).  With RONX off, layout.size is the plain sum
 * of the module sections (see debug_align() in kernel/module.c) and is
 * NOT page aligned (e.g. 0x2a3b0) — so we must not require page-aligned
 * sizes here; core alignment is validated via the base pointer instead.
 */
#define MH_MAX_CORE_SIZE	(64UL << 20)

static int reveal;
module_param(reveal, int, 0644);
MODULE_PARM_DESC(reveal,
	"enable legacy module re-link on < 4.0 kernels (dangerous, default 0)");

/*
 * Cross-validation data symbols.  Neither "modules" nor "module_kset"
 * is usable via a plain extern:
 *   - "modules" is file-local in kernel/module.c on every kernel
 *     (static LIST_HEAD up to at least 4.4, still unexported in 6.1)
 *     and is NOT declared in linux/module.h on any version;
 *   - "module_kset" is declared in linux/module.h but is not exported
 *     either on the kernels we must support.
 * Both are therefore resolved through kallsyms at init.  Note the
 * crucial difference in kind:
 *   - "modules" is the list head itself, so the kallsyms address is
 *     used directly;
 *   - "module_kset" is a 'struct kset *' POINTER VARIABLE (defined in
 *     kernel/params.c on every version from 2.6.32 through 6.12), so
 *     the kallsyms address must be dereferenced once to obtain the
 *     kset itself.  The shape of the resulting pointer is validated;
 *     on failure the kset cross-check degrades to "unavailable" and
 *     the report says so.
 * On kernels where they are absent from the symbol table
 * (CONFIG_KALLSYMS_ALL off matters for old, static "modules") the
 * affected cross-check degrades to "unavailable"; the brute-force scan,
 * the primary data source, never depends on them.
 */
static struct list_head *mh_modules;
static struct kset *mh_module_kset;
static unsigned long (*mh_kln)(const char *name);

/*
 * MODULE_STATE_UNFORMED only exists since 3.8 (module loader rework;
 * verified against include/linux/module.h v2.6.33..v3.8 — 3.7 still
 * has only LIVE/COMING/GOING).
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
#define MH_MAX_MODULE_STATE	MODULE_STATE_UNFORMED
#else
#define MH_MAX_MODULE_STATE	MODULE_STATE_GOING
#endif

#ifdef MH_HAVE_MODULE_SPACE

/* ------------------------------------------------------------------ */
/* canonical-address helpers (nitara2 lineage; 4- and 5-level paging)  */
/* ------------------------------------------------------------------ */

static __always_inline u64 mh_sext(u64 addr, u8 bits)
{
	return ((s64)addr << (64 - bits)) >> (64 - bits);
}

/*
 * A pointer is accepted when it is NULL, points into the vmalloc/module
 * area, and is canonical under either 48-bit (4-level) or 57-bit
 * (5-level) paging. Every 48-bit-canonical kernel pointer is also
 * 57-bit-canonical, so checking both covers kernels built for either
 * paging mode without needing to know which one is active.
 */
static bool mh_ptr_high_or_zero(const void *p)
{
	unsigned long a = (unsigned long)p;

	if (!p)
		return true;
	if (a < VMALLOC_START)
		return false;
	return mh_sext(a, 48) == a || mh_sext(a, 57) == a;
}

/*
 * Weaker shape check for data symbols that live in kmalloc memory
 * (direct map), below VMALLOC_START — e.g. the kset created by
 * kset_create_and_add() for "module".  Such pointers fail
 * mh_ptr_high_or_zero() by design, so this variant only requires the
 * address to be canonical under either paging mode (or NULL).
 */
static bool mh_ptr_canonical_or_zero(const void *p)
{
	unsigned long a = (unsigned long)p;

	if (!p)
		return true;
	return mh_sext(a, 48) == a || mh_sext(a, 57) == a;
}

static bool mh_modspace_or_zero(const void *p)
{
	return !p || alirt_is_module_space(p);
}

/* ------------------------------------------------------------------ */
/* struct module heuristics (merged from nitara2)                      */
/* ------------------------------------------------------------------ */

static bool mh_name_valid(const char *name)
{
	size_t i;

	if (!name)
		return false;
	for (i = 0; i < MODULE_NAME_LEN; i++) {
		if (name[i] == '\0')
			return i != 0;	/* reject "" */
		if (name[i] < 0x20 || name[i] > 0x7e)
			return false;
	}
	/* full-length name without NUL terminator: accept, bounded copy */
	return true;
}

/*
 * Heuristic struct module recognition, same rules as nitara2:
 *   - state within [MODULE_STATE_LIVE, MODULE_STATE_UNFORMED]
 *   - printable, non-empty name
 *   - init/exit point into the module space or are NULL
 *   - at least one of init/exit/list.next/list.prev is set
 *   - list pointers are vmalloc-canonical (or zero) or LIST_POISON
 *   - core size sane (non-zero, not above MH_MAX_CORE_SIZE) and the
 *     core base page aligned (module_alloc() always returns page-aligned
 *     memory; the SIZE is deliberately not page-alignment-checked, see
 *     MH_MAX_CORE_SIZE above)
 * with the core size taken from the compat layer (module_core /
 * core_layout.size / mem[MOD_*] depending on kernel version).
 */
static bool mh_looks_like_module(const struct module *mod)
{
	unsigned long core_size;

	if (mod->state < MODULE_STATE_LIVE || mod->state > MH_MAX_MODULE_STATE)
		return false;
	if (!mh_name_valid(mod->name))
		return false;
	if (!mh_modspace_or_zero((void *)mod->init) ||
	    !mh_modspace_or_zero(alirt_mod_exit(mod)))
		return false;
	if (!mod->init && !mod->exit && !mod->list.next && !mod->list.prev)
		return false;
	if (!mh_ptr_high_or_zero(mod->list.next) &&
	    mod->list.next != LIST_POISON1)
		return false;
	if (!mh_ptr_high_or_zero(mod->list.prev) &&
	    mod->list.prev != LIST_POISON2)
		return false;
	if ((unsigned long)alirt_mod_core_base(mod) % PAGE_SIZE)
		return false;
	core_size = alirt_mod_core_size(mod);
	if (!core_size || core_size > MH_MAX_CORE_SIZE)
		return false;
	return true;
}

/* ------------------------------------------------------------------ */
/* finding storage                                                     */
/* ------------------------------------------------------------------ */

struct mh_finding {
	unsigned long	addr;
	unsigned long	core_base;
	unsigned long	core_size;
	unsigned long	init_size;
	int		state;
	bool		in_list;
	bool		in_kset;
	bool		list_ptrs_wiped;	/* LIST_POISON/next/prev zeroed */
	char		name[MODULE_NAME_LEN];
};

struct mh_result {
	struct mh_finding	f[MH_MAX_FINDINGS];
	unsigned int		nr;
	unsigned long		steps;
	bool			list_ok;	/* "modules" resolved */
	bool			kset_ok;	/* "module_kset" resolved */
};

/* ------------------------------------------------------------------ */
/* data source 2: the global module list ("modules")                   */
/* ------------------------------------------------------------------ */

/*
 * Walk the module list under RCU. module_mutex is not exported, so RCU
 * is the only portable protection; try_module_get() additionally pins
 * each module so its memory cannot be freed (or its name torn) while
 * we compare, and naturally skips modules that are going away.
 */
static bool mh_find_in_list(const char *name)
{
	struct module *mod;
	bool found = false;

	if (!mh_modules)
		return false;	/* symbol not resolvable: degraded */

	rcu_read_lock();
	list_for_each_entry_rcu(mod, mh_modules, list) {
		if (!try_module_get(mod))
			continue;
		if (!strcmp(mod->name, name))
			found = true;
		module_put(mod);
		if (found)
			break;
	}
	rcu_read_unlock();
	return found;
}

/* ------------------------------------------------------------------ */
/* data source 3: the module kset ("/sys/module/<name>")               */
/* ------------------------------------------------------------------ */

/*
 * Walk kset->list. A kset has no public iterator (unlike klist) but
 * struct kset embeds its own list_lock, so we take that brief spinlock
 * instead of RCU: kobject lifetime on this list is tied to the kset
 * lock in the sysfs code, which makes this the safest portable choice.
 * Names are compared with kobject_name(); we deliberately do NOT rely
 * on the un-exported module_ktype for container_of conversion.
 */
static bool mh_find_in_kset(const char *name)
{
	struct kobject *kobj;
	bool found = false;

	if (!mh_module_kset)
		return false;

	spin_lock(&mh_module_kset->list_lock);
	list_for_each_entry(kobj, &mh_module_kset->list, entry) {
		const char *kname = kobject_name(kobj);

		if (kname && !strcmp(kname, name)) {
			found = true;
			break;
		}
	}
	spin_unlock(&mh_module_kset->list_lock);
	return found;
}

/* ------------------------------------------------------------------ */
/* data source 1: brute-force scan of the module mapping space         */
/* ------------------------------------------------------------------ */

static void mh_scan(struct mh_result *r)
{
	unsigned long start = alirt_modules_start();
	unsigned long end = alirt_modules_end();
	unsigned long addr;
	unsigned long steps = 0;

	for (addr = start; addr + sizeof(struct module) <= end;
	     addr += MH_SCAN_STEP) {
		struct module *mod = (struct module *)addr;
		struct mh_finding *f;

		if (unlikely(++steps > MH_SCAN_HARD_CAP)) {
			pr_warn("mod_hunter: scan hard cap reached, aborting\n");
			break;
		}

		/* never dereference anything the page tables don't cover */
		if (!alirt_addr_valid(addr, sizeof(*mod)))
			continue;
		if (!mh_looks_like_module(mod))
			continue;

		if (r->nr >= MH_MAX_FINDINGS) {
			pr_warn("mod_hunter: finding table full (%u entries), further hits skipped\n",
				MH_MAX_FINDINGS);
			break;
		}

		f = &r->f[r->nr++];
		f->addr = addr;
		f->core_base = (unsigned long)alirt_mod_core_base(mod);
		f->core_size = alirt_mod_core_size(mod);
		f->init_size = alirt_mod_init_size(mod);
		f->state = mod->state;
		/* struct looks valid but its list pointers were zeroed
		 * instead of poisoned: classic in-place hiding marker */
		f->list_ptrs_wiped = !mod->list.next || !mod->list.prev;
		strncpy(f->name, mod->name, sizeof(f->name) - 1);
		f->name[sizeof(f->name) - 1] = '\0';
	}
	r->steps = steps;
}

static void mh_crosscheck(struct mh_result *r)
{
	unsigned int i;

	r->list_ok = mh_modules != NULL;
	r->kset_ok = mh_module_kset != NULL;

	for (i = 0; i < r->nr; i++) {
		struct mh_finding *f = &r->f[i];

		f->in_list = mh_find_in_list(f->name);
		f->in_kset = mh_find_in_kset(f->name);
	}
}

/* ------------------------------------------------------------------ */
/* report generation (seq_file + printk dual channel)                  */
/* ------------------------------------------------------------------ */

static DEFINE_MUTEX(mh_mutex);

/*
 * One scan + cross-check run. Serialized by mh_mutex so concurrent
 * opens cannot interleave the dmesg mirror. Returns a vmalloc'ed
 * result (free with vfree()) or NULL on allocation failure.
 */
static struct mh_result *mh_collect(void)
{
	struct mh_result *r;

	mutex_lock(&mh_mutex);
	r = vmalloc(sizeof(*r));
	if (!r)
		goto out;
	memset(r, 0, sizeof(*r));
	mh_scan(r);
	mh_crosscheck(r);
out:
	mutex_unlock(&mh_mutex);
	return r;
}

/*
 * Emit one report line: format once into a bounded buffer, then push
 * it to the seq_file with seq_write() (available and exported since
 * 2.6.32; seq_vprintf() only appeared much later, so it must not be
 * used here) and mirror it to the kernel log for legacy pipelines.
 */
__printf(2, 3)
static void mh_emit(struct seq_file *m, const char *fmt, ...)
{
	va_list ap;
	char buf[320];

	va_start(ap, fmt);
	vscnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (m)
		seq_write(m, buf, strlen(buf));
	pr_info("mod_hunter: %s", buf);
}

/*
 * Verdict matrix (group index):
 *   0 CRITICAL  scan + not in list + not in kset (hidden from every
 *               kernel bookkeeping source; most likely KoviD-class)
 *   1 HIGH      scan + not in list + in kset (classic list_unlink)
 *   2 MEDIUM    scan + in list + not in kset (sysfs scrubbed)
 *   3 VISIBLE   scan + in list + in kset
 *   4 UNVERIFIED neither bookkeeping source was resolvable; the
 *               verdict is a guess from whatever source remained
 * "list_ptrs_wiped" adds a SUSPICIOUS side note on top of any verdict.
 */
static int mh_verdict_group(const struct mh_finding *f, bool list_ok,
			    bool kset_ok)
{
	if (!list_ok && !kset_ok)
		return 4;
	if (!list_ok)
		return f->in_kset ? 1 : 0;
	if (!kset_ok)
		return f->in_list ? 2 : 0;
	if (!f->in_list && !f->in_kset)
		return 0;
	if (!f->in_list)
		return 1;
	if (!f->in_kset)
		return 2;
	return 3;
}

static const char * const mh_verdict_names[] = {
	"CRITICAL", "HIGH", "MEDIUM", "VISIBLE", "UNVERIFIED"
};

static int mh_show(struct seq_file *m, void *v)
{
	struct mh_result *r = m->private;
	unsigned int i;
	unsigned int n_visible = 0, n_medium = 0, n_high = 0, n_critical = 0;
	unsigned int n_unverified = 0;

	if (!r) {
		seq_puts(m, "mod_hunter: scan failed (out of memory)\n");
		return 0;
	}

	mh_emit(m, "=== mod_hunter v%s report (built for kernel %d.%d.%d) ===\n",
		MH_VERSION,
		(LINUX_VERSION_CODE >> 16) & 0xff,
		(LINUX_VERSION_CODE >> 8) & 0xff,
		LINUX_VERSION_CODE & 0xff);
	mh_emit(m, "scanned module space [0x%lx, 0x%lx) step=0x%lx: %lu steps, %u candidate(s)\n",
		alirt_modules_start(), alirt_modules_end(),
		MH_SCAN_STEP, r->steps, r->nr);
	mh_emit(m, "verdicts: CRITICAL=hidden from list+kset HIGH=missing from list MEDIUM=missing from kset\n");
	if (!r->list_ok || !r->kset_ok)
		mh_emit(m, "note: cross-check degraded: %s%s unavailable via kallsyms; "
			    "verdicts based on the remaining source(s) only\n",
			r->list_ok ? "" : "module list",
			r->kset_ok ? "" : (r->list_ok ? "module kset" : " + module kset"));

	for (i = 0; i < r->nr; i++) {
		const struct mh_finding *f = &r->f[i];
		const int group = mh_verdict_group(f, r->list_ok, r->kset_ok);

		switch (group) {
		case 0:	n_critical++; break;
		case 1:	n_high++; break;
		case 2:	n_medium++; break;
		case 3:	n_visible++; break;
		default: n_unverified++; break;
		}

		mh_emit(m,
			"[%s] addr=0x%px name=%-32s core=0x%px size=0x%lx init_size=0x%lx state=%d list=%d kset=%d%s\n",
			mh_verdict_names[group], (void *)f->addr, f->name,
			(void *)f->core_base, f->core_size, f->init_size,
			f->state, f->in_list, f->in_kset,
			f->list_ptrs_wiped ? " SUSPICIOUS(list pointers wiped)" : "");
	}

	mh_emit(m, "=== summary: %u visible, %u medium, %u high, %u critical, %u unverified ===\n",
		n_visible, n_medium, n_high, n_critical, n_unverified);
	return 0;
}

static int mh_open(struct inode *inode, struct file *file)
{
	struct seq_file *m;
	int ret;

	ret = single_open(file, mh_show, NULL);
	if (ret)
		return ret;
	m = file->private_data;
	m->private = mh_collect();	/* NULL on allocation failure */
	return 0;
}

static int mh_release(struct inode *inode, struct file *file)
{
	struct seq_file *m = file->private_data;

	if (m)
		vfree(m->private);
	return single_release(inode, file);
}

/* ------------------------------------------------------------------ */
/* reveal: echo "0x<address>" > /proc/showmodules                      */
/* ------------------------------------------------------------------ */

/*
 * Print the full record of the module at @mod and decide on recovery.
 * Called with mh_mutex held.
 */
static void mh_reveal(struct module *mod)
{
	bool in_list = mh_find_in_list(mod->name);
	bool in_kset = mh_find_in_kset(mod->name);

	pr_info("mod_hunter: reveal request for struct module at 0x%px\n", mod);
	pr_info("mod_hunter:   name=%s core_base=0x%px core_size=0x%lx init_size=0x%lx state=%d\n",
		mod->name, alirt_mod_core_base(mod),
		alirt_mod_core_size(mod), alirt_mod_init_size(mod), mod->state);
	pr_info("mod_hunter:   data sources: list=%d kset=%d\n", in_list, in_kset);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
	if (!reveal) {
		pr_info("mod_hunter: reveal=1 required for re-link on this kernel; analysis only\n");
		return;
	}
	if (!mh_modules) {
		pr_warn("mod_hunter: 'modules' list not resolvable, cannot re-link\n");
		return;
	}
	if (in_list) {
		pr_warn("mod_hunter: module '%s' is already linked, skipping re-link\n",
			mod->name);
		return;
	}
	/*
	 * Legacy recovery: put the module back on the global module list
	 * so stock tools (lsmod, /proc/modules) see it again.
	 *
	 * RISK, read before enabling reveal=1: module_mutex is not
	 * exported, so this cannot be serialized against concurrent
	 * module load/unload; a racing request_module() or rmmod can
	 * corrupt the list. This exists only to preserve the original
	 * 2005 mod_hunter behaviour on ancient kernels and should be
	 * used in a controlled lab only.
	 */
	if (mod->list.next == NULL || mod->list.prev == NULL ||
	    mod->list.next == LIST_POISON1 ||
	    mod->list.prev == LIST_POISON2) {
		INIT_LIST_HEAD(&mod->list);
		list_add_rcu(&mod->list, mh_modules);
		pr_warn("mod_hunter: re-linked '%s' into the module list (legacy reveal, racing by design)\n",
			mod->name);
	} else {
		pr_warn("mod_hunter: list pointers of '%s' look live, refusing to re-link\n",
			mod->name);
	}
#else
	/*
	 * Modern kernels: deliberately no re-link. Faking kernel
	 * bookkeeping back into place destroys evidence and can crash a
	 * kernel that has already freed part of the module. Dump it with
	 * the ALIRT modumper tool and let the analyst decide.
	 */
	pr_info("mod_hunter: no re-link performed on >= 4.0 kernels; dump with ALIRT modumper and decide on recovery manually\n");
#endif
}

static ssize_t mh_write(struct file *file, const char __user *ubuf,
			size_t count, loff_t *ppos)
{
	char buf[24];
	unsigned long addr;
	size_t len;
	struct module *mod;

	if (!count || count >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;
	buf[count] = '\0';

	/* strip the newline/whitespace echo appends */
	len = strnlen(buf, sizeof(buf));
	while (len && (buf[len - 1] == '\n' || buf[len - 1] == '\r' ||
		       buf[len - 1] == ' ' || buf[len - 1] == '\t'))
		buf[--len] = '\0';
	if (!len)
		return -EINVAL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
	if (kstrtoul(buf, 0, &addr))
		return -EINVAL;
#else
	/* kstrtoul() does not exist on 2.6.32; simple_strtoul tolerates
	 * a 0x prefix when the base is 0 */
	{
		char *endp;

		addr = simple_strtoul(buf, &endp, 0);
		if (endp == buf)
			return -EINVAL;
	}
#endif

	if (!alirt_is_module_space((void *)addr))
		return -EINVAL;

	/*
	 * Validate before and immediately before dereferencing: an
	 * attacker racing us could unmap the page in between. Anything
	 * failing here is reported as -EFAULT (bad address).
	 */
	if (!alirt_addr_valid(addr, sizeof(*mod)))
		return -EFAULT;
	if (!alirt_addr_valid(addr, PAGE_SIZE))
		return -EFAULT;

	mod = (struct module *)addr;
	if (!mh_looks_like_module(mod))
		return -EINVAL;

	mutex_lock(&mh_mutex);
	mh_reveal(mod);
	mutex_unlock(&mh_mutex);

	return count;
}

/* ------------------------------------------------------------------ */
/* procfs registration                                                 */
/* ------------------------------------------------------------------ */

#if ALIRT_HAVE_PROC_OPS
static const struct proc_ops mh_ops = {
	.proc_open	= mh_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= mh_release,
	.proc_write	= mh_write,
};
#else
static const struct file_operations mh_ops = {
	.open		= mh_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= mh_release,
	.write		= mh_write,
};
#endif

static struct proc_dir_entry *mh_entry;

static int __init mh_init(void)
{
	int ret;

	pr_info("mod_hunter: ALIRT hidden kernel module hunter v%s\n",
		MH_VERSION);

	ret = alirt_resolve_kln(&mh_kln);
	if (ret) {
		pr_warn("mod_hunter: kallsyms_lookup_name not resolvable (%d); "
			"list/kset cross-check disabled\n", ret);
	} else {
		mh_modules = (struct list_head *)mh_kln("modules");
		/*
		 * "module_kset" is a 'struct kset *' variable, not the
		 * kset itself: dereference the kallsyms address once and
		 * validate the pointer shape before trusting it.
		 */
		{
			unsigned long ka = mh_kln("module_kset");
			struct kset *ks = ka ? *(struct kset **)ka : NULL;

			if (ks && mh_ptr_canonical_or_zero(ks))
				mh_module_kset = ks;
		}
		if (!mh_modules)
			pr_warn("mod_hunter: 'modules' not in kallsyms "
				"(CONFIG_KALLSYMS_ALL off on old kernels?); "
				"list cross-check disabled\n");
		if (!mh_module_kset)
			pr_warn("mod_hunter: 'module_kset' not in kallsyms "
				"or pointer invalid; kset cross-check disabled\n");
		/* init_mm is not exported on any supported kernel; resolve
		 * it here or alirt_addr_valid() degrades to always-false
		 * (see alirt_mm.h). */
		if (alirt_mm_init(mh_kln))
			pr_warn("mod_hunter: init_mm not in kallsyms "
				"(need CONFIG_KALLSYMS_ALL); address "
				"validation disabled\n");
	}

	mh_entry = proc_create(MH_PROC_NAME, MH_PROC_MODE, NULL, &mh_ops);
	if (!mh_entry) {
		pr_err("mod_hunter: failed to create /proc/%s\n",
		       MH_PROC_NAME);
		return -ENOMEM;
	}
	pr_info("mod_hunter: /proc/%s created (read = full report, write = reveal)\n",
		MH_PROC_NAME);
	return 0;
}

static void __exit mh_exit(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
	proc_remove(mh_entry);
#else
	/* proc_remove() does not exist on 2.6.32 */
	remove_proc_entry(MH_PROC_NAME, NULL);
#endif
	pr_info("mod_hunter: unloaded\n");
}

#else /* !MH_HAVE_MODULE_SPACE */

static int __init mh_init(void)
{
	pr_err("mod_hunter: unsupported architecture "
	       "(x86_64 only for now), refusing to load\n");
	return -ENODEV;
}

static void __exit mh_exit(void)
{
}

#endif /* MH_HAVE_MODULE_SPACE */

module_init(mh_init);
module_exit(mh_exit);

/*
 * MODULE_LICENSE accepts only "GPL" (= v2) in kbuild; the effective
 * licence of this file is GPL-3.0-only as stated in the SPDX tag.
 */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("madsys; g1inko (nitara2, merged)");
MODULE_DESCRIPTION("ALIRT hidden kernel module hunter: brute-force scan "
		   "+ module list/kset cross-validation via /proc/showmodules");
MODULE_VERSION(MH_VERSION);
