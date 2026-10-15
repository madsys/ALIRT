// SPDX-License-Identifier: GPL-3.0-only
/*
 * modumper.c - ALIRT kernel module dumper (v0.6.0)
 *
 * Dumps the in-memory core image of a loaded kernel module for
 * offline analysis (disassembly with dismod.sh, comparison against
 * the on-disk .ko, rootkit triage together with mod_hunter).
 *
 * Interface (unchanged from the 2005 original):
 *
 *     insmod modumper.ko mod_name=<module>
 *     cat /proc/get_mod
 *
 * Legacy kernels (< 5.10) write ./dump.dat (raw core image) and
 * ./dump.info (metadata) into the current working directory of the
 * insmod process, exactly like the original tool. On 5.10+ set_fs()
 * is gone, so kernel-side file writing is no longer possible; the
 * same payload is then emitted through /proc/get_mod as hex text and
 * is converted back to dump.dat/dump.info by dump-extract.sh.
 *
 * Acknowledgements / lineage:
 *   - CoolQ & madsys, "moddumper.c" v0.1 (2005). The original tool
 *     this file is a modernisation of: /proc/get_mod trigger,
 *     dump.dat/dump.info output, klib_fopen/klib_fwrite helpers.
 *
 * Modernisation over the 2005 original:
 *   - module lookup via the compat layer (alirt_mod_core_base/size,
 *     alirt_mod_init_base/size in ../compat/compat.h) covering
 *     module_core/core_layout/mem[MOD_*] layout changes from
 *     2.6.32 through 6.12+;
 *   - RCU list walk with try_module_get() pinning instead of a
 *     lockless list_for_each over a possibly-concurrent rmmod;
 *   - proc_ops / file_operations switch and seq_file reporting,
 *     same pattern as mod_hunter;
 *   - dual file-write strategy: set_fs(KERNEL_DS) + a direct
 *     file->f_op->write call on < 5.10 (the only era where it works;
 *     vfs_write is unexported there from 4.14 on, see md_fwrite), hex
 *     output through procfs on 5.10+ (set_fs was removed in 5.10, so
 *     no in-kernel file write is possible at all);
 *   - never panics: every address/size is validated before use and
 *     every failure is reported with pr_err and a proper errno.
 *
 * Supported: Linux 2.6.32 - 6.12+, all architectures the compat
 * layer covers.
 *
 * Copyright (C) 2005 CoolQ & madsys, 2025 ALIRT
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/version.h>
#include <linux/dcache.h>
#include <linux/utsname.h>
#include <linux/uaccess.h>

#include "compat.h"

#define MD_VERSION		"0.6.0"
#define MD_PROC_NAME		"get_mod"	/* keep the original name */
#define MD_PROC_MODE		(S_IRUSR | S_IRGRP | S_IROTH)

#define MD_DUMP_DAT		"./dump.dat"
#define MD_DUMP_INFO		"./dump.info"
#define MD_PATH_BUFLEN		4096

/*
 * Kernel-side file writing is only possible while set_fs() exists:
 * the file write method takes a __user pointer and relies on the
 * address-limit override to accept a kernel buffer. set_fs() was
 * removed in 5.10, therefore:
 *   <  5.10 : filp_open() + set_fs(KERNEL_DS) + file->f_op->write()
 *             (vfs_write itself is unexported from 4.14 on; see
 *             md_fwrite for the exact export history)
 *   >= 5.10 : no in-kernel file write; /proc/get_mod emits the dump
 *             as hex text, dump-extract.sh rebuilds dump.dat/.info
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
#define MD_LEGACY_FILE_WRITE	1
#endif

static char *mod_name;
module_param(mod_name, charp, 0);
MODULE_PARM_DESC(mod_name,
	"name of the module to dump (default: modumper itself)");

/*
 * The global module list.  "modules" is file-local in kernel/module.c
 * on every kernel (static LIST_HEAD up to at least 4.4, still
 * unexported in 6.1) and is NOT declared in linux/module.h on any
 * version, so a plain extern cannot link.  It is resolved through
 * kallsyms at init; on kernels where it is absent from the symbol
 * table (CONFIG_KALLSYMS_ALL off matters for old, static "modules")
 * name-based lookup degrades to an explicit error.
 */
static struct list_head *md_modules;
static unsigned long (*md_kln)(const char *name);

static DEFINE_MUTEX(md_mutex);

/* per-open dump context, handed to the seq_file via ->private */
struct md_dump {
	struct module	*mod;		/* pinned target, or THIS_MODULE */
	unsigned long	core_base;
	unsigned long	core_size;
	unsigned long	init_base;
	unsigned long	init_size;
	bool		init_freed;	/* init segment already released */
	char		name[MODULE_NAME_LEN];
};

/* ------------------------------------------------------------------ */
/* module lookup (RCU, pinned — mirrors mh_find_in_list)               */
/* ------------------------------------------------------------------ */

/*
 * Walk the global module list under RCU and return the target with an
 * elevated refcount (caller must module_put()), or NULL. The refcount
 * pins the module so neither its struct nor its core image can be
 * freed (or torn) while we read it for the dump.
 */
static struct module *md_find_module(const char *name)
{
	struct module *mod = NULL;
	struct module *m;

	rcu_read_lock();
	list_for_each_entry_rcu(m, md_modules, list) {
		if (!try_module_get(m))
			continue;
		if (!strcmp(m->name, name)) {
			mod = m;	/* keep the reference */
			break;
		}
		module_put(m);
	}
	rcu_read_unlock();
	return mod;
}

/* ------------------------------------------------------------------ */
/* legacy file-write path (< 5.10)                                     */
/* ------------------------------------------------------------------ */

#ifdef MD_LEGACY_FILE_WRITE

static struct file *md_fopen(const char *path, int flags, int mode)
{
	struct file *f = filp_open(path, flags, mode);

	return IS_ERR(f) ? NULL : f;
}

/*
 * Write a kernel buffer to an open file.  The write method expects a
 * user pointer, so briefly widen the address limit with set_fs(); this
 * is exactly what the 2005 klib_fwrite did via filp->f_op->write and
 * it remains the standard in-kernel write idiom on < 5.10 kernels.
 *
 * vfs_write() itself cannot be called: its EXPORT_SYMBOL was removed
 * in the 4.10-4.14 window (verified against fs/read_write.c: exported
 * v3.10:460, v4.4:550, v4.9:572, gone v4.14), so referencing it fails
 * insmod with "Unknown symbol vfs_write" on 4.14+ and is a hard
 * modpost error on >= 5.4 kernels.  kernel_write() does not cover the
 * range either: it is only exported from v4.14 (fs/read_write.c:526)
 * and needs set_fs() regardless, which is exactly the era split this
 * file already has.  Call the file's own ->write method directly
 * instead - the same primitive vfs_write() dispatches to.  Serialized
 * with everything else by md_mutex.
 */
static ssize_t md_fwrite(struct file *f, const void *buf, size_t len)
{
	mm_segment_t oldfs;
	loff_t pos = f->f_pos;
	ssize_t ret;

	if (!f->f_op || !f->f_op->write)
		return -EINVAL;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	ret = f->f_op->write(f, (const char __user *)buf, len, &pos);
	set_fs(oldfs);
	f->f_pos = pos;
	return ret;
}

/* log the absolute path of a just-opened cwd-relative dump file */
static void md_report_path(struct file *f, const char *what)
{
	char *buf;
	char *path;

	buf = kmalloc(MD_PATH_BUFLEN, GFP_KERNEL);
	if (!buf)
		return;
	path = d_path(&f->f_path, buf, MD_PATH_BUFLEN);
	if (!IS_ERR(path))
		pr_info("modumper: %s -> %s\n", what, path);
	kfree(buf);
}

#endif /* MD_LEGACY_FILE_WRITE */

/* ------------------------------------------------------------------ */
/* metadata text (identical keys in dump.info and the 5.10+ hex header)*/
/* ------------------------------------------------------------------ */

static void md_info_text(char *buf, size_t len, const struct md_dump *d)
{
	snprintf(buf, len,
		"module=%s\n"
		"core_base=0x%lx\n"
		"core_size=0x%lx\n"
		"init_base=0x%lx\n"
		"init_size=0x%lx\n"
		"init_freed=%s\n"
		"dumped_at_jiffies=%lu\n"
		"alirt_version=%s\n"
		"kernel=%s\n",
		d->name,
		d->core_base, d->core_size,
		d->init_base, d->init_size,
		d->init_freed ? "yes (init segment already freed)" : "no",
		jiffies,
		MD_VERSION,
		utsname()->release);
}

/* ------------------------------------------------------------------ */
/* dump execution                                                      */
/* ------------------------------------------------------------------ */

/*
 * < 5.10: write ./dump.dat (raw core bytes) + ./dump.info (metadata)
 * in the insmod cwd, then answer the seq_file with a short status.
 * >= 5.10: emit metadata as '#' comment lines followed by the core
 * image as lowercase hex, 16 bytes per line; dump-extract.sh turns
 * this back into dump.dat/dump.info.
 */
static int md_show(struct seq_file *m, void *v)
{
	struct md_dump *d = m->private;
	char info[512];

	md_info_text(info, sizeof(info), d);

	mutex_lock(&md_mutex);

#ifdef MD_LEGACY_FILE_WRITE
	{
		struct file *fdat = NULL, *finfo = NULL;
		ssize_t wr;
		size_t info_len = strlen(info);

		fdat = md_fopen(MD_DUMP_DAT, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (!fdat) {
			pr_err("modumper: failed to open %s\n", MD_DUMP_DAT);
			seq_puts(m, "modumper: failed to open ./dump.dat\n");
			goto out;
		}
		md_report_path(fdat, "dump.dat");
		wr = md_fwrite(fdat, (const void *)d->core_base, d->core_size);
		if (wr != (ssize_t)d->core_size)
			pr_err("modumper: short write on dump.dat (%zd of %lu)\n",
			       wr, d->core_size);
		else
			pr_info("modumper: dumped %lu core bytes of '%s'\n",
				d->core_size, d->name);
		fput(fdat);

		finfo = md_fopen(MD_DUMP_INFO, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (!finfo) {
			pr_err("modumper: failed to open %s\n", MD_DUMP_INFO);
			seq_puts(m, "modumper: failed to open ./dump.info\n");
			goto out;
		}
		md_report_path(finfo, "dump.info");
		wr = md_fwrite(finfo, info, info_len);
		if (wr != (ssize_t)info_len)
			pr_err("modumper: short write on dump.info (%zd of %zu)\n",
			       wr, info_len);
		fput(finfo);

		seq_printf(m, "modumper: dumped module '%s' (%lu bytes) to ./dump.dat, ./dump.info\n",
			   d->name, d->core_size);
	}
out:
#else /* >= 5.10: hex through procfs */
	{
		unsigned long off;

		seq_printf(m, "# %s", info);	/* each line already ends in \n */
		seq_puts(m, "# format=hex (convert with dump-extract.sh)\n");
		for (off = 0; off < d->core_size; off += 16) {
			int n = (int)min_t(unsigned long, 16, d->core_size - off);

			seq_printf(m, "%*ph\n", n, (const void *)(d->core_base + off));
		}
		pr_info("modumper: dumped %lu core bytes of '%s' via /proc/%s hex mode\n",
			d->core_size, d->name, MD_PROC_NAME);
	}
#endif

	mutex_unlock(&md_mutex);
	return 0;
}

/* ------------------------------------------------------------------ */
/* open: locate, pin and validate the target module                    */
/* ------------------------------------------------------------------ */

static int md_open(struct inode *inode, struct file *file)
{
	struct md_dump *d;
	struct seq_file *m;
	struct module *mod;
	int ret;

	ret = single_open(file, md_show, NULL);
	if (ret)
		return ret;

	d = kzalloc(sizeof(*d), GFP_KERNEL);
	if (!d) {
		ret = -ENOMEM;
		goto err_release;
	}

	if (mod_name) {
		if (!md_modules) {
			pr_err("modumper: 'modules' list not resolvable "
			       "(need CONFIG_KALLSYMS_ALL on old kernels), "
			       "cannot look up '%s'\n", mod_name);
			ret = -ENOENT;
			goto err_free;
		}
		mod = md_find_module(mod_name);
		if (!mod) {
			pr_err("modumper: module '%s' not found\n", mod_name);
			ret = -ENOENT;
			goto err_free;
		}
	} else {
		/*
		 * Default: dump ourselves. We cannot safely pin THIS_MODULE
		 * across the fd lifetime against our own unload, and the
		 * race is a lab-tool non-issue, so no extra ref here.
		 */
		mod = THIS_MODULE;
		pr_info("modumper: mod_name not given, dumping modumper itself\n");
	}

	/*
	 * Take addresses/sizes through the compat layer and refuse to
	 * touch anything that is NULL/zero before a single byte is read
	 * or written.
	 */
	d->mod = mod;
	d->core_base = (unsigned long)alirt_mod_core_base(mod);
	d->core_size = alirt_mod_core_size(mod);
	d->init_base = (unsigned long)alirt_mod_init_base(mod);
	d->init_size = alirt_mod_init_size(mod);
	d->init_freed = (!d->init_base || !d->init_size);
	alirt_strscpy(d->name, mod->name, sizeof(d->name));

	if (!d->core_base || !d->core_size) {
		pr_err("modumper: '%s' has no core image (base=0x%lx size=0x%lx), refusing dump\n",
		       d->name, d->core_base, d->core_size);
		ret = -EINVAL;
		goto err_put;
	}

	m = file->private_data;
	m->private = d;
	return 0;

err_put:
	if (mod != THIS_MODULE)
		module_put(mod);
err_free:
	kfree(d);
err_release:
	single_release(inode, file);
	return ret;
}

static int md_release(struct inode *inode, struct file *file)
{
	struct seq_file *m = file->private_data;
	struct md_dump *d = m ? m->private : NULL;

	if (d) {
		if (d->mod && d->mod != THIS_MODULE)
			module_put(d->mod);
		kfree(d);
	}
	return single_release(inode, file);
}

/* ------------------------------------------------------------------ */
/* procfs registration                                                 */
/* ------------------------------------------------------------------ */

#if ALIRT_HAVE_PROC_OPS
static const struct proc_ops md_ops = {
	.proc_open	= md_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= md_release,
};
#else
static const struct file_operations md_ops = {
	.open		= md_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= md_release,
};
#endif

static struct proc_dir_entry *md_entry;

static int __init md_init(void)
{
	int ret;

	pr_info("modumper: ALIRT kernel module dumper v%s\n", MD_VERSION);
	ret = alirt_resolve_kln(&md_kln);
	if (ret) {
		pr_warn("modumper: kallsyms_lookup_name not resolvable (%d); "
			"name-based module lookup disabled\n", ret);
	} else {
		md_modules = (struct list_head *)md_kln("modules");
		if (!md_modules)
			pr_warn("modumper: 'modules' not in kallsyms "
				"(CONFIG_KALLSYMS_ALL off on old kernels?); "
				"name-based lookup disabled\n");
	}
	md_entry = proc_create(MD_PROC_NAME, MD_PROC_MODE, NULL, &md_ops);
	if (!md_entry) {
		pr_err("modumper: failed to create /proc/%s\n", MD_PROC_NAME);
		return -ENOMEM;
	}
	pr_info("modumper: /proc/%s created (read = dump module '%s')\n",
		MD_PROC_NAME, mod_name ? mod_name : "modumper");
	return 0;
}

static void __exit md_exit(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
	proc_remove(md_entry);
#else
	/* proc_remove() does not exist on 2.6.32 */
	remove_proc_entry(MD_PROC_NAME, NULL);
#endif
	pr_info("modumper: unloaded\n");
}

module_init(md_init);
module_exit(md_exit);

/*
 * MODULE_LICENSE accepts only "GPL" (= v2) in kbuild; the effective
 * licence of this file is GPL-3.0-only as stated in the SPDX tag.
 */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("CoolQ & madsys; ALIRT (modernised)");
MODULE_DESCRIPTION("ALIRT kernel module dumper: dump module core image "
		   "via /proc/get_mod to dump.dat/dump.info (or hex mode)");
MODULE_VERSION(MD_VERSION);
