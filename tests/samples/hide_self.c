/*
 * hide_self.c — tutorial sample module for automated testing ONLY
 *
 * Imitates the self-protection technique of real LKM rootkits
 * (Diamorphine, KoviD, etc.): unlinks itself from the kernel module
 * list so that lsmod / /proc/modules cannot see it. ALIRT's detection
 * test uses it to verify that mod_hunter can find a stray struct module.
 *
 * WARNING: never load this module outside the test VM!
 */
#include <linux/module.h>
#include <linux/list.h>

static int __init hide_self_init(void)
{
	/* Diamorphine-style hide: unlink, then wipe the list pointers.
	 * A plain list_del_init() leaves list.next/prev pointing back at
	 * the module's own allocation, which mod_hunter's looks_like
	 * heuristics reject on arches whose module window sits below
	 * VMALLOC_START (armv7) or whose pointers are not x86-canonical
	 * (powerpc).  NULL pointers are the shape real rootkits leave
	 * behind, and mod_hunter explicitly accepts them. */
	list_del(&THIS_MODULE->list);
	THIS_MODULE->list.next = NULL;
	THIS_MODULE->list.prev = NULL;
	pr_info("hide_self: unlinked from module list (test sample)\n");
	return 0;
}

static void __exit hide_self_exit(void)
{
	pr_info("hide_self: exit\n");
}

module_init(hide_self_init);
module_exit(hide_self_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ALIRT test suite");
MODULE_DESCRIPTION("TEST-ONLY self-hiding LKM sample for detection tests");
