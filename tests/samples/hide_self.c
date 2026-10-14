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
	list_del_init(&THIS_MODULE->list);
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
