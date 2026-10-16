/* SPDX-License-Identifier: GPL-3.0-only */
/*
 * Force-include shim for selected process_hunter cross-builds.
 *
 * run-in-container.sh passes KCFLAGS="-I<this dir> -I$KDIR/mm
 * -include alirt-slub-shim.h" only for the matrix combos whose
 * cross-gcc/header-era include order breaks the frozen
 * process_hunter.c sequence
 *
 *	#include <linux/slab.h> ... #include <linux/slub_def.h>
 *
 * On those combos <linux/slub_def.h> references types no earlier
 * include has defined:
 *
 *   - 5.0 - 5.8 : struct kmem_cache embeds
 *     `struct memcg_cache_params memcg_params`, which lives only in
 *     the internal mm/slab.h on those versions.
 *   - 5.9 - 6.11: slub_def.h's own static inlines (nearest_obj() etc.)
 *     call slab_address() on `struct slab`; both exist only in the
 *     internal mm/slab.h — which itself pulls in <linux/slub_def.h>
 *     only after defining them.
 *
 * x86_64's include order happens to satisfy slub_def.h on every
 * version; the affected cross-arch combos do not, and the module
 * sources are frozen, so the missing prerequisites are pre-included
 * here.  The internal header is reachable as <slab.h> through the
 * -I$KDIR/mm flag; it defines the prerequisites first and then
 * includes <linux/slub_def.h> itself, so process_hunter.c's later
 * copy of that include is a header-guard no-op.
 */
#include <linux/version.h>
#include <linux/mm.h>
#include <linux/slab.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0) && \
    LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
#  include <slab.h>	/* the internal mm/slab.h, via -I$KDIR/mm */
#endif
