/*
 * ALIRT cross-architecture runtime test init.
 *
 * Statically linked (cross gcc -static), pure-syscall /init for the
 * initramfs used by the QEMU runtime test on non-x86 targets.  Replaces
 * the busybox-based tests/init so that no per-architecture busybox
 * binary (which Debian does not ship for e.g. mips big-endian) is needed.
 *
 * Flow (mirrors tests/init):
 *   1. mount /proc
 *   2. finit_module(/ko/hide_self.ko)   -- self-hiding sample module
 *   3. finit_module(/ko/mod_hunter.ko) -- the scanner under test
 *   4. dump /proc/showmodules to the console
 *   5. PASS if a "[CRITICAL]" or "[HIGH]" verdict line is present in the
 *      report (the seq_file output reaches userland even if a rootkit
 *      hijacks printk; the header line mentions the words without the
 *      brackets, so a plain substring match is exact)
 *   6. print "RESULT: PASS/FAIL (...)" and "RUNTIME-RESULT: PASS/FAIL",
 *      then power off the VM
 */
#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>

/* Unbuffered console output: stdout is /dev/console (opened by the kernel
 * for init), but avoid stdio buffering entirely so nothing is lost when we
 * power off immediately after printing. */
static void wr(const char *fmt, ...)
{
	char buf[1024];
	va_list ap;
	int n;
	ssize_t w;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (n <= 0)
		return;
	if (n > (int)sizeof(buf))
		n = sizeof(buf);
	w = write(1, buf, n);
	(void)w;
}

static int load_module(const char *path, const char *name)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);

	if (fd < 0) {
		wr("[TEST] %s: open %s failed: %s\n", name, path, strerror(errno));
		return -1;
	}
	/* finit_module(2) exists on every architecture since kernel 3.8 */
	if (syscall(SYS_finit_module, fd, "", 0) != 0) {
		wr("[TEST] %s: finit_module failed: %s\n", name, strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

int main(void)
{
	static char buf[256 * 1024];
	ssize_t off = 0;
	int fd;
	int found;

	wr("=== ALIRT cross-arch runtime test start ===\n");

	mkdir("/proc", 0555);
	if (mount("proc", "/proc", "proc", 0, NULL) != 0)
		wr("[TEST] mount /proc failed: %s\n", strerror(errno));

	if (load_module("/ko/hide_self.ko", "hide_self") == 0)
		wr("[TEST] hide_self loaded (unlinked from the module list)\n");

	if (load_module("/ko/mod_hunter.ko", "mod_hunter") != 0) {
		wr("RESULT: FAIL (mod_hunter failed to load)\n");
		wr("RUNTIME-RESULT: FAIL\n");
		sync();
		reboot(RB_POWER_OFF);
		return 1;
	}

	/* Trigger the scan: mod_hunter scans and reports on /proc/showmodules
	 * read; the whole report is written to the console verbatim. */
	fd = open("/proc/showmodules", O_RDONLY);
	if (fd < 0) {
		wr("RESULT: FAIL (cannot open /proc/showmodules: %s)\n",
		   strerror(errno));
		wr("RUNTIME-RESULT: FAIL\n");
		sync();
		reboot(RB_POWER_OFF);
		return 1;
	}
	while (off < (ssize_t)sizeof(buf)) {
		ssize_t n = read(fd, buf + off, sizeof(buf) - off);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (n == 0)
			break;
		off += n;
	}
	close(fd);
	{
		ssize_t w = write(1, buf, off);
		(void)w;
	}

	/* mod_hunter verdicts: [CRITICAL]=hidden from list+kset,
	 * [HIGH]=in kset but missing from the module list (unlinked = hidden).
	 * Either verdict means the scanner found a module the list does not
	 * show.  "[CRITICAL]"/"[HIGH]" with brackets appear only in per-finding
	 * verdict lines, never in the explanatory header, so a substring match
	 * is unambiguous. */
	found = memmem(buf, off, "[CRITICAL]", 10) != NULL ||
		memmem(buf, off, "[HIGH]", 6) != NULL;

	if (found)
		wr("RESULT: PASS (suspicious struct module not in the module list found)\n");
	else
		wr("RESULT: FAIL (hidden module not detected)\n");

	wr("=== ALIRT cross-arch runtime test end ===\n");
	wr("RUNTIME-RESULT: %s\n", found ? "PASS" : "FAIL");

	sync();
	reboot(RB_POWER_OFF);
	/* reboot() returns only on failure; make the kernel panic via panic=
	 * so the VM still terminates instead of sitting at a dead shell. */
	return found ? 0 : 1;
}
