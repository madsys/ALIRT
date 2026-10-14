# ALIRT top-level Makefile (v0.5.2)
# Sources live in src/<tool>/; this file only dispatches the builds.
# Usage:
#   make            build all four kernel modules
#   make mod_hunter build a single module
#   make clean      clean all build outputs
#   make KDIR=/path/to/kernel   build against a specific kernel tree
#                               (cross-compilation / testing)

KDIR  ?= /lib/modules/$(shell uname -r)/build
PWD   := $(shell pwd)

TOOLS := mod_hunter process_hunter sock_hunter mod_dumper

all: $(TOOLS)

$(TOOLS):
	$(MAKE) -C $(KDIR) M=$(PWD)/src/$@ modules

clean:
	@for t in $(TOOLS); do \
		$(MAKE) -C $(KDIR) M=$(PWD)/src/$$t clean 2>/dev/null || true; \
	done

.PHONY: all clean $(TOOLS)
