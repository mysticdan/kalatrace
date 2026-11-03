.DEFAULT_GOAL := all

.PHONY: all release debug asan ubsan clean test

all:
	$(MAKE) -C userspace all

release debug asan ubsan:
	$(MAKE) -C userspace BUILD=$@ all

test:
	$(MAKE) -C userspace BUILD=debug all
	KALATRACE_CLI=$(CURDIR)/userspace/build/debug/kalatracectl python3 -m unittest discover -s tests -p 'test_*.py' -v

clean:
	$(MAKE) -C userspace clean
