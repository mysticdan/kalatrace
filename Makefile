.DEFAULT_GOAL := all

.PHONY: all release debug asan ubsan clean

all:
	$(MAKE) -C userspace all

release debug asan ubsan:
	$(MAKE) -C userspace BUILD=$@ all

clean:
	$(MAKE) -C userspace clean
