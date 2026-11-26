.DEFAULT_GOAL := all

.PHONY: all release debug asan ubsan tsan clean test test-normal test-asan test-tsan run-tests

all:
	$(MAKE) -C userspace all

release debug asan ubsan tsan:
	$(MAKE) -C userspace BUILD=$@ all

test:
	$(MAKE) test-normal
	$(MAKE) test-asan
	$(MAKE) test-tsan

test-normal:
	$(MAKE) run-tests BUILD=tests

test-asan:
	$(MAKE) run-tests BUILD=asan

test-tsan:
	$(MAKE) run-tests BUILD=tsan

# Reserve exit code 86 for sanitizer failures, not CLI errors.
run-tests: export ASAN_OPTIONS := halt_on_error=1:exitcode=86
run-tests: export LSAN_OPTIONS := exitcode=86
run-tests: export UBSAN_OPTIONS := halt_on_error=1:exitcode=86
run-tests: export TSAN_OPTIONS := halt_on_error=1:exitcode=86
run-tests:
	$(MAKE) -C userspace BUILD=$(BUILD) all
	KALATRACE_CLI="$(CURDIR)/build/$(BUILD)/kalatracectl" python3 -m unittest discover -s tests -p 'test_*.py' -v
	$(MAKE) -C tests/unit BUILD=$(BUILD) all

clean:
	$(MAKE) -C userspace clean
	$(MAKE) -C tests/unit clean
