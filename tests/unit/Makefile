.DEFAULT_GOAL := all

CC := clang
CPPFLAGS += -I../../userspace/include
CFLAGS ?= -std=gnu23 -Wall -Wextra -Wpedantic -O0 -g3
LDLIBS += -lsqlite3

BUILD_DIR := $(abspath ../../build/tests)
TESTS := test_close_storage test_count_alerts test_count_by_severity
TARGETS := $(addprefix $(BUILD_DIR)/,$(TESTS))
STORAGE_SRCS := \
	../../userspace/storage/sqlite_init.c \
	../../userspace/storage/sqlite_close.c
HEADERS := ../../userspace/include/storage.h

.PHONY: all test clean

all: test

test: $(TARGETS)
	$(BUILD_DIR)/test_close_storage
	$(BUILD_DIR)/test_count_alerts
	$(BUILD_DIR)/test_count_by_severity

$(BUILD_DIR)/test_close_storage: test_close_storage.c $(STORAGE_SRCS) $(HEADERS) Makefile
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(filter %.c,$^) $(LDFLAGS) $(LDLIBS) -o $@

$(BUILD_DIR)/test_count_alerts: test_count_alerts.c $(STORAGE_SRCS) ../../userspace/storage/sqlite_store.c $(HEADERS) Makefile
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(filter %.c,$^) $(LDFLAGS) $(LDLIBS) -o $@

$(BUILD_DIR)/test_count_by_severity: test_count_by_severity.c $(STORAGE_SRCS) ../../userspace/storage/sqlite_store.c $(HEADERS) Makefile
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(filter %.c,$^) $(LDFLAGS) $(LDLIBS) -o $@

clean:
	$(RM) $(TARGETS)
