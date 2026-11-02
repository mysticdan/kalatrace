# Hardened Linux userspace CLI build (Clang + lld)
.DEFAULT_GOAL := all

CC := clang
BUILD ?= release

VALID_BUILDS := release debug asan ubsan
ifeq ($(filter $(BUILD),$(VALID_BUILDS)),)
$(error Unsupported BUILD='$(BUILD)'; choose $(VALID_BUILDS))
endif

# Preprocessing and compiler diagnostics
CPPFLAGS := -Iinclude
CFLAGS := -std=gnu23 -Wall -Wextra -Wpedantic \
          -Wformat=2 -Wconversion -Wshadow -Wundef \
          -Wstrict-prototypes -Wmissing-prototypes \
          -Werror=format-security -Werror=implicit-function-declaration \
          -Werror=incompatible-pointer-types -Werror=int-conversion \
          -fPIE -fstack-protector-strong -fstack-clash-protection \
          -fno-omit-frame-pointer -fstrict-flex-arrays=3 -pthread

# Full RELRO, immediate symbol binding, non-executable stack and PIE
LDFLAGS := -pie -Wl,-z,relro,-z,now,-z,noexecstack -pthread
LDLIBS := -lcjson

# Hardware-assisted branch protection depends on target architecture
TARGET_TRIPLE := $(shell $(CC) -dumpmachine)
ifneq ($(filter x86_64% i%86%,$(TARGET_TRIPLE)),)
CFLAGS += -fcf-protection=full
else ifneq ($(filter aarch64%,$(TARGET_TRIPLE)),)
CFLAGS += -mbranch-protection=standard
endif

# Keep instrumented test binaries separate from production binaries
ifeq ($(BUILD),release)
CPPFLAGS += -DNDEBUG -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3
CFLAGS += -O2 -flto=thin -ftrivial-auto-var-init=zero
LDFLAGS += -flto=thin -fuse-ld=lld
else ifeq ($(BUILD),debug)
CFLAGS += -O0 -g3 -fno-optimize-sibling-calls
else ifeq ($(BUILD),asan)
CFLAGS += -O1 -g3 -fsanitize=address,undefined \
          -fno-sanitize-recover=all -fno-optimize-sibling-calls
LDFLAGS += -fsanitize=address,undefined
else ifeq ($(BUILD),ubsan)
CFLAGS += -O1 -g3 -fsanitize=undefined -fno-sanitize-recover=all
LDFLAGS += -fsanitize=undefined
endif

# Opt into stricter builds after warnings in existing code are resolved
ifeq ($(WERROR),1)
CFLAGS += -Werror
endif

# Only include sources used by the current CLI; daemon/storage are incomplete
SRCS := \
	cli/kalatracectl.c \
	rules/parser.c \
	rules/matcher.c \
	rules/alert.c \
	output/jsonl_writer.c

BUILD_DIR := build/$(BUILD)
TARGET := $(BUILD_DIR)/kalatracectl
OBJS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(SRCS))
DEPS := $(OBJS:.o=.d)

.PHONY: all clean
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $^ $(LDFLAGS) $(LDLIBS) -o $@

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

-include $(DEPS)

clean:
	rm -rf build
