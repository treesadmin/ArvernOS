# By default, we tell `make` to remain silent. We can enable a more verbose
# output by passing `VERBOSE=1` to `make`.
VERBOSE ?= 0
ifeq ($(VERBOSE), 0)
.SILENT:
endif

MAKEFLAGS += --warn-undefined-variables

.DEFAULT_GOAL := help

# Disable implicit rules.
.SUFFIXES:

###############################################################################
# Configuration
#
# - Uppercase variables are configuration variables that a user may want to
#   change.
# - Lowercase variables are for internal purpose and should not be changed by
#   users.
###############################################################################

ARCH           = x86_64
OS_NAME        = ArvernOS
BUILD_MODE     = release
CMDLINE        = /bin/init -s
KERNEL_CMDLINE = kshell
BOARD          ?=

git_hash         := $(shell git rev-parse --short HEAD)
# We (more or less) follow the PFL project structure:
# https://api.csswg.org/bikeshed/?force=1&url=https://raw.githubusercontent.com/vector-of-bool/pitchfork/develop/data/spec.bs#intro.dirs
build_dir        = build
data_dir         = data
external_dir     = external
include_dir      = include
log_dir          = log
src_dir          = src
tests_dir        = tests
tools_dir        = tools
# Source directories.
initrd_dir       = $(data_dir)/initrd
kernel_src_dir   = $(src_dir)/kernel
libc_src_dir     = $(src_dir)/libc
userland_src_dir = $(src_dir)/userland
kernel_tests_dir = $(tests_dir)/kernel
arch_src         = $(kernel_src_dir)/arch/$(ARCH)
# Build directories.
target_build_dir = $(build_dir)/$(ARCH)
dist_dir         = $(target_build_dir)/dist
lib_objs_dir     = $(target_build_dir)/libc-objects
libk_objs_dir    = $(target_build_dir)/libk-objects
misc_dir         = $(target_build_dir)/misc
# Files.
initrd_tar       = initrd.tar
kernel_bin       = kernel-$(ARCH).bin
symbols_txt      = symbols.txt
linker_ld        = $(arch_src)/linker.ld
kernel           = $(dist_dir)/$(kernel_bin)
libc             = $(dist_dir)/libc-$(OS_NAME)-$(ARCH).a
symbols          = $(dist_dir)/$(symbols_txt)
initrd           = $(dist_dir)/$(initrd_tar)
log_file         = $(log_dir)/$(ARCH)-$(BUILD_MODE).log
gdbinit          = .gdbinit

# This is the list of external libraries we use and need to build for the
# kernel (libk).
external_deps = vtconsole
external_dirs = $(addprefix $(external_dir)/,$(external_deps))

###############################################################################
# Tools
###############################################################################

CC       = $(LLVM_PREFIX)clang$(LLVM_SUFFIX)
LD       = $(LLVM_PREFIX)ld.lld$(LLVM_SUFFIX)
AR       = $(LLVM_PREFIX)llvm-ar$(LLVM_SUFFIX)
NM       = $(LLVM_PREFIX)llvm-nm$(LLVM_SUFFIX)
OBJCOPY  = $(LLVM_PREFIX)llvm-objcopy$(LLVM_SUFFIX)
TAR      = tar
MKDIR    = mkdir
# This is from: https://github.com/nuta and it allows to print nice progress
# messages.
progress := printf "  \\033[1;96m%-8s\\033[0m  \\033[1;m%s\\033[0m\\n"

###############################################################################
# Options for the different tools
###############################################################################

###############################################################################
# Source files
###############################################################################

# libc
libc_c_files       += $(wildcard $(libc_src_dir)/*.c)
libc_c_files       += $(wildcard $(libc_src_dir)/arpa/*.c)
libc_c_files       += $(wildcard $(libc_src_dir)/arvern/*.c)
libc_c_files       += $(wildcard $(libc_src_dir)/string/*.c)
libc_c_files       += $(wildcard $(libc_src_dir)/sys/*.c)
libc_c_files       += $(wildcard $(libc_src_dir)/time/*.c)
libc_c_files       += $(wildcard $(external_dir)/printf/printf.c)
libc_asm_files     += $(wildcard $(libc_src_dir)/asm/$(ARCH)/*.asm)
# libc: object files
libc_c_objects     = $(patsubst %.c, $(lib_objs_dir)/%.o, $(libc_c_files))
libc_asm_objects   = $(patsubst %.asm, $(lib_objs_dir)/%.o, $(libc_asm_files))
# libk
libk_c_files       += $(wildcard $(kernel_src_dir)/*.c)
libk_c_files       += $(wildcard $(kernel_src_dir)/config/*.c)
libk_c_files       += $(wildcard $(kernel_src_dir)/core/elf.c)
libk_c_files       += $(wildcard $(kernel_src_dir)/core/isr.c)
libk_c_files       += $(wildcard $(kernel_src_dir)/fs/*.c)
libk_c_files       += $(wildcard $(kernel_src_dir)/fs/dev/*.c)
libk_c_files       += $(wildcard $(kernel_src_dir)/fs/proc/*.c)
libk_c_files       += $(wildcard $(kernel_src_dir)/kshell/*.c)
libk_c_files       += $(wildcard $(kernel_src_dir)/mmu/*.c)
libk_c_files       += $(wildcard $(kernel_src_dir)/net/*.c)
libk_c_files       += $(wildcard $(kernel_src_dir)/proc/*.c)
libk_c_files       += $(wildcard $(kernel_src_dir)/sys/*.c)
libk_c_files       += $(kernel_src_dir)/time/clock.c
libk_c_files       += $(kernel_src_dir)/time/timer.c
libk_c_files       += $(libc_c_files)
libk_c_files       += $(shell find $(external_dirs) -name '*.c')
libk_asm_files     +=
# libk: object files
libk_c_objects     = $(patsubst %.c, $(libk_objs_dir)/%.o, $(libk_c_files))
libk_asm_objects   = $(patsubst %.asm, $(libk_objs_dir)/%.o, $(libk_asm_files))
libk_extra_objects =

###############################################################################
# Custom configuration
###############################################################################

# Variables that may be affected by the custom configuration.
KERNEL_CFLAGS ?=
KERNEL_CONFIG ?=
LIBC_CONFIG   ?=
QEMU_OPTIONS  ?=

-include ./config
include ./Makefile-cfg.include

ifeq ($(UBSAN), 1)
	KERNEL_CFLAGS += -fsanitize=undefined
endif

ifeq ($(CONFIG_USE_DLMALLOC), 1)
	external_deps += dlmalloc
	KERNEL_CONFIG += -DCONFIG_USE_DLMALLOC
else
	external_deps += liballoc
endif

ifeq ($(CONFIG_SEMIHOSTING), 1)
	QEMU_OPTIONS  += -semihosting
	KERNEL_CONFIG += -DCONFIG_SEMIHOSTING
endif

ifeq ($(CONFIG_USE_FAKE_CLOCK), 1)
	KERNEL_CONFIG += -DBUILD_TIME_IN_NANOSECONDS=$(shell date +%s%N)
	libk_c_files  += $(kernel_src_dir)/time/fake_clock.c
endif

# This file exists in a Docker container because we copy it in `Dockerfile`.
in_docker = $(wildcard /tmp/install-linux-deps)
ifneq ($(in_docker),)
	LLVM_PREFIX =
	LLVM_SUFFIX = -13
endif

###############################################################################
# Flags
###############################################################################

LD_FLAGS += --nmagic -nostdlib --gc-sections

# Common error flags
WERRORS  += -Wall -Wextra -Werror
WERRORS  += -Wformat=2
WERRORS  += -Wno-null-pointer-arithmetic

# Includes shared between libc and libk
INCLUDES += -I$(include_dir)/libc/ -I$(external_dir)/printf/

# libc flags
LIBC_INCLUDES  += $(INCLUDES)
LIBC_ASM_FLAGS +=
LIBC_CFLAGS    += -O2 -std=c11 -ffreestanding -nostdlib -fno-builtin
LIBC_CFLAGS    += $(WERRORS)
LIBC_CFLAGS    += $(LIBC_CONFIG)

# Kernel flags
KERNEL_INCLUDES  += $(INCLUDES)
KERNEL_INCLUDES  += -I$(include_dir)/kernel/ -I$(arch_src)/
KERNEL_INCLUDES  += $(addprefix -I$(external_dir)/,$(addsuffix /, $(external_deps)))
KERNEL_ASM_FLAGS += $(KERNEL_CONFIG)
# We need to have -fno-omit-frame-pointer or the kernel stack backtrace won't
# get the stack.
KERNEL_CFLAGS    += -fno-omit-frame-pointer
KERNEL_CFLAGS    += $(LIBC_CFLAGS)
KERNEL_CFLAGS    += -ffunction-sections -fdata-sections
KERNEL_CFLAGS    += $(WERRORS)
KERNEL_CFLAGS    += $(KERNEL_CONFIG)

KERNEL_CONFIG += -DKERNEL_GIT_HASH=\"$(git_hash)\"
KERNEL_CONFIG += -DARCH=\"$(ARCH)\"

DEBUG_CFLAGS  += -g3 -DDEBUG_MODE

ENABLE_KERNEL_DEBUG ?= 1
ifeq ($(ENABLE_KERNEL_DEBUG), 1)
	DEBUG_CFLAGS += -DENABLE_KERNEL_DEBUG
endif

ifeq ($(ENABLE_CONFIG_DEBUG), 1)
	DEBUG_CFLAGS += -DENABLE_CONFIG_DEBUG
endif

ifeq ($(ENABLE_CORE_DEBUG), 1)
	DEBUG_CFLAGS += -DENABLE_CORE_DEBUG
endif

ifeq ($(ENABLE_FS_DEBUG), 1)
	DEBUG_CFLAGS += -DENABLE_FS_DEBUG
endif

ifeq ($(ENABLE_MMU_DEBUG), 1)
	DEBUG_CFLAGS += -DENABLE_MMU_DEBUG
endif

ifeq ($(ENABLE_NET_DEBUG), 1)
	DEBUG_CFLAGS += -DENABLE_NET_DEBUG
endif

ifeq ($(ENABLE_PROC_DEBUG), 1)
	DEBUG_CFLAGS += -DENABLE_PROC_DEBUG
endif

ifeq ($(ENABLE_SYS_DEBUG), 1)
	DEBUG_CFLAGS += -DENABLE_SYS_DEBUG
endif

ifeq ($(ENABLE_USERLAND_DEBUG), 1)
	DEBUG_CFLAGS += -DENABLE_USERLAND_DEBUG
endif

###############################################################################
# More specific makefiles (for archs and boards)
###############################################################################

# Include architecture-specific makefile.
include $(arch_src)/Makefile.include

ifneq ($(BOARD),)
	board_src = $(arch_src)/board/$(BOARD)

	KERNEL_CONFIG += -DBOARD=\"$(BOARD)\"

	# Include board-specific makefile when BOARD is defined.
	include $(board_src)/Makefile.include
endif

###############################################################################
# Dependencies
###############################################################################

libk_deps = $(libk_c_objects:%.o=%.d)
libk_deps += $(libk_extra_objects:%.o=%.d)

-include $(libk_deps)

libc_deps = $(libc_c_objects:%.o=%.d)

-include $(libc_deps)

###############################################################################
# Rules and targets
###############################################################################

$(build_dir):
	$(progress) "MKDIR" $@
	$(MKDIR) $@

# `|` is for order-only prerequisites, see:
# https://www.gnu.org/software/make/manual/html_node/Prerequisite-Types.html
$(target_build_dir): | $(build_dir)
	$(progress) "MKDIR" $@
	$(MKDIR) -p $@

$(dist_dir): | $(target_build_dir)
	$(progress) "MKDIR" $@
	$(MKDIR) $@

$(misc_dir): | $(target_build_dir)
	$(progress) "MKDIR" $@
	$(MKDIR) $@

$(kernel): $(linker_ld) $(libk_asm_objects) $(libk_c_objects) $(libk_extra_objects) | $(dist_dir)
	$(progress) "LD" $@
	$(LD) --output=$@ --script=$(linker_ld) $(LD_FLAGS) $(libk_asm_objects) $(libk_c_objects) $(libk_extra_objects)

$(libk_asm_objects): $(libk_objs_dir)/%.o: %.asm
	$(progress) "CC" $<
	$(MKDIR) -p $(dir $@)
	$(ASM) $(KERNEL_ASM_FLAGS) $< -o $@

$(libk_c_objects): $(libk_objs_dir)/%.o: %.c
	$(progress) "CC" $<
	$(MKDIR) -p $(dir $@)
	$(CC) -MMD -D__is_libk $(KERNEL_CFLAGS) $(KERNEL_INCLUDES) -c $< -o $@

$(libc_c_objects): $(lib_objs_dir)/%.o: %.c
	$(progress) "CC" $<
	$(MKDIR) -p $(dir $@)
	$(CC) -MMD -D__is_libc $(LIBC_CFLAGS) $(LIBC_INCLUDES) -c $< -o $@

$(libc_asm_objects): $(lib_objs_dir)/%.o: %.asm
	$(progress) "CC" $<
	$(MKDIR) -p $(dir $@)
	$(ASM) $(LIBC_ASM_FLAGS) $< -o $@

$(libc): $(libc_asm_objects) $(libc_c_objects) | $(dist_dir)
	$(progress) "AR" $@
	$(AR) rcs $@ $(libc_asm_objects) $(libc_c_objects)

$(symbols): $(kernel)
	$(NM) $< | awk '{ print $$1, $$3 }' | sort > $@

$(initrd): userland $(symbols) | $(misc_dir)
	$(progress) "TAR" $@
	cp -R $(dist_dir)/userland/bin $(initrd_dir)
	cp $(symbols) $(initrd_dir)/etc
	echo "$(OS_NAME) ($(ARCH)) build info" > $(initrd_dir)/info
	echo "" >> $(initrd_dir)/info
	echo "hash: $(git_hash)" >> $(initrd_dir)/info
	echo "date: $(shell date)" >> $(initrd_dir)/info
	echo "mode: $(BUILD_MODE)" >> $(initrd_dir)/info
	echo "" >> $(initrd_dir)/info
	echo "compiler: $(shell $(CC) --version | head -n 1)" >> $(initrd_dir)/info
	echo "" >> $(initrd_dir)/info
	echo "CFLAGS: $(KERNEL_CFLAGS)" >> $(initrd_dir)/info
	echo "INCLUDES: $(KERNEL_INCLUDES)" >> $(initrd_dir)/info
	cd $(initrd_dir) && $(TAR) -cf ../../$@ *

gdbinit:
	$(progress) "GEN" $(gdbinit)
	echo "# AUTO-GENERATED CONFIGURATION, DO NOT EDIT.\n#" > $(gdbinit)
	echo "# ARCH=$(ARCH)\n" >> $(gdbinit)
	cat .default-gdbinit >> $(gdbinit)
	echo "\nadd-symbol-file $(kernel)" >> $(gdbinit)
	if [ -f ".gdbinit.local" ]; then \
		echo "\n# .gdbinit.local - local configuration:" >> $(gdbinit); \
		cat ".gdbinit.local" >> $(gdbinit); \
	fi
.PHONY: gdbinit

libc: ## build the libc
libc: $(libc)
.PHONY: libc

release: ## build the project in release mode
release: arch-release
.PHONY: release

run-release: ## run the project in release mode
run-release: arch-run-release
.PHONY: run-release

debug: ## build the project in debug mode
debug: KERNEL_CFLAGS += $(DEBUG_CFLAGS)
debug: BUILD_MODE = debug
debug: arch-debug
.PHONY: debug

run-debug: ## run the project in debug mode
run-debug: BUILD_MODE = debug
run-debug: QEMU_OPTIONS += -monitor tcp:127.0.0.1:5555,server,nowait
run-debug: arch-run-debug
.PHONY: run-debug

gdb: ## build, run the project in debug mode and enable GDB
gdb: DEBUG_CFLAGS += -ggdb
gdb: QEMU_OPTIONS += -s -S
gdb: gdbinit run-debug
.PHONY: gdb

run-test: ## run the project in test mode
run-test: BUILD_MODE = test
run-test: CMDLINE = /bin/userland-testsuite
run-test: QEMU_OPTIONS += -display curses
run-test: run-release
.PHONY: run-test

userland: ## compile the userland programs (statically linked to libc)
userland: ENABLE_USERLAND_DEBUG ?= 0
userland: libc
	@for userland_program in $(shell find $(userland_src_dir)/* -type d -not \( -path $(userland_src_dir)/bin -o -path $(userland_src_dir)/local-build \)); do \
		$(MAKE) -C $$userland_program OS_NAME="$(OS_NAME)" ARCH="$(ARCH)" BOARD="$(BOARD)" ENABLE_USERLAND_DEBUG=$(ENABLE_USERLAND_DEBUG) ; \
	done
.PHONY: userland

fmt: ## automatically format the code with clang-format
	find . -path ./external -prune -false -o -type f \( -name '*.c' -o -name '*.h' \) -exec clang-format$(LLVM_SUFFIX) -style=file -i "{}" ";"
.PHONY: fmt

version: ## print tool versions
	$(CC) --version
	$(ASM) --version
	$(LD) --version
	$(AR) --version
	$(QEMU) --version
.PHONY: version

docs: ## build the docs
	rm -rf docs/*.* docs/search/
	doxygen ./Doxyfile
.PHONY: docs

docs-fast: ## build the docs in fast mode (does not remove previous docs)
	doxygen ./Doxyfile
.PHONY: docs-fast

clean: ## remove build artifacts
	$(progress) "CLEAN"
	rm -rf $(target_build_dir) \
				 $(initrd_dir)/bin/ \
				 $(initrd_dir)/etc/$(symbols_txt) \
				 $(initrd_dir)/info \
				 $(userland_src_dir)/local-build/ \
				 $(libk_deps) \
				 $(libc_deps)
.PHONY: clean

what: ## display some information about the current configuration
	echo "OS_NAME : $(OS_NAME)"
	echo "ARCH    : $(ARCH)"
	echo ""
	echo "CONFIG_SEMIHOSTING    = $(CONFIG_SEMIHOSTING)"
	echo "CONFIG_USE_DLMALLOC   = $(CONFIG_USE_DLMALLOC)"
	echo "CONFIG_USE_FAKE_CLOCK = $(CONFIG_USE_FAKE_CLOCK)"
.PHONY: what

help: ## show this help message
help:
	@/bin/echo -n "$(OS_NAME) - available commands for arch=$(ARCH)"
	@if [ -n "$(BOARD)" ]; then echo " board=$(BOARD)\n"; else echo "\n"; fi
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
.PHONY: help

###############################################################################
# "Private targets"
###############################################################################

build-docker-image-for-circle:
	docker build . -f .circleci/images/circle/Dockerfile -t willdurand/arvernos-circle:latest
.PHONY: build-docker-image-for-circle
