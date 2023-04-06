# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
CLANG ?= clang
MUSL-GCC ?= musl-gcc

CMAKE ?= cmake
LIBSSH_DIR := $(abspath ./libssh)
LIBSSH_OBJ := $(abspath $(OUTPUT)/libssh.a)

LLVM_STRIP ?= llvm-strip
LIBBPF_SRC := $(abspath ./libbpf/src)
BPFTOOL_SRC := $(abspath ./bpftool/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL ?= $(abspath $(OUTPUT)/bpftool/bpftool)
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
VMLINUX := ./vmlinux/$(ARCH)/vmlinux.h
# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
INCLUDES := -I$(OUTPUT) -I./libbpf/include/uapi -I$(dir $(VMLINUX)) -I$(LIBSSH_DIR)/build/src/include -I$(LIBSSH_DIR)/include -I$(LIBSSH_DIR)/build/include

CFLAGS := -g -Wall -Wno-implicit-function-declaration -Wno-unused-function -Wno-unused-but-set-variable

APPS = ruport

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directorypoe
endif

.PHONY: all
all: $(APPS)

.PHONY: cleanall clearapp
cleanall:
	$(call msg,CLEANALL)
	$(Q)rm -rf $(OUTPUT) $(APPS)

cleanapp:
	$(call msg, CLEANAPP)
	$(Q)rm $(OUTPUT)/ruport.o $(APPS)


$(OUTPUT) $(OUTPUT)/libbpf $(dir $(BPFTOOL)) $(LIBSSH_DIR)/build:
	$(call msg,MKDIR, $@)
	$(Q)mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

# Build bpftool
$(BPFTOOL): | $(dir $(BPFTOOL))
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) OUTPUT=$(dir $(BPFTOOL)) -C $(BPFTOOL_SRC)

# generate vmlinux.h
.PHONY: vmlinux_header
vmlinux_header:
	$(Q)$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

# Build BPF code
$(OUTPUT)/ruport.bpf.o: ruport.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX) | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -Werror -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c ruport.bpf.c -o $@
	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info

# Generate BPF skeletons
$(OUTPUT)/ruport.skel.h: $(OUTPUT)/ruport.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Build xdp code
$(OUTPUT)/ruport.xdp.o: ruport.xdp.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX)
	$(call msg,XDP,$@)
	$(Q)$(CLANG) -g -O2 -Werror -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c ruport.xdp.c -o $@
	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info

# Generate xdp skeletons
$(OUTPUT)/ruport.xdp.skel.h: $(OUTPUT)/ruport.xdp.o
	$(call msg,GEN-XDP-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@


# Build xdp code
$(OUTPUT)/ruport.tc.o: ruport.tc.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX)
	$(call msg,TC,$@)
	$(Q)$(CLANG) -g -O2 -Werror -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c ruport.tc.c -o $@
	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info

# Generate xdp skeletons
$(OUTPUT)/ruport.tc.skel.h: $(OUTPUT)/ruport.tc.o
	$(call msg,GEN-XDP-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Build user-space code
$(patsubst %,$(OUTPUT)/%.o,$(APPS)): $(OUTPUT)/ruport.skel.h $(OUTPUT)/ruport.xdp.skel.h $(OUTPUT)/ruport.tc.skel.h

$(OUTPUT)/utils.o: utils.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c utils.c -o $@

$(OUTPUT)/template.o: template.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c template.c -o $@

$(OUTPUT)/log.o: log.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c log.c -o $@


$(OUTPUT)/ruport.o: utils.o $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c ruport.c  -o $@

# Build Libssh 
$(LIBSSH_DIR)/build/src/libssh.a: | $(LIBSSH_DIR)/build
	$(call msg generate Makefile)
	$(CMAKE) -S $(LIBSSH_DIR) -B $(LIBSSH_DIR)/build -DWITH_EXAMPLES=OFF -DBUILD_SHARED_LIBS=OFF -DWITH_STATIC_LIB=ON
	$(MAKE) -C $(LIBSSH_DIR)/build

# Build application binary
$(APPS): %: $(OUTPUT)/utils.o  $(OUTPUT)/template.o $(OUTPUT)/log.o $(OUTPUT)/ruport.o $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	@echo "App----------------------------"
	@echo $^
	@echo "App----------------------------"
	$(Q)$(CLANG) $(CFLAGS) $^ -lelf -lz  -lpthread -o $@   

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY: