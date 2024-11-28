# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
CLANG ?= clang
MUSL-GCC ?= musl-gcc
RM ?= rm
CMAKE ?= cmake
LIBBPF_OBJ := /usr/src/linux-headers-6.8.0-49-generic/tools/bpf/resolve_btfids/libbpf/libbpf.a
BPFINCLUDE := -I /usr/src/linux-headers-6.8.0-49-generic/tools/bpf/resolve_btfids/libbpf/include
LLVM_STRIP ?= llvm-strip
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
VMLINUX_TMP := ./vmlinux
VMLINUX_DIR := $(VMLINUX_TMP)/$(ARCH)
VMLINUX_HEADER := $(VMLINUX_DIR)/vmlinux.h
INCLUDES := -I$(OUTPUT) -I$(dir $(VMLINUX_HEADER))
CFLAGS := -g -Wall -Wno-implicit-function-declaration -Wno-unused-function -Wno-unused-but-set-variable
APPS = ruport
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

.PHONY: clean
clean:
	$(call msg,clean)
	$(Q)$(RM) -rf $(OUTPUT) $(APPS)
	$(Q)$(RM) -rf $(VMLINUX_DIR)
	$(Q)$(RM) -rf $(VMLINUX_TMP)


$(OUTPUT):
	$(call msg,MKDIR, $@)
	$(Q)mkdir -p $@

$(VMLINUX_DIR):
	$(Q)mkdir -p $@

$(VMLINUX_HEADER): | $(VMLINUX_DIR)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# Build BPF code
$(OUTPUT)/ruport.bpf.o: ruport.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX_HEADER) | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -Werror -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(BPFINCLUDE) $(CLANG_BPF_SYS_INCLUDES) -c ruport.bpf.c -o $@
	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info

# Generate BPF skeletons
$(OUTPUT)/ruport.skel.h: $(OUTPUT)/ruport.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	bpftool gen skeleton $< > $@

# Build xdp code
$(OUTPUT)/ruport.xdp.o: ruport.xdp.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX_HEADER)
	$(call msg,XDP,$@)
	$(Q)$(CLANG) -g -O2 -Werror -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(BPFINCLUDE) $(CLANG_BPF_SYS_INCLUDES) -c ruport.xdp.c -o $@
	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info

# Generate xdp skeletons
$(OUTPUT)/ruport.xdp.skel.h: $(OUTPUT)/ruport.xdp.o
	$(call msg,GEN-XDP-SKEL,$@)
	bpftool gen skeleton $< > $@


# Build tc code
$(OUTPUT)/ruport.tc.o: ruport.tc.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX_HEADER)
	$(call msg,TC,$@)
	$(Q)$(CLANG) -g -O2 -Werror -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(BPFINCLUDE) $(CLANG_BPF_SYS_INCLUDES) -c ruport.tc.c -o $@
	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info

# Generate tc skeletons
$(OUTPUT)/ruport.tc.skel.h: $(OUTPUT)/ruport.tc.o
	$(call msg,GEN-XDP-SKEL,$@)
	bpftool gen skeleton $< > $@

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


$(OUTPUT)/ruport.o: $(OUTPUT)/utils.o $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) $(BPFINCLUDE) -c ruport.c  -o $@

# Build application binary
$(APPS): %: $(vmlinux_header) $(OUTPUT)/utils.o  $(OUTPUT)/template.o $(OUTPUT)/log.o $(OUTPUT)/ruport.o $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CLANG) $(CFLAGS) $^ -lelf -lz  -lpthread -o $@   

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY: