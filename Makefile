# csum_guard - build the prebuilt CO-RE BPF object.
#
# The object is architecture-independent (BPF bytecode, little-endian); one
# build runs on x86_64 and aarch64.  It relocates against the target host's
# BTF at load, so it is also portable across kernel versions (>= 6.3).

ARCH        := $(shell uname -m)
TARGET_ARCH := $(if $(filter aarch64,$(ARCH)),arm64,$(if $(filter x86_64,$(ARCH)),x86,$(ARCH)))
CLANG       ?= clang
BPFTOOL     ?= $(firstword $(wildcard /usr/lib/linux-tools/*/bpftool) bpftool)

OBJ := csum_guard.bpf.o

$(OBJ): csum_guard.bpf.c vmlinux.h
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(TARGET_ARCH) -I. -c $< -o $@

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# The artifact consumed by a release: object + its checksum.
$(OBJ).sha256: $(OBJ)
	sha256sum $(OBJ) > $@

.PHONY: dist test bench clean
dist: $(OBJ) $(OBJ).sha256

test: $(OBJ)
	sudo ./test/ci.sh

bench:
	sudo ./bench/ci-bench.sh

clean:
	rm -f $(OBJ) $(OBJ).sha256 vmlinux.h bench/*.o bench/blast
