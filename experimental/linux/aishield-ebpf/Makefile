CLANG ?= clang
LLC   ?= llc
ARCH  := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_SRC := aishield_connect.bpf.c
BPF_OBJ := aishield_connect.bpf.o

.PHONY: all clean

all: $(BPF_OBJ)
	@echo "Built $(BPF_OBJ) — load with bpftool or custom loader"

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-c $(BPF_SRC) -o $(BPF_OBJ)

clean:
	rm -f $(BPF_OBJ)
