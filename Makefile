CLANG ?= clang
LLC ?= llc
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

# Adjust these paths to your system's libbpf
LIBBPF_DIR ?= /usr/lib64
BPF_OBJ = xdp_lb.o
LOADER_SRC = xdp_loader.c
LOADER_BIN = xdp_loader

LIBS = -lbpf -lelf

all: $(BPF_OBJ) $(LOADER_BIN)

.PHONY: clean

$(BPF_OBJ): xdp_lb.c
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    -I/usr/include/ -I/usr/local/include \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

$(LOADER_BIN): $(LOADER_SRC)
	$(CLANG) -Wall -O2 -g -o $@ $< $(LIBS)

clean:
	rm -f *.o *.ll $(LOADER_BIN)
