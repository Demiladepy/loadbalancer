CLANG ?= clang

BPF_OBJ = xdp_lb.o
LOADER_BIN = xdp_loader

LIBS = -lbpf -lelf

all: $(BPF_OBJ) $(LOADER_BIN)

.PHONY: clean

$(BPF_OBJ): xdp_lb.c common.h
	$(CLANG) -O2 -g -Wall -target bpf -mcpu=v3 -D__TARGET_ARCH_x86 \
		-I/usr/include/x86_64-linux-gnu -c $< -o $@

$(LOADER_BIN): xdp_loader.c common.h
	$(CLANG) -Wall -O2 -g -o $@ $< $(LIBS)

clean:
	rm -f $(BPF_OBJ) $(LOADER_BIN)
