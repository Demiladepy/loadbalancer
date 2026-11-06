FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang \
        llvm \
        libbpf-dev \
        make \
        gcc \
        python3 \
        iproute2 \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY common.h xdp_lb.c xdp_loader.c Makefile ./
COPY scripts ./scripts
RUN sed -i 's/\r$//' scripts/lab.sh scripts/backend.py && chmod +x scripts/lab.sh scripts/backend.py && make
CMD ["bash", "scripts/lab.sh"]
