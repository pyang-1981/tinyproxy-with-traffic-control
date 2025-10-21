# Multi-stage Dockerfile for tinyproxy
# Builder stage builds the binary using system packages
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential autoconf automake libtool pkg-config ca-certificates git \
    bison flex \
    libmnl-dev libnss3-dev libssl-dev wget && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Download and build libnl first (this layer will be cached)
RUN set -eux; \
    wget -O /tmp/libnl-3.11.0.tar.gz https://github.com/thom311/libnl/releases/download/libnl3_11_0/libnl-3.11.0.tar.gz; \
    tar -xzf /tmp/libnl-3.11.0.tar.gz -C /tmp; \
    cd /tmp/libnl-3.11.0; \
    ./configure --prefix=/usr/local; \
    make -j$(nproc); \
    make install; \
    rm -rf /tmp/libnl-3.11.0*

# Copy project files (this invalidates cache when source changes)
COPY . /build

# Generate configure and Makefiles, configure and build tinyproxy
RUN set -eux; \
    export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}; \
    autoreconf -i || true; \
    ./configure; \
    make -j$(nproc)

# Runtime image: slim Debian with required runtime libs
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    tini ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy binary and default config from builder
COPY --from=builder /build/src/tinyproxy /usr/local/bin/tinyproxy
COPY --from=builder /build/etc/tinyproxy.conf /etc/tinyproxy/tinyproxy.conf

# Copy libnl libraries installed into /usr/local by the builder stage
COPY --from=builder /usr/local/lib /usr/local/lib
COPY --from=builder /usr/local/lib/pkgconfig /usr/local/lib/pkgconfig
# copy libmnl runtime library from builder (installed via libmnl-dev)
COPY --from=builder /usr/lib/x86_64-linux-gnu/libmnl.so.* /usr/lib/x86_64-linux-gnu/

ENV LD_LIBRARY_PATH=/usr/local/lib:${LD_LIBRARY_PATH:-}

RUN chmod 0755 /usr/local/bin/tinyproxy && \
    # create a dedicated system user/group for least-privilege runtime
    groupadd -r tinyproxy || true && \
    useradd -r -g tinyproxy -d /nonexistent -s /usr/sbin/nologin tinyproxy || true && \
    mkdir -p /var/log/tinyproxy /var/run/tinyproxy && \
    chown -R tinyproxy:tinyproxy /var/log/tinyproxy /var/run/tinyproxy /etc/tinyproxy/tinyproxy.conf

EXPOSE 8888

# Run the container as root. If you prefer least-privilege, remove this
# and use the tinyproxy user created above, or run the container with
# specific capabilities (for traffic-control you may need --cap-add=NET_ADMIN).
USER root
WORKDIR /var/run/tinyproxy

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/local/bin/tinyproxy", "-d", "-c", "/etc/tinyproxy/tinyproxy.conf"]
