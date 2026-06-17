FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Dependances Snort 3
# NB Ubuntu : la libdnet attendue par Snort est packagee 'libdumbnet-dev'
# (header dumbnet.h) ; on cree un lien dnet.h pour que cmake FindDNET la trouve.
RUN apt-get update && apt-get install -y \
    build-essential cmake libhwloc-dev libluajit-5.1-dev \
    libpcap-dev libpcre3-dev libdumbnet-dev zlib1g-dev \
    libssl-dev libsqlite3-dev liblzma-dev libunwind-dev \
    libmnl-dev autotools-dev libfl-dev pkg-config \
    wget git flex bison uuid-dev \
    && ln -sf /usr/include/dumbnet.h /usr/include/dnet.h \
    && rm -rf /var/lib/apt/lists/*

# libdaq (Data Acquisition Library)
RUN git clone https://github.com/snort3/libdaq.git /tmp/libdaq && \
    cd /tmp/libdaq && ./bootstrap && \
    ./configure --prefix=/usr/local && \
    make -j$(nproc) && make install && \
    ldconfig && rm -rf /tmp/libdaq

# gperftools (tcmalloc)
RUN wget -qO- https://github.com/gperftools/gperftools/releases/download/gperftools-2.15/gperftools-2.15.tar.gz | \
    tar xz -C /tmp && cd /tmp/gperftools-2.15 && \
    ./configure --prefix=/usr/local && \
    make -j$(nproc) && make install && \
    ldconfig && rm -rf /tmp/gperftools-2.15

# Snort 3
RUN wget -qO- https://github.com/snort3/snort3/archive/refs/tags/3.3.5.0.tar.gz | \
    tar xz -C /tmp && cd /tmp/snort3-3.3.5.0 && \
    cmake -B build -DCMAKE_INSTALL_PREFIX=/usr/local \
      -DENABLE_TCMALLOC=ON -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build -j$(nproc) && \
    cmake --install build && \
    ldconfig && rm -rf /tmp/snort3-3.3.5.0

# Regles communautaires
RUN mkdir -p /usr/local/etc/snort /usr/local/etc/rules /var/log/snort && \
    wget -qO /tmp/community-rules.tar.gz \
      https://www.snort.org/downloads/community/snort3-community-rules.tar.gz && \
    tar xzf /tmp/community-rules.tar.gz -C /usr/local/etc/rules --strip-components=1 && \
    rm /tmp/community-rules.tar.gz

WORKDIR /var/log/snort

ENTRYPOINT ["/bin/sh", "-c"]
CMD ["snort -c /usr/local/etc/snort/snort.lua -i ${IFACE:-eth0} -l /var/log/snort --plugin-path /usr/local/lib/snort"]
