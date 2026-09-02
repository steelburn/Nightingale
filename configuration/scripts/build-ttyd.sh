#!/usr/bin/env bash
# Build libwebsockets with libuv, then ttyd 1.7.7, against the image OpenSSL.
set -eux

apt-get update
apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    wget \
    unzip \
    libuv1-dev \
    libssl-dev \
    zlib1g-dev \
    libjson-c-dev \
    libcap-dev \
    libzstd-dev \
    git
rm -rf /var/lib/apt/lists/*

cd /tmp
git clone --depth 1 --branch v4.3-stable https://github.com/warmcat/libwebsockets.git libwebsockets-src
cd libwebsockets-src
mkdir build && cd build
cmake .. -DLWS_WITH_LIBUV=ON -DLWS_WITH_LIBEVENT=OFF -DLWS_WITH_LIBEV=OFF -DCMAKE_BUILD_TYPE=Release
make -j"$(nproc)"
make install
ldconfig
cd /tmp && rm -rf libwebsockets-src

wget -L https://github.com/tsl0922/ttyd/archive/refs/tags/1.7.7.zip
unzip 1.7.7.zip
cd ttyd-1.7.7 && mkdir build && cd build
cmake .. -DLWS_WITH_LIBUV=ON -DLWS_WITH_LIBEVENT=OFF -DLWS_WITH_LIBEV=OFF -DCMAKE_BUILD_TYPE=Release
make && make install
cd /tmp && rm -rf ttyd-1.7.7 1.7.7.zip

command -v ttyd >/dev/null || { echo "ERROR: ttyd build failed"; exit 1; }
ttyd --version || { echo "ERROR: ttyd cannot run - library dependency issue"; exit 1; }
