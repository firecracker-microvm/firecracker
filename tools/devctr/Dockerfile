FROM public.ecr.aws/lts/ubuntu:22.04

# TODO: use a multi-stage build to reduce the download size when updating this container.
# The Rust toolchain layer will get updated most frequently, but we could keep the system
# dependencies layer intact for much longer.

ARG RUST_TOOLCHAIN="1.79.0"
ARG TMP_BUILD_DIR=/tmp/build
ARG DEBIAN_FRONTEND=noninteractive
ARG ARCH

ENV CARGO_HOME=/usr/local/rust
ENV RUSTUP_HOME=/usr/local/rust
ENV PATH="$PATH:$CARGO_HOME/bin"
ENV LC_ALL=C.UTF-8
ENV QEMU_VER="8.1.1"
ENV CROSVM_VER="9d542e6dafa3a85acd1fb6cd6f1adfa1331c4e96"
ENV CROSVM_TOOLCHAIN_VER="1.68.2"

# Build and install Qemu vhost-user-blk backend
#
RUN apt-get update \
    && apt-get -y install --no-install-recommends \
        curl gpg gpg-agent \
        python3-pip build-essential ninja-build libglib2.0-dev libpixman-1-dev flex bison \
    && pip3 install meson \
    && mkdir /tmp/qemu_build && cd /tmp/qemu_build \
    && curl -sLO https://keys.openpgp.org/vks/v1/by-fingerprint/CEACC9E15534EBABB82D3FA03353C9CEF108B584 \
    && curl -sLO https://download.qemu.org/qemu-${QEMU_VER}.tar.xz \
    && curl -sLO https://download.qemu.org/qemu-${QEMU_VER}.tar.xz.sig \
    && gpg --import CEACC9E15534EBABB82D3FA03353C9CEF108B584 \
    && gpg --verify qemu-${QEMU_VER}.tar.xz.sig qemu-${QEMU_VER}.tar.xz \
    && tar xf qemu-${QEMU_VER}.tar.xz && cd qemu-${QEMU_VER} \
    && ./configure && make -j $(nproc) contrib/vhost-user-blk/vhost-user-blk \
    && strip ./build/contrib/vhost-user-blk/vhost-user-blk \
    && cp -a ./build/contrib/vhost-user-blk/vhost-user-blk /usr/local/bin \
    && pip3 uninstall -y meson \
    && apt-get purge -y \
        curl gpg gpg-agent \
        python3-pip build-essential ninja-build libglib2.0-dev libpixman-1-dev flex bison \
    && apt-get autoremove -y \
    && cd && rm -r /tmp/qemu_build

# Install system dependencies
#
RUN apt-get update \
    && apt-get -y install --no-install-recommends \
        # essential build tools
        gcc make libc-dev binutils-dev libssl-dev \
        # Useful utilities
        gdbserver \
        # Needed in order to be able to compile `userfaultfd-sys`.
        clang \
        curl \
        file \
        git \
        jq \
        less \
        libbfd-dev \
        # for pandas
        libbz2-dev \
        libdw-dev \
        # for aarch64, but can install in x86_64
        libfdt-dev \
        libiberty-dev \
        libcurl4-openssl-dev \
        lsof \
        musl-tools \
        # needed for integration tests
        net-tools iproute2 iperf3 socat fdisk \
        numactl \
        iptables \
        openssh-client \
        pkgconf \
        python3 python3-dev python3-pip \
        screen tmux \
        tzdata \
        tini \
        # for cpu-template-helper
        # TODO: Remove `dmidecode` after the end of kernel 4.14 support.
        # https://github.com/firecracker-microvm/firecracker/issues/3677
        dmidecode \
        # for aws-lc-rs
        cmake \
        # for Qemu vhost-user-blk backend
        libglib2.0-dev \
        # for crosvm (vhost-user-blk backend)
        libcap2 \
        # for debugging
        gdb strace \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --upgrade pip poetry


COPY tools/devctr /tmp/poetry
RUN cd /tmp/poetry && \
    HOME=. POETRY_VIRTUALENVS_CREATE=false poetry install --only main --no-interaction \
    && rm -rf ~/.cache ~/.local /tmp/poetry

# Running the three as a single dockerfile command to avoid inflation of the image:
# - Install the Rust toolchain. Kani only work on x86, so only try to install it there
# - Build and install crosvm (used as vhost-user-blk backend)
# - Clean up cargo compilation directories
# - Always install both x86_64 and aarch64 musl targets, as our rust-toolchain.toml would force on-the-fly installation of both anyway
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain "$RUST_TOOLCHAIN" \
    && rustup target add x86_64-unknown-linux-musl \
    && rustup target add aarch64-unknown-linux-musl \
    && rustup component add llvm-tools-preview \
    && cargo install --locked cargo-audit cargo-deny grcov cargo-sort cargo-afl \
    && (if [ "$ARCH" = "x86_64" ]; then cargo install --locked kani-verifier && cargo kani setup; else true; fi) \
    \
    && apt-get update \
    && apt-get -y install --no-install-recommends \
        libcap-dev \
        protobuf-compiler \
    && git clone https://github.com/google/crosvm.git /tmp/crosvm \
    && cd /tmp/crosvm && git checkout ${CROSVM_VER} \
    && git submodule update --init \
    && cargo build --no-default-features --release \
    && strip ./target/release/crosvm \
    && cp -a ./target/release/crosvm /usr/local/bin \
    && apt-get purge -y \
        libcap-dev \
        protobuf-compiler \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* \
    && rustup toolchain uninstall ${CROSVM_TOOLCHAIN_VER}-${ARCH}-unknown-linux-gnu \
    && cd && rm -r /tmp/crosvm \
    \
    && rm -rf "$CARGO_HOME/registry" \
    && rm -rf "$CARGO_HOME/git"

# help musl-gcc find linux headers
RUN cd /usr/include/$ARCH-linux-musl \
    && ln -s ../$ARCH-linux-gnu/asm asm \
    && ln -s ../linux linux \
    && ln -s ../asm-generic asm-generic

# Build iperf3-vsock
RUN mkdir "$TMP_BUILD_DIR" && cd "$TMP_BUILD_DIR" \
    && git clone https://github.com/stefano-garzarella/iperf-vsock \
    && cd iperf-vsock && git checkout 9245f9a \
    && mkdir build && cd build \
    && ../configure "LDFLAGS=--static" --disable-shared && make \
    && cp src/iperf3 /usr/local/bin/iperf3-vsock \
    && cd / \
    && rm -rf "$TMP_BUILD_DIR"

# Download the codecov.io uploader
RUN cd /usr/local/bin \
    && (if [ "$ARCH" = "x86_64" ]; then  \
      curl -O https://uploader.codecov.io/latest/linux/codecov; else \
      curl -O https://uploader.codecov.io/latest/aarch64/codecov; fi) \
    && chmod +x codecov \
    && cd -

ADD tools/devctr/ctr_gitconfig /root/.gitconfig

ENTRYPOINT ["/usr/bin/tini", "--"]
