# Building the devctr is a multi-stage process. The dependency graph is as follows:
#
# Stage dependency graph:
#
#                                   +--- qemu-builder -------+
#                                   |                        |
#                                   +--- libseccomp-builder -+
#                                   |                        |
#   base-image +--------------------+--- iperf3-builder -----+--- devctr
#              |                    |                        |
#              |                    +--- git-secrets-builder +
#              |                                             |
#              +--- apt-base                                 |
#                      |                                     |
#                      |                                     |
#                  python-deps      +--- crosvm-builder -----+
#                      |            |                        |
#                 rust-toolchain ---+------------------------+
#
# Parallel builders (from base-image):
#   qemu-builder, libseccomp-builder, iperf3-builder, git-secrets-builder
#
# Sequential base chain:
#   base-image -> apt-base -> python-deps -> rust-toolchain
#
# Rust fork (from rust-toolchain):
#   crosvm-builder  (build deps thrown away, only binary copied)
#   devctr           (cargo tools, kani, nightly, then COPY from all builders)
#

# ============================================================
# Base image: Shared between builders
# ============================================================
FROM public.ecr.aws/lts/ubuntu:24.04 AS base-image
ARG DEBIAN_FRONTEND=noninteractive
ARG ARCH
RUN apt-get update \
    && apt-get -y install --no-install-recommends \
        git gcc make libc-dev ca-certificates musl-tools

# help musl-gcc find linux headers
RUN cd /usr/include/$ARCH-linux-musl \
    && ln -s ../$ARCH-linux-gnu/asm asm \
    && ln -s ../linux linux \
    && ln -s ../asm-generic asm-generic

# ============================================================
# Builder: Qemu vhost-user-blk backend
# ============================================================
FROM base-image AS qemu-builder
ARG PIP_BREAK_SYSTEM_PACKAGES=1
ENV QEMU_VER="8.1.1"

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
    && cp -a ./build/contrib/vhost-user-blk/vhost-user-blk /usr/local/bin

# ============================================================
# Builder: static libseccomp (musl)
# ============================================================
FROM base-image AS libseccomp-builder
ENV LIBSECCOMP_VER="v2.6.0"

# Install static version of libseccomp
# We need to compile from source because
# libseccomp provided by the distribution is not
# compiled with musl-gcc and we need this
# for our musl builds.
# We specify the tag in order to have a fixed version
# of the library.
RUN apt-get -y install --no-install-recommends \
        libtool gperf autoconf automake \
    && git clone https://github.com/seccomp/libseccomp /tmp/libseccomp \
    && cd /tmp/libseccomp \
    && git checkout tags/${LIBSECCOMP_VER} \
    && ./autogen.sh \
    && CC="musl-gcc -static" ./configure --enable-static=yes --enable-shared=false \
    && make DESTDIR=/staging install

# ============================================================
# Builder: iperf3-vsock
# ============================================================
FROM base-image AS iperf3-builder
RUN git clone https://github.com/stefano-garzarella/iperf-vsock /tmp/iperf-vsock \
    && cd /tmp/iperf-vsock && git checkout 9245f9a \
    && mkdir build && cd build \
    && ../configure "LDFLAGS=--static" --disable-shared && make \
    && cp src/iperf3 /usr/local/bin/iperf3-vsock

# ============================================================
# Builder: git-secrets
# ============================================================
FROM base-image AS git-secrets-builder
RUN git clone https://github.com/awslabs/git-secrets /tmp/git-secrets \
    && cd /tmp/git-secrets \
    && make DESTDIR=/staging install

# ============================================================
# Base: apt packages (changes very rarely)
# ============================================================
FROM base-image AS apt-base
ARG ARCH
ENV LC_ALL=C.UTF-8

RUN apt-get update \
    && apt-get -y install --no-install-recommends \
        # essential build tools
        binutils-dev libssl-dev \
        # Useful utilities
        gdbserver \
        # Needed in order to be able to compile `userfaultfd-sys`.
        clang \
        curl \
        file \
        jq \
        less \
        libbfd-dev \
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
        python3 python3-dev python3-pip python3-venv \
        screen tmux \
        tzdata \
        tini \
        squashfs-tools zstd \
        python3-seccomp \
        # for aws-lc-rs
        cmake \
        # for crosvm (vhost-user-blk backend)
        libcap2 \
        # for debugging
        gdb strace trace-cmd \
    && rm -rf /var/lib/apt/lists/*


# Add cross-compile toolchain for devtool checkbuild command (rust target added in devctr stage)
RUN case "${ARCH}" in \
    "aarch64") \
        apt-get update && apt install -y gcc-x86-64-linux-gnu libc6-dev-amd64-cross linux-libc-dev-amd64-cross \
        ;; \
    "x86_64") \
        apt-get update && apt install -y gcc-aarch64-linux-gnu libc6-dev-arm64-cross linux-libc-dev-arm64-cross \
        ;; \
    *) echo "Unsupported arch ${ARCH}" && exit 1 ;; \
    esac \
    && rm -rf /var/lib/apt/lists/*


# Download codecov uploader
RUN cd /usr/local/bin \
    && (if [ "$ARCH" = "x86_64" ]; then  \
      curl -O https://uploader.codecov.io/latest/linux/codecov; else \
      curl -O https://uploader.codecov.io/latest/aarch64/codecov; fi) \
    && chmod +x codecov

# ============================================================
# Base: Python/Poetry deps (changes with poetry.lock)
# ============================================================
FROM apt-base AS python-deps
ARG PIP_BREAK_SYSTEM_PACKAGES=1
ARG ARCH
ARG VENV="/opt/venv"

RUN curl -sSL https://install.python-poetry.org | python3 -
ENV PATH="/root/.local/bin:$PATH"

COPY tools/devctr/poetry.lock /tmp/poetry/
COPY tools/devctr/pyproject.toml /tmp/poetry/
RUN cd /tmp/poetry \
    && python3 -m venv $VENV \
    && . $VENV/bin/activate \
    && poetry install --only main --no-directory --no-interaction \
    && rm -rf ~/.local/share/virtualenv/ ~/.cache /tmp/poetry \
    && cd -
ENV VIRTUAL_ENV=$VENV
ENV PATH=$VENV/bin:$PATH

# apt-get installs it globally, to manually copy it into the venv
RUN cp /usr/lib/python3/dist-packages/seccomp.cpython-312-"$ARCH"-linux-gnu.so "$VENV"/lib/python3.12/site-packages/

# ============================================================
# Base: Rust toolchain (current version)
# ============================================================
FROM python-deps AS rust-toolchain
ARG RUST_TOOLCHAIN="1.95.0"
ENV CARGO_HOME=/usr/local/rust
ENV RUSTUP_HOME=/usr/local/rust
ENV PATH="$PATH:$CARGO_HOME/bin"
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal --default-toolchain "$RUST_TOOLCHAIN" \
    && rustup target add x86_64-unknown-linux-musl \
    && rustup target add aarch64-unknown-linux-musl \
    && rustup component add llvm-tools-preview clippy rustfmt

# ============================================================
# Builder: crosvm (used as vhost-user-blk backend)
# ============================================================
FROM rust-toolchain AS crosvm-builder
ENV CROSVM_VER="9d542e6dafa3a85acd1fb6cd6f1adfa1331c4e96"
RUN apt-get update && \
    apt-get -y install --no-install-recommends \
        libcap2 \
        libcap-dev \
        protobuf-compiler \
    && git clone https://github.com/google/crosvm.git /tmp/crosvm \
    && cd /tmp/crosvm && git checkout ${CROSVM_VER} \
    && git submodule update --init \
    && cargo build --no-default-features --release \
    && strip ./target/release/crosvm \
    && cp -a ./target/release/crosvm /usr/local/bin

# ============================================================
# Devctr (final): Kani, cargo targets and assembled artifacts
# ============================================================
FROM rust-toolchain AS devctr
ARG ARCH
ENV CARGO_HOME=/usr/local/rust

# Run these as a single dockerfile command to avoid inflation of the image:
# - Install required binary crates, including cargo-afl (fuzzer) and Kani (formal verification)
# - Kani always installs _some_ nightly toolchain, we reuse it for the seccomp filter analysis test. Dynamically
#   determine the exact toolchain name, and install more components into it.
# - Always install both x86_64 and aarch64 musl targets, as our rust-toolchain.toml would force on-the-fly installation of both anyway
# - Clean up cargo compilation directories
RUN cargo install --locked grcov cargo-sort cargo-afl \
    && cargo install --locked cargo-deny --version 0.19.0 \
    && cargo install --locked kani-verifier --version 0.67.0 && cargo kani setup \
    \
    && NIGHTLY_TOOLCHAIN=$(rustup toolchain list | grep nightly | tr -d '\n') \
    && rustup component add rust-src --toolchain "$NIGHTLY_TOOLCHAIN" \
    && rustup target add "$ARCH"-unknown-linux-musl --toolchain "$NIGHTLY_TOOLCHAIN" \
    && cargo +"$NIGHTLY_TOOLCHAIN" install cargo-udeps \
    \
    && case "${ARCH}" in \
        "aarch64") rustup target add x86_64-unknown-linux-gnu ;; \
        "x86_64")  rustup target add aarch64-unknown-linux-gnu ;; \
       esac \
    \
    && rm -rf "$CARGO_HOME/registry" \
    && rm -rf "$CARGO_HOME/git"

# Copy pre-built artifacts LAST — builder changes don't invalidate Rust layer
COPY --from=qemu-builder /usr/local/bin/vhost-user-blk /usr/local/bin/
COPY --from=libseccomp-builder /staging /
COPY --from=iperf3-builder /usr/local/bin/iperf3-vsock /usr/local/bin/
COPY --from=git-secrets-builder /staging /
COPY --from=crosvm-builder /usr/local/bin/crosvm /usr/local/bin/

ADD tools/devctr/ctr_gitconfig /root/.gitconfig

ENTRYPOINT ["/usr/bin/tini", "--"]
