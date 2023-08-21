FROM ubuntu:22.04

# TODO: use a multi-stage build to reduce the download size when updating this container.
# The Rust toolchain layer will get updated most frequently, but we could keep the system
# dependencies layer intact for much longer.

ARG RUST_TOOLCHAIN="1.70.0"
ARG TMP_BUILD_DIR=/tmp/build
ARG FIRECRACKER_SRC_DIR="/firecracker"
ARG FIRECRACKER_BUILD_DIR="$FIRECRACKER_SRC_DIR/build"
ARG CARGO_REGISTRY_DIR="$FIRECRACKER_BUILD_DIR/cargo_registry"
ARG CARGO_GIT_REGISTRY_DIR="$FIRECRACKER_BUILD_DIR/cargo_git_registry"
ARG DEBIAN_FRONTEND=noninteractive
ARG ARCH

ENV CARGO_HOME=/usr/local/rust
ENV RUSTUP_HOME=/usr/local/rust
ENV PATH="$PATH:$CARGO_HOME/bin"
ENV LC_ALL=C.UTF-8

# Install system dependencies
#
RUN apt-get update \
    && apt-get -y install --no-install-recommends \
        # essential build tools
        gcc make libc-dev binutils-dev libssl-dev \
        # Useful utilifies
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
        openssh-client \
        pkgconf \
        python3 python3-dev python3-pip \
        screen tmux \
        tzdata \
        tini \
        # for mdl
        ruby \
        # for cpu-template-helper
        # TODO: Remove `dmidecode` after the end of kernel 4.14 support.
        # https://github.com/firecracker-microvm/firecracker/issues/3677
        dmidecode \
        # for aws-lc-rs
        cmake \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --upgrade pip poetry \
    && gem install mdl


COPY tools/devctr /tmp/poetry
RUN cd /tmp/poetry && \
    HOME=. POETRY_VIRTUALENVS_CREATE=false poetry install --only main --no-interaction \
    && rm -rf ~/.cache ~/.local /tmp/poetry

# Install the Rust toolchain. Kani only work on x86, so only try to install it there.
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain "$RUST_TOOLCHAIN" \
    && rustup target add $ARCH-unknown-linux-musl \
    && rustup component add llvm-tools-preview \
    && cargo install cargo-audit cargo-deny grcov cargo-sort \
    && (if [ "$ARCH" = "x86_64" ]; then cargo install kani-verifier && cargo kani setup; else true; fi) \
    && rm -rf "$CARGO_HOME/registry" \
    && ln -s "$CARGO_REGISTRY_DIR" "$CARGO_HOME/registry" \
    && rm -rf "$CARGO_HOME/git" \
    && ln -s "$CARGO_GIT_REGISTRY_DIR" "$CARGO_HOME/git"

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

WORKDIR "$FIRECRACKER_SRC_DIR"
ENTRYPOINT ["/usr/bin/tini", "--"]
