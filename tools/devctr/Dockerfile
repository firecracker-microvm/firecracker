FROM ubuntu:18.04

# TODO: use a multi-stage build to reduce the download size when updating this container.
# The Rust toolchain layer will get updated most frequently, but we could keep the system
# dependencies layer intact for much longer.

ARG RUST_TOOLCHAIN="1.32.0"
ARG TMP_BUILD_DIR=/tmp/build
ARG FIRECRACKER_SRC_DIR="/firecracker"
ARG FIRECRACKER_BUILD_DIR="$FIRECRACKER_SRC_DIR/build"
ARG CARGO_REGISTRY_DIR="$FIRECRACKER_BUILD_DIR/cargo_registry"
ARG CARGO_GIT_REGISTRY_DIR="$FIRECRACKER_BUILD_DIR/cargo_git_registry"

ENV CARGO_HOME=/usr/local/rust
ENV RUSTUP_HOME=/usr/local/rust
ENV PATH="$PATH:$CARGO_HOME/bin"
ENV CARGO_TARGET_DIR="$FIRECRACKER_BUILD_DIR/cargo_target"

# Install system dependecies
#
RUN apt-get update \
    && apt-get -y install --no-install-recommends \
        binutils-dev \
        cmake \
        curl \
        file \
        g++ \
        gcc \
        gcc-aarch64-linux-gnu \
        iperf3 \
        iproute2 \
        jq \
        libcurl4-openssl-dev \
        libdw-dev \
        libiberty-dev \
        libssl-dev \
        lsof \
        make \
        musl-tools \
        net-tools \
        openssh-client \
        pkgconf \
        python \
        python3 \
        python3-dev \
        python3-pip \
        python3-venv    \
        xz-utils \
        zlib1g-dev \
    && python3 -m pip install \
        setuptools \
        wheel \
    && python3 -m pip install \
        boto3 \
        nsenter \
        pycodestyle \
        pydocstyle \
        pylint \
        pytest \
        pytest-timeout \
        pyyaml \
        requests \
        requests-unixsocket \
        retry \
    # install cross-compiled fdt library
    && mkdir "$TMP_BUILD_DIR" \
    && cd "$TMP_BUILD_DIR" \
        && curl -LO http://ftp.de.debian.org/debian/pool/main/d/device-tree-compiler/libfdt-dev_1.4.7-3_arm64.deb \
        && ar x libfdt-dev_1.4.7-3_arm64.deb \
        && tar -xf data.tar.xz \
	&& cp usr/lib/aarch64-linux-gnu/libfdt.a /usr/lib/aarch64-linux-gnu/libfdt.a \
    && cd / \
    && rm -rf "$TMP_BUILD_DIR" \
    && rm -rf /var/lib/apt/lists/*

# Install the Rust toolchain
#
RUN mkdir "$TMP_BUILD_DIR" \
    && curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain "$RUST_TOOLCHAIN" \
        && rustup target add x86_64-unknown-linux-musl \
        && rustup target add aarch64-unknown-linux-musl \
        && rustup component add rustfmt \
        && rustup component add clippy-preview \
        && cd "$TMP_BUILD_DIR" \
            && cargo install cargo-kcov \
            && cargo kcov --print-install-kcov-sh | sh \
        && rm -rf "$CARGO_HOME/registry" \
        && ln -s "$CARGO_REGISTRY_DIR" "$CARGO_HOME/registry" \
        && rm -rf "$CARGO_HOME/git" \
        && ln -s "$CARGO_GIT_REGISTRY_DIR" "$CARGO_HOME/git" \
    && cd / \
    && rm -rf "$TMP_BUILD_DIR"
    
WORKDIR "$FIRECRACKER_SRC_DIR"

