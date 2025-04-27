#!/bin/bash
# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# fail if we encounter an error, uninitialized variable or a pipe breaks
set -eu -o pipefail

PS4='+\t '

cd $(dirname $0)
ARCH=$(uname -m)
OUTPUT_DIR=$PWD/$ARCH

GIT_ROOT_DIR=$(git rev-parse --show-toplevel)
source "$GIT_ROOT_DIR/tools/functions"

# Make sure we have all the needed tools
function install_dependencies {
    apt update
    apt install -y bc flex bison gcc make libelf-dev libssl-dev squashfs-tools busybox-static tree cpio curl patch docker.io
}

function prepare_docker {
    nohup /usr/bin/dockerd --host=unix:///var/run/docker.sock --host=tcp://127.0.0.1:2375 &

    # Wait for Docker socket to be created
    timeout 15 sh -c "until docker info; do echo .; sleep 1; done"
}

function compile_and_install {
    local C_FILE=$1
    local BIN_FILE=$2
    local OUTPUT_DIR=$(dirname $BIN_FILE)
    mkdir -pv $OUTPUT_DIR
    gcc -Wall -o $BIN_FILE $C_FILE
}

# Build a rootfs
function build_rootfs {
    local ROOTFS_NAME=$1
    local flavour=${2}
    local FROM_CTR=public.ecr.aws/ubuntu/ubuntu:$flavour
    local rootfs="tmp_rootfs"
    mkdir -pv "$rootfs"

    # Launch Docker
    prepare_docker

    cp -rvf overlay/* $rootfs

    # curl -O https://cloud-images.ubuntu.com/minimal/releases/noble/release/ubuntu-24.04-minimal-cloudimg-amd64-root.tar.xz
    #
    # TBD use systemd-nspawn instead of Docker
    #   sudo tar xaf ubuntu-22.04-minimal-cloudimg-amd64-root.tar.xz -C $rootfs
    #   sudo systemd-nspawn --resolv-conf=bind-uplink -D $rootfs
    docker run --env rootfs=$rootfs --privileged --rm -i -v "$PWD:/work" -w /work "$FROM_CTR" bash -s <<'EOF'

./chroot.sh

# Copy everything we need to the bind-mounted rootfs image file
dirs="bin etc home lib lib64 root sbin usr"
for d in $dirs; do tar c "/$d" | tar x -C $rootfs; done

# Make mountpoints
mkdir -pv $rootfs/{dev,proc,sys,run,tmp,var/lib/systemd}
# So apt works
mkdir -pv $rootfs/var/lib/dpkg/
EOF

    # TBD what abt /etc/hosts?
    echo | tee $rootfs/etc/resolv.conf

    rootfs_img="$OUTPUT_DIR/$ROOTFS_NAME.squashfs"
    mv $rootfs/root/manifest $OUTPUT_DIR/$ROOTFS_NAME.manifest
    mksquashfs $rootfs $rootfs_img -all-root -noappend -comp zstd
    rm -rf $rootfs
    for bin in fast_page_fault_helper fillmem init readmem; do
        rm $PWD/overlay/usr/local/bin/$bin
    done
    rm -f nohup.out
}


# https://wiki.gentoo.org/wiki/Custom_Initramfs#Busybox
function build_initramfs {
    INITRAMFS_BUILD=initramfs
    mkdir -p $INITRAMFS_BUILD
    pushd $INITRAMFS_BUILD
    mkdir bin dev proc sys
    cp /bin/busybox bin/sh
    ln bin/sh bin/mount

    # Report guest boot time back to Firecracker via MMIO
    # See arch/src/lib.rs and the BootTimer device
    MAGIC_BOOT_ADDRESS=0xd0000000
    if [ $ARCH = "aarch64" ]; then
        MAGIC_BOOT_ADDRESS=0x40000000
    fi
    MAGIC_BOOT_VALUE=123
    cat > init <<EOF
#!/bin/sh
mount -t devtmpfs devtmpfs /dev
mount -t proc none /proc
devmem $MAGIC_BOOT_ADDRESS 8 $MAGIC_BOOT_VALUE
mount -t sysfs none /sys
exec 0</dev/console
exec 1>/dev/console
exec 2>/dev/console

echo Boot took $(cut -d' ' -f1 /proc/uptime) seconds
echo ">>> Welcome to fcinitrd <<<"

exec /bin/sh
EOF
    chmod +x init

    find . -print0 |cpio --null -ov --format=newc -R 0:0 > $OUTPUT_DIR/initramfs.cpio
    popd
    rm -rf $INITRAMFS_BUILD
}

function clone_amazon_linux_repo {
    [ -d linux ] || git clone --no-checkout --filter=tree:0 https://github.com/amazonlinux/linux
}

# prints the git tag corresponding to the newest and best matching the provided kernel version $1
# this means that if a microvm kernel exists, the tag returned will be of the form
#
#    microvm-kernel-$1.<patch number>.amzn2[023]
#
# otherwise choose the newest tag matching
#
#    kernel-$1.<patch number>.amzn2[023]
function get_tag {
    local KERNEL_VERSION=$1

    # list all tags from newest to oldest
    (git --no-pager tag -l --sort=-creatordate | grep "microvm-kernel-$1\..*\.amzn2" \
        || git --no-pager tag -l --sort=-creatordate | grep "kernel-$1\..*\.amzn2") | head -n1
}

function build_al_kernel {
    local KERNEL_CFG=$1
    # Extract the kernel version from the config file provided as parameter.
    local KERNEL_VERSION=$(echo $KERNEL_CFG | grep -Po "microvm-kernel-ci-$ARCH-\K(\d+\.\d+)")

    pushd linux
    # fails immediately after clone because nothing is checked out
    make distclean || true

    git checkout $(get_tag $KERNEL_VERSION)

    arch=$(uname -m)
    if [ "$arch" = "x86_64" ]; then
        format="elf"
        target="vmlinux"
        binary_path="$target"
    elif [ "$arch" = "aarch64" ]; then
        format="pe"
        target="Image"
        binary_path="arch/arm64/boot/$target"
    else
        echo "FATAL: Unsupported architecture!"
        exit 1
    fi
    # Concatenate all config files into one. olddefconfig will then resolve
    # as needed. Later values override earlier ones.
    cat "$@" >.config
    make olddefconfig
    make -j $(nproc) $target
    LATEST_VERSION=$(cat include/config/kernel.release)
    flavour=$(basename $KERNEL_CFG .config |grep -Po "\d+\.\d+\K(-.*)" || true)
    # Strip off everything after the last number - sometimes AL kernels have some stuff there.
    # e.g. vmlinux-4.14.348-openela -> vmlinux-4.14.348
    normalized_version=$(echo "$LATEST_VERSION" | sed -E "s/(.*[[:digit:]]).*/\1/g")
    OUTPUT_FILE=$OUTPUT_DIR/vmlinux-$normalized_version$flavour
    cp -v $binary_path $OUTPUT_FILE
    cp -v .config $OUTPUT_FILE.config

    popd &>/dev/null
}

function prepare_and_build_rootfs {
    BIN=overlay/usr/local/bin
    compile_and_install $BIN/init.c $BIN/init
    compile_and_install $BIN/fillmem.c $BIN/fillmem
    compile_and_install $BIN/fast_page_fault_helper.c $BIN/fast_page_fault_helper
    compile_and_install $BIN/readmem.c $BIN/readmem
    if [ $ARCH == "aarch64" ]; then
        compile_and_install $BIN/devmemread.c $BIN/devmemread
    fi

    build_rootfs ubuntu-24.04 noble
    build_initramfs
}

function vmlinux_split_debuginfo {
    VMLINUX="$1"
    DEBUGINFO="$VMLINUX.debug"
    VMLINUX_ORIG="$VMLINUX"
    if [ $ARCH = "aarch64" ]; then
        # in aarch64, the debug info is in vmlinux
        VMLINUX_ORIG=linux/vmlinux
    fi
    objcopy --only-keep-debug $VMLINUX_ORIG $DEBUGINFO
    objcopy --preserve-dates --strip-debug --add-gnu-debuglink=$DEBUGINFO $VMLINUX
    # gdb does not support compressed files, but compress them because they are huge
    gzip -v $DEBUGINFO
}

function build_al_kernels {
    if [[ $# = 0 ]]; then
        local KERNEL_VERSION="all"
    elif [[ $# -ne 1 ]]; then
        die "Too many arguments in '$(basename $0) kernels' command. Please use \`$0 help\` for help."
    else
        KERNEL_VERSION=$1
        if [[ "$KERNEL_VERSION" != @(5.10|5.10-no-acpi|6.1) ]]; then
            die "Unsupported kernel version: '$KERNEL_VERSION'. Please use \`$0 help\` for help."
        fi
    fi

    clone_amazon_linux_repo

    CI_CONFIG="$PWD/guest_configs/ci.config"

    if [[ "$KERNEL_VERSION" == @(all|5.10) ]]; then
        build_al_kernel $PWD/guest_configs/microvm-kernel-ci-$ARCH-5.10.config "$CI_CONFIG"
    fi
    if [[ $ARCH == "x86_64" && "$KERNEL_VERSION" == @(all|5.10-no-acpi) ]]; then
        build_al_kernel $PWD/guest_configs/microvm-kernel-ci-$ARCH-5.10-no-acpi.config "$CI_CONFIG"
    fi
    if [[ "$KERNEL_VERSION" == @(all|6.1) ]]; then
        build_al_kernel $PWD/guest_configs/microvm-kernel-ci-$ARCH-6.1.config "$CI_CONFIG"
    fi

    # Build debug kernels
    FTRACE_CONFIG="$PWD/guest_configs/ftrace.config"
    DEBUG_CONFIG="$PWD/guest_configs/debug.config"
    OUTPUT_DIR=$OUTPUT_DIR/debug
    mkdir -pv $OUTPUT_DIR
    if [[ "$KERNEL_VERSION" == @(all|5.10) ]]; then
        build_al_kernel "$PWD/guest_configs/microvm-kernel-ci-$ARCH-5.10.config" "$CI_CONFIG" "$FTRACE_CONFIG" "$DEBUG_CONFIG"
        vmlinux_split_debuginfo $OUTPUT_DIR/vmlinux-5.10.*
    fi
    if [[ "$KERNEL_VERSION" == @(all|6.1) ]]; then
        build_al_kernel "$PWD/guest_configs/microvm-kernel-ci-$ARCH-6.1.config" "$CI_CONFIG" "$FTRACE_CONFIG" "$DEBUG_CONFIG"
        vmlinux_split_debuginfo $OUTPUT_DIR/vmlinux-6.1.*
    fi
}

function print_help {
    cat <<EOF
Firecracker CI artifacts build script

Usage: $(basename $0) [<command>] [<command args>]

Available commands:

    all (default)
        Build CI rootfs and default guest kernels using configurations from
        resources/guest_configs.
        This will patch the guest configurations with all the patches under
        resources/guest_configs/patches.
        This is the default command, if no command is chosen.

    rootfs
        Builds only the CI rootfs.

    kernels [version]
        Builds our the currently supported CI kernels.

        version: Optionally choose a kernel version to build. Supported
                 versions are: 5.10, 5.10-no-acpi or 6.1.

    help
        Displays the help message and exits.
EOF
}

function main {
    if [[ $# = 0 ]]; then
        local MODE="all"
    else
        case $1 in
            all|rootfs|kernels)
                local MODE=$1
                shift
                ;;
            help)
                print_help
                exit 0
                ;;
            *)
                die "Unknown command: '$1'. Please use \`$0 help\` for help."
        esac
    fi

    set -x

    install_dependencies

    # Create the directory in which we will store the kernels and rootfs
    mkdir -pv $OUTPUT_DIR

    if [[ "$MODE" =~ (all|rootfs) ]]; then
        say "Building rootfs"
        prepare_and_build_rootfs
    fi

    if [[ "$MODE" =~ (all|kernels) ]]; then
        say "Building CI kernels"
        build_al_kernels "$@"
    fi

    tree -h $OUTPUT_DIR
}

main "$@"
