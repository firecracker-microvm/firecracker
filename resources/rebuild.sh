#!/bin/bash
# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# fail if we encounter an error, uninitialized variable or a pipe breaks
set -eu -o pipefail

set -x
PS4='+\t '

cd $(dirname $0)
ARCH=$(uname -m)
OUTPUT_DIR=$PWD/$ARCH

# Make sure we have all the needed tools
function install_dependencies {
    sudo apt update
    sudo apt install -y bc flex bison gcc make libelf-dev libssl-dev squashfs-tools busybox-static tree cpio curl
}

function dir2ext4img {
    # ext4
    # https://unix.stackexchange.com/questions/503211/how-can-an-image-file-be-created-for-a-directory
    local DIR=$1
    local IMG=$2
    # Default size for the resulting rootfs image is 300M
    local SIZE=${3:-300M}
    local TMP_MNT=$(mktemp -d)
    truncate -s "$SIZE" "$IMG"
    mkfs.ext4 -F "$IMG"
    sudo mount "$IMG" "$TMP_MNT"
    sudo tar c -C $DIR . |sudo tar x -C "$TMP_MNT"
    # cleanup
    sudo umount "$TMP_MNT"
    rmdir $TMP_MNT
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
    mkdir -pv "$rootfs" "$OUTPUT_DIR"

    cp -rvf overlay/* $rootfs

    # curl -O https://cloud-images.ubuntu.com/minimal/releases/jammy/release/ubuntu-22.04-minimal-cloudimg-amd64-root.tar.xz
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
EOF

    # TBD what abt /etc/hosts?
    echo |sudo tee $rootfs/etc/resolv.conf

    # Generate key for ssh access from host
    if [ ! -s id_rsa ]; then
        ssh-keygen -f id_rsa -N ""
    fi
    sudo install -d -m 0600 "$rootfs/root/.ssh/"
    sudo cp id_rsa.pub "$rootfs/root/.ssh/authorized_keys"
    id_rsa=$OUTPUT_DIR/$ROOTFS_NAME.id_rsa
    sudo cp id_rsa $id_rsa

    # -comp zstd but guest kernel does not support
    rootfs_img="$OUTPUT_DIR/$ROOTFS_NAME.squashfs"
    sudo mv $rootfs/root/manifest $OUTPUT_DIR/$ROOTFS_NAME.manifest
    sudo mksquashfs $rootfs $rootfs_img -all-root -noappend
    rootfs_ext4=$OUTPUT_DIR/$ROOTFS_NAME.ext4
    dir2ext4img $rootfs $rootfs_ext4
    sudo rm -rf $rootfs
    sudo chown -Rc $USER. $OUTPUT_DIR
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


function get_linux_git {
    # git clone -s -b v$KV ../../linux
    # --depth 1
    cd linux
    LATEST_TAG=$(git tag -l "v$KV.*" --sort=v:refname |tail -1)
    git clean -fdx
    git checkout $LATEST_TAG
}


# Download the latest kernel source for the given kernel version
function get_linux_tarball {
    local KERNEL_VERSION=$1
    echo "Downloading the latest patch version for v$KERNEL_VERSION..."
    local major_version="${KERNEL_VERSION%%.*}"
    local url_base="https://cdn.kernel.org/pub/linux/kernel"
    local LATEST_VERSION=$(
        curl -fsSL $url_base/v$major_version.x/ \
        | grep -o "linux-$KERNEL_VERSION\.[0-9]*\.tar.xz" \
        | sort -rV \
        | head -n 1 || true)
    # Fetch tarball and sha256 checksum.
    curl -fsSLO "$url_base/v$major_version.x/sha256sums.asc"
    curl -fsSLO "$url_base/v$major_version.x/$LATEST_VERSION"
    # Verify checksum.
    grep "${LATEST_VERSION}" sha256sums.asc | sha256sum -c -
    echo "Extracting the kernel source..."
    tar -xaf $LATEST_VERSION
    local DIR=$(basename $LATEST_VERSION .tar.xz)
    ln -svfT $DIR linux
}

function build_linux {
    local KERNEL_CFG=$1
    # Extract the kernel version from the config file provided as parameter.
    local KERNEL_VERSION=$(grep -Po "^# Linux\/\w+ \K(\d+\.\d+)" "$KERNEL_CFG")

    get_linux_tarball $KERNEL_VERSION
    pushd linux

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
    cp "$KERNEL_CFG" .config

    make olddefconfig
    make -j $(nproc) $target
    LATEST_VERSION=$(cat include/config/kernel.release)
    flavour=$(basename $KERNEL_CFG .config |grep -Po "\d+\.\d+\K(-.*)" || true)
    OUTPUT_FILE=$OUTPUT_DIR/vmlinux-$LATEST_VERSION$flavour
    cp -v $binary_path $OUTPUT_FILE
    cp -v .config $OUTPUT_FILE.config
    popd &>/dev/null
}

#### main ####

install_dependencies

BIN=overlay/usr/local/bin
compile_and_install $BIN/init.c    $BIN/init
compile_and_install $BIN/fillmem.c $BIN/fillmem
compile_and_install $BIN/readmem.c $BIN/readmem
if [ $ARCH == "aarch64" ]; then
    compile_and_install $BIN/devmemread.c $BIN/devmemread
fi

# build_rootfs ubuntu-18.04 bionic
# build_rootfs ubuntu-20.04 focal
build_rootfs ubuntu-22.04 jammy

build_initramfs

build_linux $PWD/guest_configs/microvm-kernel-ci-$ARCH-4.14.config
build_linux $PWD/guest_configs/microvm-kernel-ci-$ARCH-5.10.config

if [ $ARCH == "aarch64" ]; then
    build_linux $PWD/guest_configs/microvm-kernel-ci-$ARCH-5.10-no-sve.config vmlinux-no-sve
fi

tree -h $OUTPUT_DIR
