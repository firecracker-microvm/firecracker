#!/usr/bin/bash
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

# Container runtime detection (Docker or Podman)
detect_container_runtime() {
    if command -v docker &>/dev/null && docker info &>/dev/null; then
        echo "docker"
    elif command -v podman &>/dev/null; then
        echo "podman"
    else
        echo ""
    fi
}

# Detect the host OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo $ID
    else
        echo $(uname -s | tr '[:upper:]' '[:lower:]')
    fi
}

# Get container runtime
CONTAINER_RUNTIME=$(detect_container_runtime)
if [ -z "$CONTAINER_RUNTIME" ]; then
    say "Warning: Neither Docker nor Podman found. Some features may not work."
fi

# Generate an incremental name for directories/files to avoid conflicts
function getIncName {
    local base_name="$1"
    local counter=0
    local name="$base_name"
    
    while [ -e "$name" ]; do
        counter=$((counter + 1))
        name="${base_name}_${counter}"
    done
    
    echo "$name"
}

# Check if we can use fakeroot to reduce sudo usage
function check_fakeroot_support {
    if command -v fakeroot &>/dev/null; then
        echo "fakeroot"
    else
        echo ""
    fi
}

# Create ext4 image from directory (more robust than the previous version)
function dir2ext4img {
    local DIR=$1
    local IMG=$2
    local SIZE="${3}M"  # Append M to the size, to specify the size in MB
    local TMP_MNT=$(mktemp -d)

    # Create the image file
    truncate -s "$SIZE" "$IMG"
    mkfs.ext4 -F "$IMG"
    
    # SUDO NEEDED: Only root can mount filesystems
    sudo mount "$IMG" "$TMP_MNT"
    # SUDO NEEDED: Copy files preserving ownership (container files are root-owned)
    sudo tar c -C "$DIR" . | sudo tar x -C "$TMP_MNT"
    # SUDO NEEDED: Only root can unmount filesystems
    sudo umount "$TMP_MNT"
    rmdir "$TMP_MNT"
    
    # SUDO NEEDED: Fix ownership of the created image file
    sudo chown $USER: "$IMG"
    
    say "Created ext4 image: $IMG (${SIZE})"
}

# Make sure we have all the needed tools
function install_dependencies {
    # Check if we're already inside nix-shell (like rebuild-kernal.sh does)
    if [ -n "${IN_NIX_SHELL:-}" ]; then
        say "Already inside nix-shell, skipping dependency installation"
        return
    fi
    
    # Detect OS for package manager selection
    local os=$(detect_os)
    
    case $os in
        ubuntu|debian)
            apt update
            apt install -y bc flex bison gcc make libelf-dev libssl-dev squashfs-tools busybox-static tree cpio curl patch
            
            # Install container runtime if not present
            if [ -z "$CONTAINER_RUNTIME" ]; then
                say "Installing Docker as no container runtime was found"
                apt install -y docker.io
                CONTAINER_RUNTIME="docker"
            fi
            ;;
        fedora|centos)
            if command -v dnf &>/dev/null; then
                dnf install -y bc flex bison gcc make elfutils-libelf-devel openssl-devel squashfs-tools busybox tree cpio curl patch
                if [ -z "$CONTAINER_RUNTIME" ]; then
                    dnf install -y docker
                    CONTAINER_RUNTIME="docker"
                fi
            else
                yum install -y bc flex bison gcc make elfutils-libelf-devel openssl-devel squashfs-tools busybox tree cpio curl patch
                if [ -z "$CONTAINER_RUNTIME" ]; then
                    yum install -y docker
                    CONTAINER_RUNTIME="docker"
                fi
            fi
            ;;
        arch)
            # Arch Linux package installation
            say "Installing dependencies for Arch Linux"
            pacman -Sy --noconfirm bc flex bison gcc make libelf openssl squashfs-tools busybox tree cpio curl patch
            
            # Install container runtime if not present
            if [ -z "$CONTAINER_RUNTIME" ]; then
                say "Installing Docker as no container runtime was found"
                pacman -S --noconfirm docker
                systemctl enable docker
                systemctl start docker
                CONTAINER_RUNTIME="docker"
            fi
            ;;
        nixos)
            # NixOS package installation - use the same approach as rebuild-kernal.sh
            say "Installing dependencies for NixOS"
            # Create a temporary nix expression
            NIX_TEMP=$(mktemp)
            trap 'rm -f "$NIX_TEMP"' EXIT
            
            cat > "$NIX_TEMP" <<'EOF'
with import <nixpkgs> {};
mkShell {
  buildInputs = [
    bc flex bison gcc gnumake elfutils openssl
    squashfsTools busybox tree cpio curl docker
  ];
}
EOF
            # Execute nix-shell with our temporary expression
            exec nix-shell "$NIX_TEMP" --run "exec $0 $*"
            ;;
        *)
            say "Warning: Unknown OS '$os'. Please install dependencies manually:"
            say "Required packages: bc flex bison gcc make libelf-dev openssl-dev squashfs-tools busybox tree cpio curl patch docker"
            say "Try installing these packages using your system's package manager."
            die "Unsupported OS '$os'. Please install dependencies manually and re-run the script."
            ;;
    esac

    # Install Go if not present
    if ! command -v go &>/dev/null; then
        say "Installing Go"
        version=$(curl -s https://go.dev/VERSION?m=text | head -n 1)
        case $ARCH in
            x86_64) archive="${version}.linux-amd64.tar.gz" ;;
            aarch64) archive="${version}.linux-arm64.tar.gz" ;;
        esac
        curl -LO http://go.dev/dl/${archive}
        tar -C /usr/local -xzf $archive
        export PATH=$PATH:/usr/local/go/bin
        go version
        rm $archive
    else
        say "Go already installed: $(go version)"
    fi
}

function prepare_container_runtime {
    if [ "$CONTAINER_RUNTIME" = "docker" ]; then
        nohup /usr/bin/dockerd --host=unix:///var/run/docker.sock --host=tcp://127.0.0.1:2375 &
        # Wait for Docker socket to be created
        timeout 15 sh -c "until docker info; do echo .; sleep 1; done"
    elif [ "$CONTAINER_RUNTIME" = "podman" ]; then
        # Podman doesn't need a daemon, but ensure it's working
        podman info >/dev/null || die "Podman is not working properly"
    else
        die "No container runtime available. Please install Docker or Podman."
    fi
}

function compile_and_install {
    local SRC=$1
    local BIN="${SRC%.*}"
    if [[ $SRC == *.c ]]; then
        gcc -Wall -o $BIN $SRC
    elif [[ $SRC == *.go ]]; then
        pushd $SRC
        local MOD=$(basename $BIN)
        go mod init $MOD
        go mod tidy
        go build -o ../$MOD
        rm go.mod go.sum
        popd
    fi
}

# Build a rootfs
function build_rootfs {
    local ROOTFS_NAME=${1:-"ubuntu-24.04"}
    local flavour=${2:-"noble"}
    local format=${3:-"squashfs"}  # squashfs or ext4
    local filesize_mb=${4:-2048}   # Default 2GB for ext4
    local custom_output_dir=${5:-""}
    
    # Support both docker.io/library/ and public.ecr.aws formats
    local FROM_CTR
    if [[ "$flavour" =~ ^[0-9]+$ ]]; then
        # Numeric version, use docker.io format
        FROM_CTR="docker.io/library/ubuntu:$flavour"
    else
        # Named version, use ECR format
        FROM_CTR="public.ecr.aws/ubuntu/ubuntu:$flavour"
    fi
    
    local rootfs=$(getIncName "tmp_rootfs")
    local actual_output_dir=${custom_output_dir:-$OUTPUT_DIR}
    
    mkdir -pv "$rootfs"
    mkdir -pv "$actual_output_dir"

    # Launch container runtime
    prepare_container_runtime

    cp -rvf overlay/* $rootfs

    # curl -O https://cloud-images.ubuntu.com/minimal/releases/noble/release/ubuntu-24.04-minimal-cloudimg-amd64-root.tar.xz
    #
    # TBD use systemd-nspawn instead of Docker
    #   sudo tar xaf ubuntu-22.04-minimal-cloudimg-amd64-root.tar.xz -C $rootfs
    #   sudo systemd-nspawn --resolv-conf=bind-uplink -D $rootfs

    # Use detected container runtime
    $CONTAINER_RUNTIME run --env rootfs=$rootfs --privileged --rm -i -v "$PWD:/work" -w /work "$FROM_CTR" bash -s <<'EOF'

./chroot.sh

# Copy everything we need to the bind-mounted rootfs image file
dirs="bin etc home lib lib64 root sbin usr"
for d in $dirs; do tar c "/$d" | tar x -C $rootfs; done

# Make mountpoints
mkdir -pv $rootfs/{dev,proc,sys,run,tmp,var/lib/systemd}
EOF

    # TBD what abt /etc/hosts?
    echo | tee $rootfs/etc/resolv.conf >/dev/null

    # Generate SSH key for root access from host
    if [ ! -s id_rsa ]; then
        say "Generating SSH key for root access"
        ssh-keygen -f id_rsa -N "" -C "firecracker-rootfs-$(date +%Y%m%d)"
    fi
    
    # Create SSH directory and setup keys (minimize sudo usage)
    mkdir -p "$rootfs/root/.ssh/"
    cp id_rsa.pub "$rootfs/root/.ssh/authorized_keys"
    chmod 700 "$rootfs/root/.ssh/"
    chmod 600 "$rootfs/root/.ssh/authorized_keys"
    
    # Copy SSH private key to output directory (no sudo needed initially)
    local id_rsa_output="$actual_output_dir/$ROOTFS_NAME.id_rsa"
    cp id_rsa "$id_rsa_output"
    chmod 600 "$id_rsa_output"
    say "SSH private key saved: $id_rsa_output"

    # Move manifest if it exists (no sudo needed for move)
    if [ -f "$rootfs/root/manifest" ]; then
        mv "$rootfs/root/manifest" "$actual_output_dir/$ROOTFS_NAME.manifest"
    else
        say "Warning: Manifest file not found at $rootfs/root/manifest"
    fi

    if [ "$format" = "ext4" ]; then
        # Create ext4 image using the improved function (sudo only where needed)
        rootfs_img="$actual_output_dir/$ROOTFS_NAME.ext4"
        dir2ext4img "$rootfs" "$rootfs_img" "$filesize_mb"
    else
        # Create squashfs image (sudo only for mksquashfs)
        rootfs_img="$actual_output_dir/$ROOTFS_NAME.squashfs"
        
        # SUDO NEEDED: mksquashfs with -all-root requires root privileges to set 
        # correct file ownership in the guest filesystem image
        local MKSQUASHFS=$(which mksquashfs)
        sudo "$MKSQUASHFS" "$rootfs" "$rootfs_img" -all-root -noappend -comp zstd
        say "Created squashfs rootfs: $rootfs_img"
        
        # SUDO NEEDED: Fix ownership of the image file created by root
        sudo chown $USER: "$rootfs_img"
    fi
    
    # SUDO NEEDED: Remove container-created files which are owned by root
    # (Docker/Podman containers run as root and create root-owned files)
    sudo rm -rf "$rootfs"
    rm -f nohup.out
    
    # SUDO NEEDED: Fix ownership of any files that might have been created with root ownership
    if [ -f "$actual_output_dir/$ROOTFS_NAME.manifest" ]; then
        sudo chown $USER: "$actual_output_dir/$ROOTFS_NAME.manifest" 2>/dev/null || true
    fi
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
    MAGIC_BOOT_ADDRESS=0xc0000000
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
    local rootfs_name=${1:-"ubuntu-24.04"}
    local distro=${2:-"ubuntu"}
    local version=${3:-"noble"}
    local format=${4:-"squashfs"}
    local filesize_mb=${5:-2048}
    local custom_output_dir=${6:-""}
    
    BIN_DIR=overlay/usr/local/bin

    SRCS=(init.c fillmem.c fast_page_fault_helper.c readmem.c go_sdk_cred_provider.go go_sdk_cred_provider_with_custom_endpoint.go)
    if [ $ARCH == "aarch64" ]; then
        SRCS+=(devmemread.c)
    fi

    for SRC in ${SRCS[@]}; do
        compile_and_install $BIN_DIR/$SRC
    done

    build_rootfs "$rootfs_name" "$version" "$format" "$filesize_mb" "$custom_output_dir"
    
    # Only build initramfs for default builds
    if [ -z "$custom_output_dir" ]; then
        build_initramfs
    fi

    for SRC in ${SRCS[@]}; do
        BIN="${SRC%.*}"
        rm $BIN_DIR/$BIN
    done
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
    PCIE_CONFIG="$PWD/guest_configs/pcie.config"

    if [[ "$KERNEL_VERSION" == @(all|5.10) ]]; then
        build_al_kernel $PWD/guest_configs/microvm-kernel-ci-$ARCH-5.10.config "$CI_CONFIG" "$PCIE_CONFIG"
    fi
    if [[ $ARCH == "x86_64" && "$KERNEL_VERSION" == @(all|5.10-no-acpi) ]]; then
        build_al_kernel $PWD/guest_configs/microvm-kernel-ci-$ARCH-5.10-no-acpi.config "$CI_CONFIG" "$PCIE_CONFIG"
    fi
    if [[ "$KERNEL_VERSION" == @(all|6.1) ]]; then
        build_al_kernel $PWD/guest_configs/microvm-kernel-ci-$ARCH-6.1.config "$CI_CONFIG" "$PCIE_CONFIG"
    fi

    # Build debug kernels
    FTRACE_CONFIG="$PWD/guest_configs/ftrace.config"
    DEBUG_CONFIG="$PWD/guest_configs/debug.config"
    OUTPUT_DIR=$OUTPUT_DIR/debug
    mkdir -pv $OUTPUT_DIR
    if [[ "$KERNEL_VERSION" == @(all|5.10) ]]; then
        build_al_kernel "$PWD/guest_configs/microvm-kernel-ci-$ARCH-5.10.config" "$CI_CONFIG" "$PCIE_CONFIG" "$FTRACE_CONFIG" "$DEBUG_CONFIG"
        vmlinux_split_debuginfo $OUTPUT_DIR/vmlinux-5.10.*
    fi
    if [[ "$KERNEL_VERSION" == @(all|6.1) ]]; then
        build_al_kernel "$PWD/guest_configs/microvm-kernel-ci-$ARCH-6.1.config" "$CI_CONFIG" "$PCIE_CONFIG" "$FTRACE_CONFIG" "$DEBUG_CONFIG"
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

    rootfs [name] [distro] [version] [format] [size_mb] [output_dir]
        Builds only the CI rootfs with optional customization.
        
        name:       Rootfs name (default: ubuntu-24.04)
        distro:     Distribution (default: ubuntu)
        version:    Version/codename (default: noble)
        format:     Output format: squashfs or ext4 (default: squashfs)
        size_mb:    Size in MB for ext4 format (default: 2048)
        output_dir: Custom output directory (default: current/arch)
        
        Note: Automatically generates SSH key for root access and avoids
              naming conflicts using incremental naming.

    kernels [version]
        Builds our the currently supported CI kernels.

        version: Optionally choose a kernel version to build. Supported
                 versions are: 5.10, 5.10-no-acpi or 6.1.

    help
        Displays the help message and exits.

Examples:
    $(basename $0)                                          # Build everything (default)
    $(basename $0) rootfs                                   # Build default rootfs only
    $(basename $0) rootfs myapp ubuntu noble ext4 4096     # Custom ext4 rootfs (4GB)
    $(basename $0) kernels 6.1                            # Build only 6.1 kernel

Container Runtime:
    Automatically detects and uses Docker or Podman.
    Current runtime: ${CONTAINER_RUNTIME:-"none detected"}

Supported Operating Systems:
    - Ubuntu/Debian (apt)
    - Fedora/RHEL/CentOS (dnf/yum)
    - Arch Linux (pacman)
    - NixOS (nix-env/nix profile)
EOF
}

function main {
    if [[ $# = 0 ]]; then
        local MODE="all"
    else
        case $1 in
            all)
                local MODE=$1
                shift
                ;;
            rootfs)
                local MODE=$1
                shift
                # Parse optional rootfs arguments
                local ROOTFS_NAME=${1:-"ubuntu-24.04"}
                local DISTRO=${2:-"ubuntu"}
                local VERSION=${3:-"noble"}
                local FORMAT=${4:-"squashfs"}
                local SIZE_MB=${5:-2048}
                local CUSTOM_OUTPUT_DIR=${6:-""}
                
                # Validate format
                if [[ "$FORMAT" != "squashfs" && "$FORMAT" != "ext4" ]]; then
                    die "Invalid format '$FORMAT'. Supported formats: squashfs, ext4"
                fi
                
                # Validate size for ext4
                if [[ "$FORMAT" == "ext4" && ! "$SIZE_MB" =~ ^[0-9]+$ ]]; then
                    die "Invalid size '$SIZE_MB'. Size must be a number (MB)"
                fi
                
                # Validate size minimum
                if [[ "$FORMAT" == "ext4" && "$SIZE_MB" -lt 100 ]]; then
                    die "Size too small: ${SIZE_MB}MB. Minimum size for ext4 is 100MB"
                fi
                ;;
            kernels)
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
        if [ "$MODE" = "rootfs" ]; then
            # Custom rootfs build with parameters
            prepare_and_build_rootfs "$ROOTFS_NAME" "$DISTRO" "$VERSION" "$FORMAT" "$SIZE_MB" "$CUSTOM_OUTPUT_DIR"
        else
            # Default all build
            prepare_and_build_rootfs
        fi
    fi

    if [[ "$MODE" =~ (all|kernels) ]]; then
        say "Building CI kernels"
        build_al_kernels "$@"
    fi

    if [ -z "$CUSTOM_OUTPUT_DIR" ]; then
        tree -h $OUTPUT_DIR
    else
        tree -h "$CUSTOM_OUTPUT_DIR"
        tree -h $OUTPUT_DIR
    fi
}

main "$@"
