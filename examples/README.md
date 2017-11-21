Boots a minimal kernel and busybox / small hello world program.
Tested with kernel 4.9.

# Prereq:
 * Linux kernel source code version 4.9 downloaded
 * busybox source code downloaded

# Linux config

 $ cp minimum_linux_kernel_config ~/git/linux-4.9/.config
 $ cp initramfs_list ~/git/linux-4.9/

# Busybox userland
 $ gcc -static init.c -o ~/git/linux-4.9/usr/init
 $ cd ~/git/busybox/
 $ make defconfig
 $ make clean && make -j8 LDFLAGS=-static # compile busybox statically
 $ mkdir -p ~/git/linux-4.9/usr/bin/ && cp busybox ~/git/linux-4.9/usr/bin/

# Hello world userland
 $ gcc -static hello.c -o ~/git/linux-4.9/usr/init

# Build the kernel
 $ cd ~/git/linux-4.9/
 $ make oldconfig
 $ make -j8


# Run
 $ cd ~/git/branciog-firecracker/
 $ cargo run -- -k ../linux-4.9/arch/x86/boot/compressed/vmlinux.bin

