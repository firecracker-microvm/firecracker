# PVH boot mode

Firecracker supports booting x86 kernels in "PVH direct boot" mode
[as specified by the Xen project](https://github.com/xen-project/xen/blob/master/docs/misc/pvh.pandoc).
If a kernel is provided which contains the XEN_ELFNOTE_PHYS32_ENTRY ELF Note
then this boot mode will be used. This boot mode was designed for virtualized
environments which load the kernel directly, and is simpler than the "Linux
boot" mode which is designed to be launched from a legacy boot loader.

PVH boot mode can be enabled for Linux by setting `CONFIG_PVH=y` in the kernel
configuration. (This is not the default setting.)

PVH boot mode is enabled by default in FreeBSD, which has support for
Firecracker starting with FreeBSD 14.0. Instructions on building a FreeBSD
kernel and root filesystem are available [here](rootfs-and-kernel-setup.md).
