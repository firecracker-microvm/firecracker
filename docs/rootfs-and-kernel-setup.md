# Creating Custom rootfs and kernel Images

## Creating a kernel Image

### Manual compilation

Currently, Firecracker supports uncompressed ELF kernel images on x86_64 while on
aarch64 it supports PE formatted images.

Here's a quick step-by-step guide to building your own kernel that Firecracker
can boot:

1. Get the Linux source code:

   ```bash
   git clone https://github.com/torvalds/linux.git linux.git
   cd linux.git
   ```

1. Check out the Linux version you want to build (e.g. we'll be using v4.20
   here):

   ```bash
   git checkout v4.20
   ```

1. You will need to configure your Linux build. You can start from our
   recommended  [guest kernel configurations](../resources/guest_configs/)
   by copying the relevant one to `.config` (under the Linux sources dir).
   You can make interactive config adjustments using:

   ```bash
   make menuconfig
   ```

   *Note*: there are many ways of building a kernel config file, other than
   `menuconfig`. You are free to use whichever one you choose.

1. Build the kernel image:

   ```bash
   arch=$(uname -m)
   if [ "$arch" = "x86_64" ]; then
        make vmlinux
   elif [ "$arch" = "aarch64" ]; then
        make Image
   fi
   ```

1. Upon a successful build, you can find the kernel image under `./vmlinux`
   (for x86) or `./arch/arm64/boot/Image` (for aarch64).

For a list of currently supported kernel versions, check out the
[kernel support policy](kernel-policy.md).

### Use the provided recipe

The kernel images used in our CI to test Firecracker's features are obtained by
using the recipe inside devtool:

```bash
config="resources/guest_configs/microvm-kernel-x86_64-4.14.config"
./tools/devtool build_kernel -c $config -n 8
```

or

```bash
config="resources/guest_configs/microvm-kernel-arm64-4.14.config"
./tools/devtool build_kernel -c $config -n 8
```

on an aarch64 machine.

## Creating a rootfs Image

A rootfs image is just a file system image, that hosts at least an init system.
For instance, our getting started guide uses an ext4 filesystem image. Note
that, whichever file system you choose to use, support for it will have to be
compiled into the kernel, so it can be mounted at boot time.

In order to obtain an ext4 image that you can use with Firecracker, you have the
following options:

### Manual build

1. Prepare a properly-sized file. We'll use 50MiB here, but this depends
   on how much data you'll want to fit inside:

   ```bash
   dd if=/dev/zero of=rootfs.ext4 bs=1M count=50
   ```

1. Create an empty file system on the file you created:

   ```bash
   mkfs.ext4 rootfs.ext4
   ```

You now have an empty EXT4 image in `rootfs.ext4`, so let's prepare to
populate it. First, you'll need to mount this new file system, so you
can easily access its contents:

```bash
mkdir /tmp/my-rootfs
sudo mount rootfs.ext4 /tmp/my-rootfs
```

The minimal init system would be just an ELF binary, placed at `/sbin/init`.
The final step in the Linux boot process executes `/sbin/init` and expects it
to never exit. More complex init systems build on top of this, providing
service configuration files, startup / shutdown scripts for various services,
and many other features.

For the sake of simplicity, let's set up an Alpine-based rootfs, with OpenRC
as an init system. To that end, we'll use the official Docker image for
Alpine Linux:

1. First, let's start the Alpine container, bind-mounting the EXT4 image
   created earlier, to `/my-rootfs`:

   ```bash
   docker run -it --rm -v /tmp/my-rootfs:/my-rootfs alpine
   ```

1. Then, inside the container, install the OpenRC init system, and some basic
   tools:

   ```bash
   apk add openrc
   apk add util-linux
   ```

1. And set up userspace init (still inside the container shell):

   ```bash
   # Set up a login terminal on the serial console (ttyS0):
   ln -s agetty /etc/init.d/agetty.ttyS0
   echo ttyS0 > /etc/securetty
   rc-update add agetty.ttyS0 default

   # Make sure special file systems are mounted on boot:
   rc-update add devfs boot
   rc-update add procfs boot
   rc-update add sysfs boot

   # Then, copy the newly configured system to the rootfs image:
   for d in bin etc lib root sbin usr; do tar c "/$d" | tar x -C /my-rootfs; done

   # The above command may trigger the following message:
   # tar: Removing leading "/" from member names
   # However, this is just a warning, so you should be able to
   # proceed with the setup process.

   for dir in dev proc run sys var; do mkdir /my-rootfs/${dir}; done

   # All done, exit docker shell.
   exit
   ```

1. Finally, unmount your rootfs image:

   ```bash
   sudo umount /tmp/my-rootfs
   ```

### Use the provided recipe

The disk images used in our CI to test Firecracker's features are obtained by
using the recipe (in a Ubuntu 22.04 host):

```bash
./resources/rebuild.sh
```

The images resulting using this method are minimized Ubuntu 22.04. Feel free to
adjust the script(s) to suit your use case.

You should now have a kernel image (`vmlinux`) and a rootfs image
(`rootfs.ext4`), that you can boot with Firecracker.
