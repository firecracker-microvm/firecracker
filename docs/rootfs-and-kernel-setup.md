# Creating Custom rootfs and kernel Images

## Creating a kernel Image

Currently, Firecracker supports only uncompressed, ELF kernel images. You can
build an uncompressed Linux kernel image with:

```bash
make vmlinux
```

Here's a quick step-by-step guide to building your own kernel that Firecracker
can boot:
1. Get the Linux source code:

   ```bash
   git clone https://github.com/torvalds/linux.git linux.git
   cd linux.git
   ```

2. Check out the Linux version you want to build (e.g. we'll be using v4.20
   here):

   ```bash
   git checkout v4.20
   ```

3. You will need to configure your Linux build. You can start from
   [our recommended config](../resources/microvm-kernel-config) - just copy
   it to `.config` (under the Linux sources dir). You can make interactive
   config adjustments using:

   ```bash
   make menuconfig
   ```

   *Note*: there are many ways of building a kernel config file, other than
   `menuconfig`. You are free to use whichever one you choose.

4. Build the uncompressed kernel image:

   ```bash
   make vmlinux
   ```

5. Upon a successful build, you can find the uncompressed kernel image under
   `./vmlinux`.


## Creating a rootfs Image

A rootfs image is just a file system image, that hosts at least an init
system. For instance, our getting started guide uses an EXT4 FS image with
OpenRC as an init system. Note that, whichever file system you choose to use,
support for it will have to be compiled into the kernel, so it can be mounted
at boot time.

There are many ways to build rootfs images, multiple tools and techniques can be found with a simple online search.  Here is one way do to it, by using the Firecracker `rfstool` to build a minimal test image.

1. From the root of the Firecracker repo, run the following:

   ```bash
   ./tools/rfstool build
   ```
   Download the docker image when prompted, and the build should progress.
   ```bash
   [Firecracker rfstool] Starting rootfs minimal build ...
   [   0.0] Examining the guest ...
   [  38.5] Setting a random seed
   virt-customize: warning: random seed could not be set for this type of
   guest
   [  38.9] Installing packages: ca-certificates
   [  51.1] Installing packages: curl
   [  63.0] Installing packages: iperf3
   [  73.9] Installing packages: iproute2
   [  89.5] Installing packages: iptables
   [ 100.6] Installing packages: openrc
   [ 113.5] Installing packages: openssh-server
   [ 124.8] Installing packages: util-linux
   [ 148.1] Linking: /etc/init.d/agetty.ttyS0 -> agetty
   [ 148.2] Running: echo ttyS0 >/etc/securetty
   [ 149.2] Running: rc-update add agetty.ttyS0 default
   [ 150.2] Running: rc-update add devfs boot
   [ 151.3] Running: rc-update add procfs boot
   [ 152.3] Running: rc-update add sysfs boot
   [ 153.6] Setting passwords
   [ 166.9] Finishing off
   [Firecracker rfstool] Minimal rootfs built and available at: /home/bob/workspace/firecracker/build/img/local/x86_64/minimal/fsfiles/boottime-rootfs.ext4
   ```
   This will result in a bootable rootfs image at the path specified, that can be run on Firecracker and accessed with credentials username: root, password: root.


`rfstool` is a container-based tool, that uses wget and the [libguestfs](http://libguestfs.org/) library and tools to build the rootfs image. It works as follows:
 
1. Downloads an Alpline minifs image with wget:

   ```bash
    wget http://dl-cdn.alpinelinux.org/alpine/v3.8/releases/x86/alpine-minirootfs-3.8.1-x86.tar.gz
   ```

2. Extracts the image into a file of a specified size and type, using [virt-make-fs](http://libguestfs.org/virt-make-fs.1.html):
   ```bash
   virt-make-fs --size=30M --type=ext4 <alpine_package.gz> <rootfs_filename>
   ```

3. Customizes the image using [virt-customize](http://libguestfs.org/virt-customize.1.html) to add packages and devices, and set services and passwords:
   ```bash
   virt-customize \
     -a <rootfs_filename> \
     --install ca-certificates \
     --install curl \
     --install iperf3 \
     --install iproute2 \
     --install iptables \
     --install openrc \
     --install openssh-server \
     --install util-linux \
     --link agetty:/etc/init.d/agetty.ttyS0 \
     --run-command 'echo ttyS0 >/etc/securetty' \
     --run-command 'rc-update add agetty.ttyS0 default' \
     --run-command 'rc-update add devfs boot' \
     --run-command 'rc-update add procfs boot' \
     --run-command 'rc-update add sysfs boot' \
     --root-password password:'root' \
     --password-crypto sha512
   ```
   The same process can be used to create rootfs's for other Linux distibutions, as long as:
   1.  They have file-based or cloud image distributions.
   2.  They are supported by libguestfs. Typically rpm, apt, zipper and apk based systems are.

   \
   `rftool` also allows shell access to the container, via `./tools/rfstool shell`, to allow custom scripting of your rootfs image via the libguestfs tools.  For example, ensuring sshd is available at startup and injecting SSH keys into your rootfs:
   ```bash
   virt-customize \
     -a <rootfs_filename> \
     --run-command 'rc-update add sshd' \
     --ssh-inject root:file:<path_to_ssh_pub_key> \
     --append-line /etc/ssh/sshd_config:"PermitRootLogin yes"
   ```


## Putting it together

You should now have a kernel image (`vmlinux`) and a rootfs image
(`boottime-rootfs.ext4`), that you can boot with Firecracker.  Follow the instructions on how to run Firecracker on the [getting-started](docs/getting-started.md#running-firecracker) page, subsituting the example kernel and rootfs with the path to your newly built ones.

If you wish to connect to your firecracker instance via SSH, then [networking](docs/network-setup.md) will have to be enabled.
