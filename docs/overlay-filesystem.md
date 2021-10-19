# Let Multiple Firecracker VMs Share a Root Filesystem with Copy-on-Write

An overlay (copy-on-write) filesystem lets multiple microVMs share a common read-only
filesystem on the host. Each microVM can still write changes to that filesystem
by using its own overlay. By default, files are read from the underlying root filesystem.
All changes are written to the overlay by copying the file and writing the modified
copy. If such a copy exists on the overlay, it takes precedence over whatever is
in the root filesystem.

As used by [`firecracker-containerd`](https://github.com/firecracker-microvm/firecracker-containerd),
this requires a root filesystem in `squashfs` mounted as read-only and a write-layer
formatted as `ext4`, which can be either a temporary `tempfs` in guest memory or
a sparse `ext4` file on the host. The latter method has the advantage that changes
can be persisted across microVM reboots if required.

Please note that this requires changes on the guest and is thus only possible
if you control the guest's init.

## Convert rootfs to squashfs

If you already have an existing `rootfs` file formatted as `ext4`, e.g., created
according to the [rootfs-and-kernel-setup](https://github.com/firecracker-microvm/firecracker/blob/main/docs/rootfs-and-kernel-setup.md)
documentation, you can simply mount it and create a new `squashfs` formatted filesystem
from that.

This requires `mksquashfs`, which is available as part of the `squashfs-tools`
for you distribution.

1. Create a mounting point

    ```bash
    mkdir /tmp/my-rootfs
    ```

1. Mount the existing rootfs (e.g., `rootfs.ext4`). If you don't have an existing
    rootfs, you can skip this step and simply copy your files directly.

    ```bash
    sudo mount rootfs.ext4 /tmp/my-rootfs
    ```

1. Create necessary folders for mounting the overlay filesystem. These mount points
    have to be created now as the microVM will not be able to change anything on
    the read-only filesystem.

    ```bash
    sudo mkdir -p /tmp/my-rootfs/overlay/root \
        /tmp/my-rootfs/overlay/work \
        /tmp/my-rootfs/mnt \
        /tmp/my-rootfs/rom
    ```

1. Create  the `overlay-init` script (adapted from [overlay-init of firecracker-containerd](https://github.com/firecracker-microvm/firecracker-containerd/blob/main/tools/image-builder/files_debootstrap/sbin/overlay-init)).

    ```bash
    cat > overlay-init <<EOF
    #!/bin/sh
    # Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved
    #
    # Licensed under the Apache License, Version 2.0 (the "License"). You may
    # not use this file except in compliance with the License. A copy of the
    # License is located at
    #
    # <http://aws.amazon.com/apache2.0/>
    #
    # or in the "license" file accompanying this file. This file is distributed
    # on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
    # express or implied. See the License for the specific language governing
    # permissions and limitations under the License

    # Parameters
    # 1. rw_root -- path where the read/write root is mounted
    # 2. work_dir -- path to the overlay workdir (must be on same filesystem as rw_root)
    # Overlay will be set up on /mnt, original root on /mnt/rom
    pivot() {
        local rw_root work_dir
        rw_root="$1"
        work_dir="$2"
        /bin/mount \
    -o noatime,lowerdir=/,upperdir=${rw_root},workdir=${work_dir} \
    -t overlay "overlayfs:${rw_root}" /mnt
        pivot_root /mnt /mnt/rom
    }

    # Overlay is configured under /overlay
    # Global variable $overlay_root is expected to be set to either
    # "ram", which configures a tmpfs as the rw overlay layer (this is
    # the default, if the variable is unset)
    # - or -
    # A block device name, relative to /dev, in which case it is assumed
    # to contain an ext4 filesystem suitable for use as a rw overlay
    # layer. e.g. "vdb"
    do_overlay() {
        local overlay_dir="/overlay"
        if [ "$overlay_root" = ram ] ||
            [ -z "$overlay_root" ]; then
            /bin/mount -t tmpfs -o noatime,mode=0755 tmpfs /overlay
        else
            /bin/mount -t ext4 "/dev/$overlay_root" /overlay
        fi
        mkdir -p /overlay/root /overlay/work
        pivot /overlay/root /overlay/work
    }

    # If we're given an overlay, ensure that it really exists. Panic if not
    if [ -n "$overlay_root" ] &&
        [ "$overlay_root" != ram ] &&
        [ ! -b "/dev/$overlay_root" ]; then
        echo -n "FATAL: "
        echo -n "Overlay root given as $overlay_root but "
        echo "/dev/$overlay_root does not exist"
        exit 1
    fi

    do_overlay

    # invoke the actual system init program and procede with the boot
    # process
    exec /sbin/init $@
    EOF

    sudo cp overlay-init /tmp/my-rootfs/sbin/overlay-init
    ```

1. Create a `squashfs` formatted filesystem

    ```bash
    sudo mksquashfs /tmp/my-rootfs rootfs.img -noappend
    ```

1. Unmount the old rootfs (if mounted in step 2).

    ```bash
    sudo umount /tmp/my-rootfs
    ```

Now we have successfully prepared the rootfs.

## Creating an ext4 Formatted Persistent Overlay

To allow microVMs to save persistent files that are available after a reboot, we
need to create an `ext4` image to use as an overlay. If data does not need to be
available again after a reboot, you can skip this step, as it is possible to use
an in-memory `tmpfs` as an overlay instead.

1. Create the image file. We will use a size of 1 GiB (1024 MiB), but this can
    be increased.

    ```bash
    dd if=/dev/zero of=overlay.ext4 conv=sparse bs=1M count=1024
    ```

    The file will be created as a sparse file, so that it only uses as much disk
    space as it currently needs. The file size may still be reported as 1 GiB
    (the file's _apparent size_). Note that this requires your host filesystem
    to support sparse files. Its actual size can be checked with the following
    command (which should be 0 right now):

    ```bash
    du -h overlay.ext4
    ```

    `du` can also be used to report the apparent size of a file (1GiB in this
    example):

    ```bash
    du -h --apparent-size overlay.ext4
    ```

1. Create an `ext4` file system on the image file.

    ```bash
    mkfs.ext4 overlay.ext4
    ```

Done! The overlay is ready now. Note that you need to create **one filesystem per
microVM**.

## Configure the rootfs and Kernel Boot Parameters

To actually use the overlay filesystem correctly, you will need to adapt your Firecracker
configuration and boot parameters for you microVMs.

First, mount the new `squashfs` root filesystem as read-only. Note that this step
is optional but recommended. Simply set the `is_read_only` parameter in your Firecracker
disk parameters to `true` for the root device.

Second, set the `init` parameter to `/sbin/overlay-init` to execute the initalization
of our overlay filesystem before starting the rest of the microVM's init process.
If you set the `overlay_root` to `ram` or leave it unset, a `tmpfs` will be created
and used as the write layer. Otherwise, add the `overlay.ext4` as a second drive
and set `overlay_root` to `vdb` (or mount it as a third drive and set to `vdc`, etc.).

```json
{
  "boot-source": {
    "kernel_image_path": "vmlinux",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off overlay_root=vdb init=/sbin/overlay-init",
  },
  "drives": [
    {
      "drive_id": "rootfs",
      "path_on_host": "rootfs.img",
      "is_root_device": true,
      "is_read_only": true,
    },
    {
      "drive_id": "overlayfs",
      "path_on_host": "overlay.ext4",
      "is_root_device": false,
    }
  ],
  "machine-config": {
    "vcpu_count": 2,
    "mem_size_mib": 1024,
  },
}
```
