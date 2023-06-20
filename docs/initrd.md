# Creating and using an initrd for Firecracker

## Creating

### Based on alpine or suse

You can use the script found [here](https://github.com/marcov/firecracker-initrd)
to generate an initrd either based on alpine or suse linux.

The script extracts the init system from each distribution and creates a
initrd.

### Custom

Use this option for creating an initrd if you're building your own init or if
you need any specific files / logic in your initrd.

```bash
mkdir initrd
cp /path/to/your/init initrd/init
# copy everything else you need in initrd/
cd initrd
find . -print0 | cpio --null --create --verbose --format=newc > initrd.cpio
```

## Usage

When setting your boot source, add a `initrd_path` property like so:

```shell
curl --unix-socket /tmp/firecracker.socket -i \
    -X PUT 'http://localhost/boot-source'   \
    -H 'Accept: application/json'           \
    -H 'Content-Type: application/json'     \
    -d "{
        \"kernel_image_path\": \"/path/to/kernel\",
        \"boot_args\": \"console=ttyS0 reboot=k panic=1 pci=off\",
        \"initrd_path\": \"/path/to/initrd.cpio\"
    }"
```

### Notes

- You should not use a drive with `is_root_device: true` when using an initrd
- Make sure your kernel configuration has `CONFIG_BLK_DEV_INITRD=y`
- If you don't want to place your init at the root of your initrd, you can add
  `rdinit=/path/to/init` to your `boot_args` property
- If you intend to `pivot_root` in your init, it won't be possible because the
  initrd is mounted as a rootfs and cannot be unmounted. You will need to use
  `switch_root` instead.
