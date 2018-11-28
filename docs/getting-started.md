# Getting Started with Firecracker

## Contents
- [Prerequisites](#prerequisites)
- [Getting the Firecracker Binary](#getting-the-firecracker-binary)
- [Running Firecracker](#running-firecracker)
- [Building From Source](#building-from-source)
- [Running the Integration Test Suite](#running-the-integration-test-suite)
- [Appendix A: Setting Up KVM Access](#appendix-a-setting-up-kvm-access)
- [Appendix B: Setting Up Docker](#appendix-b-setting-up-docker)

## Prerequisites

- **Linux 4.14+**

  Firecracker currently supports physical Linux x86_64 hosts, with kernel
  version 4.14 or later.

- **KVM**

  Firecracker uses [KVM](https://www.linux-kvm.org). Please make sure that:
  1. you have KVM enabled in your Linux kernel, and
  2. you have read/write access to `/dev/kvm`.
     If you need help setting up access to `/dev/kvm`, you should check out
     [Appendix A](#appendix-a-setting-up-kvm-access).

<details>

<summary>Click here to see a BASH script that will check if your system meets
the basic requirements to run Firecracker.</summary>

```bash
err=""; \
[ "$(uname) $(uname -m)" = "Linux x86_64" ] \
  || err="ERROR: your system is not Linux x86_64."; \
dmesg | grep -i "hypervisor detected" \
  && err="$err\nERROR: you are running in a virtual machine."; \
[ -r /dev/kvm ] && [ -w /dev/kvm ] \
  || err="$err\nERROR: /dev/kvm is innaccessible."; \
(( $(uname -r | cut -d. -f1)*1000 + $(uname -r | cut -d. -f2) >= 4014 )) \
  || err="$err\nERROR: your kernel version ($(uname -r)) is too old."; \
[ -z "$err" ] && echo "Your system looks ready for Firecracker!" || echo -e "$err"
```

</details>

## Getting the Firecracker Binary

Firecracker is linked statically against
[musl](https://www.musl-libc.org/), having no library dependencies. You can
just download the latest binary from our
[release page](https://github.com/firecracker-microvm/firecracker/releases),
and run it on your x86_64 Linux machine.

If, instead, you'd like to build Firecracker yourself, you should check out
the [Building From Source section](#building-from-source) in this doc.


## Running Firecracker

In production, Firecracker is designed to be run securely, inside
an execution jail, carefully set up by the `jailer` binary. This is how
our
[integration test suite](#running-the-integration-test-suite) does it.
However, if you just want to see Firecracker booting up a guest Linux
machine, you can do that as well.

First, make sure you have the Firecracker binary available - either
[downloaded from our release page](#getting-the-firecracker-binary), or
[built from source](#building-from-source).

Next, you will need an uncompressed Linux kernel binary, and an ext4
file system image (to use as rootfs). You can use these files from our
microVM image S3 bucket:
[kernel](
https://s3.amazonaws.com/spec.ccfc.min/img/hello/kernel/hello-vmlinux.bin
), and
[rootfs](
https://s3.amazonaws.com/spec.ccfc.min/img/hello/fsfiles/hello-rootfs.ext4
).

Now, let's open up two shell prompts: one to run Firecracker, and another one
to control it (writing to the API socket). For the purpose of this guide,
**make sure the two shells run in the same directory where you placed the
`firecracker` binary**.

In your **first shell**:
- make sure Firecracker can create its API socket:

```bash
rm -f /tmp/firecracker.sock
```

- then, start Firecracker:
```bash
./firecracker --api-sock /tmp/firecracker.sock
```

In your **second shell** prompt:
- get the kernel and rootfs, if you don't have any available:

  ```bash
  curl -fsSL -o hello-vmlinux.bin https://s3.amazonaws.com/spec.ccfc.min/img/hello/kernel/hello-vmlinux.bin
  curl -fsSL -o hello-rootfs.ext4 https://s3.amazonaws.com/spec.ccfc.min/img/hello/fsfiles/hello-rootfs.ext4
  ```

- set the guest kernel:

  ```bash
  curl --unix-socket /tmp/firecracker.sock -i \
      -X PUT 'http://localhost/boot-source'   \
      -H 'Accept: application/json'           \
      -H 'Content-Type: application/json'     \
      -d '{
          "kernel_image_path": "./hello-vmlinux.bin",
          "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
      }'
  ```

- set the guest rootfs:

  ```bash
  curl --unix-socket /tmp/firecracker.sock -i \
      -X PUT 'http://localhost/drives/rootfs' \
      -H 'Accept: application/json'           \
      -H 'Content-Type: application/json'     \
      -d '{
          "drive_id": "rootfs",
          "path_on_host": "./hello-rootfs.ext4",
          "is_root_device": true,
          "is_read_only": false
      }'
  ```

- start the guest machine:

  ```bash
  curl --unix-socket /tmp/firecracker.sock -i \
      -X PUT 'http://localhost/actions'       \
      -H  'Accept: application/json'          \
      -H  'Content-Type: application/json'    \
      -d '{
          "action_type": "InstanceStart"
       }'
  ```

Going back to your first shell, you should now see a serial TTY prompting you
to log into the guest machine. If you used our `hello-rootfs.ext4` image,
you can login as `root`, using the password `root`.

When you're done,
issuing a `reboot` command inside the guest will shutdown Firecracker
gracefully. This is because, since microVMs are not designed to be restarted,
and Firecracker doesn't currently implement guest power management, we're
using the keyboard reset action as a shut down switch.

**Note**: the default microVM will have 1 vCPU and 128 MiB RAM. If you wish to
customize that (say, 2 vCPUs and 1024MiB RAM), you can do so before issuing
the `InstanceStart` call, via this API command:

```bash
curl --unix-socket /tmp/firecracker.sock -i  \
    -X PUT 'http://localhost/machine-config' \
    -H 'Accept: application/json'            \
    -H 'Content-Type: application/json'      \
    -d '{
        "vcpu_count": 2,
        "mem_size_mib": 1024
    }'
```

## Building From Source

The quickest way to build and test Firecracker is by using our development
tool ([`tools/devtool`](../tools/devtool)). It employs a
[Docker container](../tools/devctr/Dockerfile)  to store the software toolchain
used throughout the development process. If you need help setting up
[Docker](https://docker.com) on your system, you can check out
[Appendix B: Setting Up Docker](#appendix-b-setting-up-docker).

### Getting the Firecracker Sources

Get a copy of the Firecracker sources by cloning our GitHub repo:

```bash
git clone https://github.com/firecracker-microvm/firecracker
```

All development happens on the master branch and we use git tags to mark
releases. If you are interested in a specific release (e.g. v0.10.1), you can
check it out with:

```bash
git checkout tags/v0.10.1
```


### Building Firecracker

Within the Firecracker repository root directory:

```bash
tools/devtool build
```

This will build and place the two Firecracker binaries at
`build/debug/firecracker` and `build/debug/jailer`. The default build profile
is `debug`. If you want to build the release binaries (optimized and stripped
of debug info), use the `--release` option:

```bash
tools/devtool build --release
```

Extensive usage information about `devtool` and its various functions and
arguments is available via:

```bash
tools/devtool --help
```


## Running the Integration Test Suite

You can also use our development tool to run the integration test suite:

```bash
tools/devtool test
```

Please note that the test suite is designed to ensure our
[SLA parameters](../SPECIFICATION.md) as measured on EC2 .metal instances
and, as such, some performance tests may fail when run on a regular desktop
machine. Specifically, don't be alarmed if you see
`tests/integration_tests/performance/test_process_startup_time.py` failing when
not run on an EC2 .metal instance.


## Appendix A: Setting Up KVM Access

Some Linux distributions use the `kvm` group to manage access to `/dev/kvm`,
while others rely on access control lists. If you have the ACL package for your
distro installed, you can grant your user access via:

```bash
sudo setfacl -m u:${USER}:rw /dev/kvm
```

Otherwise, if access is managed via the `kvm` group:

```bash
[ $(stat -c "%G" /dev/kvm) = kvm ] && sudo usermod -aG kvm ${USER} && echo "Access granted."
```

If none of the above works, you will need to either install the file
system ACL package for your distro and use the `setfacl` command as above,
or run Firecracker as `root` (via `sudo`).

You can check if you have access to `/dev/kvm` with:
  ```bash
  [ -r /dev/kvm ] && [ -w /dev/kvm ] && echo "OK" || echo "FAIL"
  ```

Note: if you've just added your user to the `kvm` group via `usermod`, don't
forget to log out and then back in, so this change takes effect.


## Appendix B: Setting Up Docker

To get Docker, you can either use the
[official Docker install instructions](
https://docs.docker.com/install/
), or the package manager available on your specific Linux distribution:
- on Debian / Ubuntu

  ```bash
  sudo apt-get update
  sudo apt-get install docker.io
  ```

- on Fedora / CentOS / RHEL / Amazon Linux

  ```bash
  sudo yum install docker
  ```

Then, for any of the above, you will need to start the Docker daemon
and add your user to the `docker` group.

```bash
sudo systemctl start docker
sudo usermod -aG docker $USER
```

Don't forget to log out and then back in again, so that the user
change takes effect.

If you wish to have Docker started automatically after boot, you can:

```bash
sudo systemctl enable docker
```

We recommend testing your Docker configuration by running a lightweight
test container and checking for net connectivity:

```bash
docker pull alpine
docker run --rm -it alpine ping -c 3 amazon.com
```
