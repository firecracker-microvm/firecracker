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

If you need an opinionated way of running Firecracker, create an `i3.metal`
instance using Ubuntu 18.04 on EC2. Firecracker uses
[KVM](https://www.linux-kvm.org) and needs read/write access that can be
granted as shown below:

```
sudo setfacl -m u:${USER}:rw /dev/kvm
```

The generic requirements are explained below:

- **Linux 4.14+**

  Firecracker currently supports physical Linux **x86_64** and **aarch64**
  hosts, running kernel version 4.14 or later. However, the **aarch64** support
  is not feature complete (alpha stage).

- **KVM**

  Please make sure that:
  1. you have KVM enabled in your Linux kernel, and
  2. you have read/write access to `/dev/kvm`.
     If you need help setting up access to `/dev/kvm`, you should check out
     [Appendix A](#appendix-a-setting-up-kvm-access).

To check if your system meets the requirements to run Firecracker, clone
the repository and execute `tools/devtool checkenv`.

## Getting the Firecracker Binary

Firecracker is linked statically against
[musl](https://www.musl-libc.org/), having no library dependencies. You can
just download the latest binary from our
[release page](https://github.com/firecracker-microvm/firecracker/releases),
and run it on your x86_64 or aarch64 Linux machine.

On the EC2 instance, this binary can be downloaded as:

```wrap
latest=$(basename $(curl -fsSLI -o /dev/null -w  %{url_effective} https://github.com/firecracker-microvm/firecracker/releases/latest))
```

```wrap
curl -LOJ https://github.com/firecracker-microvm/firecracker/releases/download/${latest}/firecracker-${latest}-$(uname -m)
```

Rename the binary to "firecracker":

```
mv firecracker-${latest}-$(uname -m) firecracker
```

Make the binary executable:

```
chmod +x firecracker
```

If, instead, you'd like to build Firecracker yourself, you should check out
the [Building From Source section](#building-from-source) in this doc.

## Running Firecracker

In production, Firecracker is designed to be run securely, inside
an execution jail, carefully set up by the `jailer` binary. This is how
our
[integration test suite](#running-the-integration-test-suite) does it.
However, if you just want to see Firecracker booting up a guest Linux
machine, you can do that as well.

First, make sure you have the `firecracker` binary available - either
[downloaded from our release page](#getting-the-firecracker-binary), or
[built from source](#building-from-source).

Next, you will need an uncompressed Linux kernel binary, and an ext4
file system image (to use as rootfs).

1. To run an `x86_64` guest you can download such resources from:
    [kernel](https://s3.amazonaws.com/spec.ccfc.min/img/hello/kernel/hello-vmlinux.bin)
    and [rootfs](https://s3.amazonaws.com/spec.ccfc.min/img/hello/fsfiles/hello-rootfs.ext4).
1. To run an `aarch64` guest, download them from:
    [kernel](https://s3.amazonaws.com/spec.ccfc.min/img/aarch64/ubuntu_with_ssh/kernel/vmlinux.bin)
    and [rootfs](https://s3.amazonaws.com/spec.ccfc.min/img/aarch64/ubuntu_with_ssh/fsfiles/xenial.rootfs.ext4).

Now, let's open up two shell prompts: one to run Firecracker, and another one
to control it (by writing to the API socket). For the purpose of this guide,
**make sure the two shells run in the same directory where you placed the
`firecracker` binary**.

In your **first shell**:

- make sure Firecracker can create its API socket:

```bash
rm -f /tmp/firecracker.socket
```

- then, start Firecracker:

```bash
./firecracker --api-sock /tmp/firecracker.socket
```

In your **second shell** prompt:

- get the kernel and rootfs, if you don't have any available:

  ```bash
  arch=`uname -m`
  dest_kernel="hello-vmlinux.bin"
  dest_rootfs="hello-rootfs.ext4"
  image_bucket_url="https://s3.amazonaws.com/spec.ccfc.min/img"

  if [ ${arch} = "x86_64" ]; then
      kernel="${image_bucket_url}/hello/kernel/hello-vmlinux.bin"
      rootfs="${image_bucket_url}/hello/fsfiles/hello-rootfs.ext4"
  elif [ ${arch} = "aarch64" ]; then
      kernel="${image_bucket_url}/aarch64/ubuntu_with_ssh/kernel/vmlinux.bin"
      rootfs="${image_bucket_url}/aarch64/ubuntu_with_ssh/fsfiles/xenial.rootfs.ext4"
  else
      echo "Cannot run firecracker on $arch architecture!"
      exit 1
  fi

  echo "Downloading $kernel..."
  curl -fsSL -o $dest_kernel $kernel

  echo "Downloading $rootfs..."
  curl -fsSL -o $dest_rootfs $rootfs

  echo "Saved kernel file to $dest_kernel and root block device to $dest_rootfs."
  ```

- set the guest kernel (assuming you are in the same directory as the
  above script was run):

  ```bash
  arch=`uname -m`
  kernel_path=$(pwd)"/hello-vmlinux.bin"

  if [ ${arch} = "x86_64" ]; then
      curl --unix-socket /tmp/firecracker.socket -i \
        -X PUT 'http://localhost/boot-source'   \
        -H 'Accept: application/json'           \
        -H 'Content-Type: application/json'     \
        -d "{
              \"kernel_image_path\": \"${kernel_path}\",
              \"boot_args\": \"console=ttyS0 reboot=k panic=1 pci=off\"
         }"
  elif [ ${arch} = "aarch64" ]; then
      curl --unix-socket /tmp/firecracker.socket -i \
        -X PUT 'http://localhost/boot-source'   \
        -H 'Accept: application/json'           \
        -H 'Content-Type: application/json'     \
        -d "{
              \"kernel_image_path\": \"${kernel_path}\",
              \"boot_args\": \"keep_bootcon console=ttyS0 reboot=k panic=1 pci=off\"
         }"
  else
      echo "Cannot run firecracker on $arch architecture!"
      exit 1
  fi
  ```

- set the guest rootfs:

  ```bash
  rootfs_path=$(pwd)"/hello-rootfs.ext4"
  curl --unix-socket /tmp/firecracker.socket -i \
    -X PUT 'http://localhost/drives/rootfs' \
    -H 'Accept: application/json'           \
    -H 'Content-Type: application/json'     \
    -d "{
          \"drive_id\": \"rootfs\",
          \"path_on_host\": \"${rootfs_path}\",
          \"is_root_device\": true,
          \"is_read_only\": false
     }"
  ```

- start the guest machine:

  ```bash
  curl --unix-socket /tmp/firecracker.socket -i \
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

When you're done, issuing a `reboot` command inside the guest will actually
shutdown Firecracker gracefully. This is due to the fact that Firecracker
doesn't implement guest power management.

**Note**: the default microVM will have 1 vCPU and 128 MiB RAM. If you wish to
customize that (say, 2 vCPUs and 1024MiB RAM), you can do so before issuing
the `InstanceStart` call, via this API command:

```bash
curl --unix-socket /tmp/firecracker.socket -i  \
  -X PUT 'http://localhost/machine-config' \
  -H 'Accept: application/json'            \
  -H 'Content-Type: application/json'      \
  -d '{
      "vcpu_count": 2,
      "mem_size_mib": 1024,
      "ht_enabled": false
  }'
```

### Configuring the microVM without sending API requests

If you'd like to boot up a guest machine without using the API socket, you can
do that by passing the parameter `--config-file` to the Firecracker process.
The command for starting Firecracker with this option will look like this:

```wrap
./firecracker --api-sock /tmp/firecracker.socket --config-file <path_to_the_configuration_file>
```

`path_to_the_configuration_file` should represent the path to a file that
contains a JSON which stores the entire configuration for all of the microVM's
resources. The JSON **must** contain the configuration for the guest kernel and
rootfs, as these are mandatory, but all of the other resources are optional,
so it's your choice if you want to configure them or not. Because using this
configuration method will also start the microVM, you need to specify all
desired pre-boot configurable resources in that JSON. The names of the
resources are the ones from the `firecracker.yaml` file and the names of
their fields are the same that are used in API requests. You can find an
example of configuration file at `tests/framework/vm_config.json`.
After the machine is booted, you can still use the socket to send
API requests for post-boot operations.

## Building From Source

The quickest way to build and test Firecracker is by using our development
tool ([`tools/devtool`](../tools/devtool)). It employs a
per-architecture [Docker container](../tools/devctr/)  to store the software toolchain
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

1. with the __default__ musl target: ```tools/devtool build```
1. (__Experimental only__) using the gnu target: 
```tools/devtool build -l gnu```

This will build and place the two Firecracker binaries at:

- `build/cargo_target/${toolchain}/debug/firecracker` and
- `build/cargo_target/${toolchain}/debug/jailer`.

The default build profile is `debug`. If you want to build
the release binaries (optimized and stripped of debug info),
use the `--release` option:

```bash
tools/devtool build --release
```

Extensive usage information about `devtool` and its various functions and
arguments is available via:

```bash
tools/devtool --help
```

### Alternative: Building Firecracker using glibc

The toolchain that Firecracker is tested against and that is recommended for
building production releases is the one that is automatically used by building
using `devtool`. In this configuration, Firecracker is currently built as a
static binary linked against the [musl](https://www.musl-libc.org/) libc
implementation.

Firecracker also builds using [glibc](https://www.gnu.org/software/libc/)
toolchains, such as the default Rust toolchains provided in certain Linux
distributions:

```bash
arch=`uname -m`
cargo build --target ${arch}-unknown-linux-gnu
```

That being said, Firecracker binaries linked with glibc or built without
`devtool` are always considered experimental and should not be used in
production.

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
not run on an EC2 .metal instance. You can skip performance tests with:

```bash
 ./tools/devtool test -- --ignore integration_tests/performance
 ```

## Appendix A: Setting Up KVM Access

Some Linux distributions use the `kvm` group to manage access to `/dev/kvm`,
while others rely on access control lists. If you have the ACL package for your
distro installed, you can grant your user access via:

```bash
sudo setfacl -m u:${USER}:rw /dev/kvm
```

Otherwise, if access is managed via the `kvm` group:

```bash
[ $(stat -c "%G" /dev/kvm) = kvm ] && sudo usermod -aG kvm ${USER} \
&& echo "Access granted."
```

If none of the above works, you will need to either install the file
system ACL package for your distro and use the `setfacl` command as above,
or run Firecracker as `root` (via `sudo`).

You can check if you have access to `/dev/kvm` with:

```bash
[ -r /dev/kvm ] && [ -w /dev/kvm ] && echo "OK" || echo "FAIL"
```

**Note:** If you've just added your user to the `kvm` group via `usermod`, don't
forget to log out and then back in, so this change takes effect.

## Appendix B: Setting Up Docker

To get Docker, you can either use the
[official Docker install instructions](https://docs.docker.com/install/)
, or the package manager available on your specific Linux distribution:

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
