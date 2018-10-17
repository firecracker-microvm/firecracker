# Firecracker Read Me

## What is Firecracker

Firecracker is a new virtualization technology that enables customers to deploy
lightweight *micro* Virtual Machines or microVMs. Firecracker microVMs combine
the security and workload isolation properties of traditional VMs with the
speed and resource efficiency enabled by containers. MicroVMs can initiate
user-space code execution in less than 150ms, have a footprint of less than
5 MiB of memory, and provide a secure, trusted environment for multi-tenant
services. Customers can create microVMs with any combination of vCPU and memory
to match  their application requirements.

MicroVMs are created and managed by the Firecracker process, which implements a
virtual machine manager based on Linux's Kernel-based Virtual Machine (KVM),
the state of art for Linux virtualization. Firecracker provides the minimal
required device emulation to the guest operating system while excluding non-
essential functionality to enable faster startup time and a reduced memory
footprint. The Firecracker process also provides a control API, a metadata
store, enforces microVM sandboxing, and handles resource rate limiting for
microVMs.

## What's Included

Firecracker consists of a single micro Virtual Machine Manager binary that will
spawn a RESTful API endpoint when started. The API supported by the current
version can be found at `api_server/swagger/firecracker.yaml`.

The **API endpoint** can be used to:

- Configure the microvm by:
  - Change the number of vCPUs (the default is 1)
  - Change the memory size (the default is 128 MiB)
  - Set a CPU template (the only available templates are C3 and T2 for now)
  - Enable/Disable hyperthreading (by default hyperthreading is disabled).
    The host needs to be modified before starting Firecracker as this flag
    only changes the topology inside the microvm.
- Add one or more network interfaces to the microVM. Firecracker is mapping
  an existing host file as a VirtIO/block device into the microVM.
- Add one or more read/write disks (file-backed block devices) to the microVM.
- Trigger block device rescan while the guest is running. This enables the
  guest OS to pick up size changes to the block device's backing file.
- Change the backing file for a block device, before or after the guest boots.
- Configure the logging system by:
  - Specifying two named pipes (one for human readable logs and one for the
    metrics).
  - Enabling or disabling printing the log level, line and file of the log
    origin.
  - Setting the maximum level for triggering logs.
- Configure rate limiters for VirtIO devices which can limit the bandwidth,
  ops/s or both.
- Start the microVM using a given kernel image, root file system and boot
  arguments.
- Stop the microVM.

**Additional capabilities**:

- Emulated keyboard (i8042) and serial console (UART). The microVM serial
  console input and output are connected to those of the Firecracker process
  (this allows direct console access to the guest OS).
- Metrics currently logged every 60s to a one-purpose only named pipe.
  Categories:
  - API requests related metrics
  - VCPUs related metrics
  - Device emulation related metrics:
    - The serial console (UART)
    - Keyboard (i8042)
    - Block
    - Network
  - Seccomp filtering related metrics
- Default demand fault paging & CPU oversubscription.

## Performance

### Manual One-Time Benchmarking and Stress Testing

- An `iperf` network test (TCP, send-only, 1500 MTU, single core) from the
  microVM to the host has reached **8 Gbps** on an `i3.metal` EC2 instance. The
  test fully saturated 1 CPU core within the microVM, while the Firecracker
  thread running VirtIO/net emulation consumed another 75% of a host core.
- A `dd` storage test (writing large chunks of data to a file-backed block
  device stored in a RAM-disk, single-core) ran at 1 **GB/s**. The test fully
  saturated 1 CPU core within the microVM, while the Firecracker thread running
  VirtIO/block emulation consumed another 50% of a host core.
- At least **2000** Firecracker microVMs have been started on a single host
  (each with 1 vCPu core, and one TUN/TAP device), and have been stable under
  CPU and network I/O stress conditions, on an `i3.metal` EC2 instance.

### Integration Testing

- The boot-time SLA is enforced in `tests/performance/test_boottime.py`.
- The process startup time SLA is enforced in
  `tests/performance/test_process_startup_time.py`. This value corresponds to
  the CPU time (time that the process actually spent on the CPU) elapsed
  between `jailer` starting and `bind` being called on the API socket.

### Measuring boot time

- Writing the magic value `123` to IO port `0x03f0` triggers a timestamp entry
  in the Firecracker log, which represents the time elapsed since receiving the
  `InstanceStart` command. This mechanism can be used to measure guest boot-
  time by writing to said IO port very early (ideally as part of init) from the
  guest.

## Getting Started

### Get or Build the Firecracker Binary

You can grab the latest Firecracker binary from the release S3 bucket.
You can request access to the S3 bucket by opening an issue with the label
"Support: Access Request".

If you want to build it from source, you'll need add the Rust `musl` toolchain:

``` bash
rustup target add x86_64-unknown-linux-musl
cargo build --release
```

The binary is `target/x86_64-unknown-linux-musl/release/firecracker`.

### Run the Integration Tests

See `tests/README.md` for details on how to run the integration tests.

### Secure a Host with KVM Access

To build, test, or run, Firecracker requires a host with a modern version of
KVM (Linux kernel 4.14+) running on physical hardware (or a virtual machine
with nested virtualization enabled).

Firecracker needs rw access to `/dev/kvm`. You can grant these rights, e.g., to
all users, with: `sudo chmod a+rw /dev/kvm`.

### Start Firecracker

See `docs/jailer.md` for details on how to start Firecracker in a jail. This is
the recommended way to use Firecracker, as it enforces containment and
security.

Firecracker can be started outside the jail as well. To do this, run:

``` bash
./firecracker --api-sock </path/to/unix/socket> --id <microvm-id>
```

If the api socket is not specified at startup, Firecracker will create
`/tmp/firecracker.socket`. Similarly, the `--id` parameter can be omitted,
in which case, Firecracker will use `anonymous-instance` as an ID.

### Configure the MicroVM

The MicroVM is configured via the `machine-config/` API resource.
Example with cURL:

``` bash
curl --unix-socket ${socket} -i \
     -X PUT "http://localhost/machine-config" \
     -H "accept: application/json" \
     -H "Content-Type: application/json" \
     -d "{
            \"vcpu_count\": 6,
            \"mem_size_mib\": 3906,
            \"cpu_template\": \"T2\",
            \"ht_enabled\": true
        }"
```

### Select the Guest Kernel and RootFS

To run a guest OS within a Firecracker microVMs, you will need to have:

- **A guest kernel image** that boots and runs with Firecracker's minimal/
  VirtIO device model. Pass this via the `/boot-source` API resource.

```bash
curl --unix-socket ${socket} -i  \
     -X PUT "http://localhost/boot-source" \
     -H "accept: application/json" \
     -H "Content-Type: application/json" \
     -d "{
            \"kernel_image_path\": \"${kernel_path}\",
            \"boot_args\": \"reboot=k panic=1 pci=off nomodules console=ttyS0\"
        }"
```

By default, Firecracker guests start with the console disabled, as a speed
optimization. If you need it, the following arguments need to be passed to the
`boot-source` call:
`\"boot_args\": \"console=ttyS0 reboot=k panic=1 pci=off nomodules\"`.

- **A guest root file system** that boots with that kernel. You'll pass this as
  a bootable block device to Firecracker via the `/drives` API resource.

```bash
curl --unix-socket ${socket} -i \
     -X PUT "http://localhost/drives/root" \
     -H "accept: application/json" \
     -H "Content-Type: application/json" \
     -d "{
            \"drive_id\": \"root\",
            \"path_on_host\": \"${rootfs_path}\",
            \"is_root_device\": true,
            \"is_read_only\": false
         }"
```

### Provision Network / Storage Resources

Firecracker expects network interfaces and drives to be created beforehand and
passed by name. Ensure Firecracker will have the required permissions to open
these resources.

Both network and block support IO rate limiting. This is done by using the
`rate_limiter` optional field(s) in the device setup API call.

Limits are defined by configuring each of the `bandwidth` and `ops` token
buckets. A token bucket is defined by configurable `size`, `one_time_burst`
and `refill_time` (milliseconds).

The bucket _refill-rate_ is derived from `size` and `refill_time`, and it is
the constant rate at which the tokens replenish. An initial burst size
(`one_time_burst`) can also be specified and it represents the budget that
can be consumed once with an unlimited rate.

It is worth mentioning that the refill process only starts taking place after
the initial burst size is completely consumed. Also, bursts are unbounded in
speed but bounded in size. Once the token bucket is empty, consumption speed
is bound by the _refill_rate_.

A token bucket with either `size == 0` or `refill_time == 0` will be
inactive/unlimited. Tokens are `bytes` for _bandwidth limiting_ and
`operations` for _ops/s limiting_, and time is specified in milliseconds.

#### Network

For example, if using a TUN/TAP device, you will need to create it beforehand:

``` bash
sudo ip tuntap add name vmtap33 mode tap
sudo ifconfig vmtap33 192.168.241.1/24 up
```

And then call the `/network-interfaces` API resource with its name and desired
properties:

- Interface ID is `1`
- Host device is `vmtap33`
- Guest mac is `06:00:00:00:00:01`
- RX _Bandwith_ rate limit is `100 MBps` and _Ops/s_ rate is unlimited
  - `100 MBps` example token bucket with an initial burst size of `2 Gbytes`
    and refill time of `1000 milliseconds`
- No TX rate limiting of any kind
- State is `attached`

```bash
curl --unix-socket ${socket} -i \
     -X PUT "http://localhost/network-interfaces/1" \
     -H "accept: application/json" \
     -H "Content-Type: application/json" \
     -d "{
            \"iface_id\": \"1\",
            \"host_dev_name\": \"vmtap33\",
            \"guest_mac\": \"06:00:00:00:00:01\",
            \"rx_rate_limiter\": {
              \"bandwidth\": { \"size\": 104857600,
                                \"one_time_burst\": 2147483648,
                                \"refill_time\": 1000
                             }
            },
            \"state\": \"Attached\"
        }"
```

#### Storage

Firecracker uses file backed block devices, exposing them to the guest OS. The
root filesystem should contain the OS image that boots with the kernel.
Multiple block devices can be attached the same way to the microVM. For
example, to add an empty 100 MiB scratch block device, with an `ext4`
filesystem:

```bash
dd if=/dev/zero of=${scratch_file} bs=1M count=100
mkfs.ext4 ${scratch_file}

curl --unix-socket ${socket} -i \
     -X PUT "http://localhost/drives/scratch" \
     -H "accept: application/json" \
     -H "Content-Type: application/json" \
     -d "{
            \"drive_id\": \"scratch\",
            \"path_on_host\": \"${scratch_file}\",
            \"is_root_device\": false,
            \"is_read_only\": true
         }"
```

The path of the backing file can be updated later, both before and after the
guest has booted. This is achievable via a `PATCH` to the same `/drives`
resource, specifying the drive ID and the new path.

```bash
curl --unix-socket ${socket} -i \
     -X PATCH "http://localhost/drives/scratch" \
     -H "accept: application/json" \
     -H "Content-Type: application/json" \
     -d "{
            \"drive_id\": \"scratch\",
            \"path_on_host\": \"${new_scratch_file}\"
         }"
```

If the file has been resized on the host while the guest is running, the guest
OS needs to be notified in order to pick up the changes. First, unmount the
filesystem on the _guest_, if it was mounted. After that, trigger a rescan with
a `PUT` to the `/actions` resource, specifying the ID of the rescanned drive in
the `payload` field:

```bash
curl --unix-socket ${socket} -i \
     -X PUT "http://localhost/actions" \
     -H  "accept: application/json" \
     -H  "Content-Type: application/json" \
     -d "{
            \"action_type\": \"BlockDeviceRescan\",
            \"payload\": \"scratch\"
         }"
```

After the rescan, the filesystem can be safely remounted in the guest.

### Configure the microVM Metadata Store (MMDS)

Each Firecracker process has an associated MMDS, which is essentially a
treelike key-value store backed by a JSON representation. We strive to provide
a guest facing experience which closely resembles the behavior of the EC2 IMDS,
documented [here](
https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
).

MMDS contents are initialized using `PUT` requests to the `/mmds` `API`
resource. Updates are possible via `PATCH` requests. Both use cases are
illustrated in the `test_mmds` function from
[tests/integration_tests/functional/test_mmds.py](
tests/integration_tests/functional/test_mmds.py). 

### Power-On the MicroVM

Simply issue the `InstanceStart` action to the `/actions` API resource.
This is an synchronous API request. You can check the response with a get
on the same path.

``` bash
# Start the Firecracker MicroVM
curl --unix-socket ${socket} -i \
     -X PUT "http://localhost/actions" \
     -H  "accept: application/json" \
     -H  "Content-Type: application/json" \
     -d "{
            \"action_type\": \"InstanceStart\"
         }"
```

### Notes

1. It is the user's responsibility to make sure that the same backing file is
   not added as a read-write block device to multiple Firecracker instances. A
   file can be safely added as a read-only block device to multiple Firecracker
   instances.
1. Firecracker is started without the serial console for performance reasons.
   You can use the following boot_args if you need the serial console:
   `console=ttyS0 reboot=k panic=1 pci=off nomodules`
1. Firecracker uses default values for the following parameters:
   1. Kernel Command Line:
      `reboot=k panic=1 pci=off nomodules 8250.nr_uarts=0`. This can be
      changed via the `/boot-source`.
   1. Number of vCPUs: 1. Default Memory Size: 128 MiB. Hyperthreading is
      disabled. CPU Template: None.
   1. Unix domain socket: `/tmp/firecracker.socket`.
1. Firecracker links the microVM serial console output to its stdout, and its
   stdin to the microVM serial console input. Therefore, you can interact with
   the microVM guest in the screen session.

### Caveats

1. The unix domain socket is not deleted when Firecracker is stopped.
   You have to remove it yourself after stopping the Firecracker process.
1. Firecracker doesn't yet emulate a power management device. This means that
   any shutdown/poweroff/halt commands issued by the guest OS will not work as
   intended.

### Getting Started Code Example

For a full example, you can take a look at the `test_api_happy_start` test in
[tests/functional/test_api.py](tests/functional/test_api.py), and at the
`basic_config` method of the `Microvm` class in
[tests/microvm.py](tests/microvm.py).
