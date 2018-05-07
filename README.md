# What is Firecracker

Firecracker is a new virtualization technology that enables customers to deploy lightweight *micro* Virtual Machines or microVMs. Firecracker microVMs combine the security and workload isolation properties of traditional VMs with the speed and resource efficiency enabled by containers. MicroVMs can initiate user-space code execution in less than 150ms, have a footprint of less than 32 MiB of memory, and provide a secure, trusted environment for multi-tenant services. Customers can create microVMs with any combination of vCPU and memory to match their application requirements.

MicroVMs are created and managed by the Firecracker process, which implements a virtual machine manager based on Linux's Kernel-based Virtual Machine (KVM), the state of art for Linux virtualization. Firecracker provides the minimal required device emulation to the guest operating system while excluding non-essential functionality to enable faster startup time and a reduced memory footprint. The Firecracker process also provides a control API, enforces microVM sandboxing, and handles resource rate limiting for microVMs.

# Overview

Firecracker consists of a single micro Virtual Machine Manager binary that will spawn a RESTful API endpoint when started. The API endpoint can be used to:
* Add one or more vCPUs to the microVM.
* Add memory to the microVM.
* Add one or more network interfaces to the microVM.
* Add one or more read/write disks (block devices) to the microVM.
* Start the microVM using a given kernel image and root file system.
* Stop the microVM.

## What's Included in the current version?
* One-process virtual machine manager (one Firecracker per microVM).
* RESTful API running on a unix socket. The API supported by the current version can be found at `api/swagger/firecracker-beta.yaml`.
* Emulated keyboard (i8042) and serial console (UART). The microVM serial console input and output are connected to those of the Firecracker process (this allows direct console access to the guest OS).
* The capability of mapping an existing host tun-tap device as a virtIO/net device into the microVM.
* The capability of mapping an existing host file as a virtIO/block device into the microVM.
* Default demand fault paging & CPU oversubscription.

## Limits and Performance

So far, no stress testing & benchmarking has been done. This is scheduled for a pater timeframe. A couple of manual tests indicate that at least 2000 Firecracker microVMs and 2000 TUN/TAP devices work (under no stress) on an i3p instance.

# Getting Started

## Add musl target to the active toolchain
Firecracker supports musl-only build, so before building the project add the musl target to rust's active toolchain:
```bash
rustup target add x86_64-unknown-linux-musl
```

## Build the Firecracker Binary
Clone this repo and build it with Rust's: `cargo build --release`.

## Secure a Host with KVM Access
To build, test, or run, Firecracker requires a host with a modern version of KVM (Linux kernel 4.11+) running on physical hardware (or a virtual machine with nested virtualization enabled).

## Firecracker's Take on Resources
Firecracker expects network interfaces and drives to be created beforehand and passed by name. Ensure Firecracker will have the required permissions to open these resources. For example, if using a TUN/TAP device, you will need to create this beforehand, and call the `/network-interfaces` API with the name of the host TUN/TAP interface.

## Select the Guest Kernel and RootFS
To run microVMs with Firecracker, you will need to have:
* a guest kernel image that boots and runs with Firecracker's minimal/VirtIO device model
* a guest root file system that boots with that kernel (can be an image file or drive).

## Runtime Dependencies
* Firecracker needs rw access to `/dev/kvm`. You can grant these rights, e.g., to all users, with: `sudo chmod a+rw /dev/kvm`.

## Start Firecracker & the Micro VM

The python-based toy example below will start a Firecracker microVM with 2 vCPUs, 256 MiB or RAM, two network interfaces and two disks (rootfs and temp).

Currently, only the core parts of the API (`/actions`, `/machine-config`, `/boot-source`, `/network-interfaces` and `/drives`) are implemented. For the planned v1.0 API description see `/api/swagger/firecracker-v1.0.yaml`.

The toy example snapshot below uses a Python script to start a Firecracker instance. The Firecracker binary, as well as compatible kernel, root file system, and temp file system images are assumed to already exist. The TUN/TAP devices passed to the networking API are also assumed to already exist.

The full example can be found in [the examples directory](examples/hello_api/spawn_microvm.py)

```
# Spawn a new Firecracker Virtual Machine Manager process.
firecracker = Firecracker('0001')
firecracker.spawn()

# Give the api time to come online since we don't handle retries here.
time.sleep(0.0042)

# Configure the microVM CPU and memory.
requests.put(firecracker.machine_config_url, json={'vcpu_count': 2})
requests.put(firecracker.machine_config_url, json={'mem_size_mib': 256})

# Add a network interface to the microVM.
# Firecracker will map this host network interface into the microVM.
requests.put(
    firecracker.network_ifaces_url + '/1',
    json={
        'iface_id': '1',
        'host_dev_name': 'fc0001tap1',
        'state': 'Attached'
    }
)

# Add another network interface to the microVM.
# Firecracker will map this host network interface into the microVM.
requests.put(
    firecracker.network_ifaces_url + '/2',
    json={
        'iface_id': '2',
        'host_dev_name': 'fc0001tap2',
        'state': 'Attached'
    }
)

# Add a disk (block device) to the microVM.
# This one will be flagged as the root file system.
requests.put(
    firecracker.drives_url + '/1',
    json={
        'drive_id': '1',
        'path_on_host': '/tmp/firecracker0001/ami-rootfs.ext4',
        'state': 'Attached',
        'permissions': 'rw',
        'is_root_device': True
    }
)

# Add another disk (block device) to the microVM.
# This one is empty, usable for, e.g., guest scratch space.
requests.put(
    firecracker.drives_url + '/2',
    json={
        'drive_id': '2',
        'path_on_host': '/tmp/firecracker0001/scratch.ext4',
        'state': 'Attached',
        'permissions': 'rw',
        'is_root_device': False
    }
)

# Specify a boot source: a kernel image.
# Currently, only linux kernel images are supported.
requests.put(
    firecracker.boot_source_url,
    json={
        'boot_source_id': '1',
        'source_type': 'LocalImage',
        'local_image': {'kernel_image_path': '/tmp/vmlinux.bin'},
    }
)

# Start!
requests.put(
    firecracker.actions_url + '/1',
    json={'action_id': '1', 'action_type': 'InstanceStart'}
)
```

## Notes
1. The Kernel and RootFS need to work together, and the Kernel needs to run with Firecracker's limited device model.
2. It is the user's responsibility to make sure that the same backing file is not added as a read-write block device to multiple Firecracker instances. A file can be safely added as a read-only block device to multiple Firecracker instances.
3. Firecracker uses default values for the following parameters:
    1. Kernel Command Line: `console=ttyS0 noapic reboot=k panic=1 pci=off nomodules`. This can be changed with a `PUT` request to `/boot-source`.
    2. Number of vCPUs: 1. This can be changed with a `PUT` request to `/machine-config`
    3. Memory Size: 128 MiB. This can be changed with a `PUT` request to `/machine-config`
    4. Unix domain socket: `/tmp/firecracker.socket`. This can be changed only when Firecracker is started, by using the command line parameter `--api-sock`.
4. Firecracker links the microVM serial console output to its stdout, and its stdin to the microVM serial console input. Therefore, you can interact with the microVM guest in the screen session.
5. Important: The unix domain socket is not deleted when Firecracker is stopped. You have to remove it yourself after stopping the Firecracker process.
6. Firecracker doesn't yet emulate a power management device. This means that any shutdown/poweroff command issued by the guest OS only does partial shutdown then hangs. The linux 'reboot' command when run in the guest OS will actually cleanly shut down the guest without bringing it back up.
