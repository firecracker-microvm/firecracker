# Firecracker Frequently Asked Questions

## About Firecracker

### What is Firecracker?

Firecracker is an open source Virtual Machine Monitor (VMM) that
enables secure, multi-tenant, minimal-overhead execution of container
and function workloads.

### Who developed Firecracker?

Firecracker was built by developers at Amazon Web Services to enable services
such as [AWS Lambda](https://aws.amazon.com/lambda/) and [AWS
Fargate](https://aws.amazon.com/fargate/) to improve resource utilization and
customer experience, while providing the security and isolation required of
public cloud infrastructure. Firecracker started from Chromium OS's Virtual
Machine Monitor,
[crosvm](https://chromium.googlesource.com/chromiumos/platform/crosvm/), an open
source VMM written in Rust. Today, crosvm and Firecracker have diverged to
serve very different customer needs. [Rust-vmm](https://github.com/rust-vmm) is
an open source community where we collaborate with the crosvm maintainers and
other groups and individuals to build and share quality Rust virtualization
components.

### Why did you develop Firecracker?

When we launched Lambda in November of 2014, we were focused on providing a
secure [serverless](https://aws.amazon.com/serverless/) experience. At launch we
used per-customer EC2 instances to provide strong security and isolation between
customers. As Lambda grew, we saw the need for technology to provide a highly
secure, flexible, and efficient runtime environment for services like Lambda and
Fargate. Using our experience building isolated EC2 instances with hardware
virtualization technology, we started an effort to build a VMM that was tailored
to integrate with container ecosystems.

### What processors does Firecracker support?

The Firecracker VMM is built to be processor agnostic. Intel processors are
supported for production workloads. Support for AMD and Arm processors is in
developer preview.

### Can Firecracker be used within the container ecosystem?

Yes. Firecracker is integrated with
[Kata Containers](https://github.com/kata-containers/documentation/wiki/Initial-release-of-Kata-Containers-with-Firecracker-support),
[Weave FireKube](https://www.weave.works/oss/firekube/) (via
[Weave Ignite](https://github.com/weaveworks/ignite)), and containerd via
[firecracker-containerd](https://github.com/firecracker-microvm/firecracker-containerd).
We welcome contributions that enable Firecracker to integrate naturally with the
container ecosystem and provide more choices in how container workloads are
isolated.

### What is the difference between Firecracker and QEMU?

Firecracker is an
[alternative to QEMU](https://www.redhat.com/en/blog/all-you-need-know-about-kvm-userspace)
that is purpose-built for running serverless functions and containers safely and
efficiently, and nothing more. Firecracker is written in Rust, provides a
minimal required device model to the guest operating system while excluding
non-essential functionality (only 5 emulated devices are available: virtio-net,
virtio-block, virtio-vsock, serial console, and a minimal keyboard controller
used only to stop the microVM). This, along with a streamlined kernel loading
process enables a < 125 ms startup time and a < 5 MiB memory footprint. The
Firecracker process also provides a RESTful control API, handles resource rate
limiting for microVMs, and provides a microVM metadata service to enable the
sharing of configuration data between the host and guest.

### What operating systems are supported by Firecracker?

Firecracker supports Linux host and guest operating systems with kernel versions
4.14 and above, as well as
[OSv](http://blog.osv.io/blog/2019/04/19/making-OSv-run-on-firecraker/) guests.
The long-term support plan is still under discussion.

### What is the open source license for Firecracker?

Firecracker is licensed under the Apache License, version 2.0, allowing you to
freely use, copy, and distribute your changes under the terms of your choice.
[Read more about Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0).
Crosvm code sections are licensed under a
[BSD-3-Clause license](https://opensource.org/licenses/BSD-3-Clause) that also
allows you to use, copy, and distribute your changes under the terms of your
choice.

### How can I contribute?

Firecracker is an AWS open source project that encourages contributions from
customers and the developer community. Any contribution is welcome as long as it
aligns with our [charter](CHARTER.md). You can learn more about how to
contribute in [CONTRIBUTING.md](CONTRIBUTING.md). You can chat with others in
the community on the [Firecracker Slack
workspace](https://firecracker-microvm.slack.com).

### How is Firecracker project governed?

The Firecracker [team at Amazon Web Services](MAINTAINERS.md) owns project
maintainer responsibilities, permissions to merge pull requests, and the ability
to create new Firecracker releases.

## Technical FAQ & Troubleshooting

### I tried using an initrd for boot but it doesn't seem to be used. Is initrd supported?

Initrds are only recently supported in Firecracker. If your release predates
issue [#228](https://github.com/firecracker-microvm/firecracker/issues/208)
being resolved, please update.

### Firecracker is not showing any output on the console.

In order to debug the issue, check the response of the `InstanceStart` API
request. Possible responses:

- **Error**: Submit a new issue with the label "Support: Failure".
- **Success**: If the boot was successful, you should get a response with 204
  as the status code.

If you have no output in the console, most likely you will have to update the
kernel command line. By default, Firecracker starts with the serial console
disabled for boot time performance reasons.

Example of a kernel valid command
line that enables the serial console (which goes in the `boot_args` field of
the `/boot-source` Firecracker API resource):

```
console=ttyS0 reboot=k panic=1 pci=off nomodules
```

### How can I configure multiple Ethernet devices through the kernel command line?

The `ip=` boot param in the linux kernel only actually supports configuring a
single interface. Multiple interfaces can be set up in Firecracker using the
API, but guest IP configuration at boot time through boot arguments can only be
done for a single interface.

### My guest wall-clock is drifting, how can I fix it?

The canonical solution is to use NTP in your guests.

However, if you want to run Firecracker at scale, we suggest using a PTP emulated
device as the guest's NTP time source so as to minimize network traffic and
resource overhead. With this solution the guests will constantly update time
to stay in sync with host wall-clock. They do so using cheap para-virtualized
calls into kvm ptp instead of actual network NTP traffic.

To be able to do this you need to have a guest kernel compiled with `KVM_PTP`
support:
```
CONFIG_PTP_1588_CLOCK=y
CONFIG_PTP_1588_CLOCK_KVM=y
```
Our [recommended guest kernel config](resources/microvm-kernel-config) already
has these included.

Now `/dev/ptp0` should be available in the guest. Next you need to configure
`/dev/ptp0` as a NTP time source.

For example when using `chrony`:

1. Add `refclock PHC /dev/ptp0 poll 3 dpoll -2 offset 0` to the chrony conf
file (`/etc/chrony/chrony.conf`)
2. Restart the `chrony` daemon.

You can see more info about the `refclock` parameters
[here](https://chrony.tuxfamily.org/doc/3.4/chrony.conf.html#refclock).
Adjust them according to your needs.

### Each Firecracker opens 20+ file descriptors. Is this an issue?

The relatively high FD usage is expected and correct. Firecracker heavily
relies on event file descriptors to drive device emulation.

### How does network interface numbering work?

There is no relation between the numbering of the `/network-interface` API calls
and the number of the network interface in the guest. Rather, it is usually
the order of network interface creation that determines the number in the guest
(but this depends on the distribution).

For example, when you create two network interfaces by calling
`/network-interfaces/1` and then `/network-interfaces/0`, it may result in this
mapping:

```
/network-interfaces/1 -> eth0
/network-interfaces/0 -> eth1
```

### How can I gracefully reboot the guest? How can I gracefully poweroff the guest?

Firecracker does not implement ACPI and PM devices, therefore operations like
gracefully rebooting or powering off the guest are supported in unconventional ways.

Running the `poweroff` or `halt` commands inside a Linux guest will bring it down but
Firecracker process remains unaware of the guest shutdown so it lives on.

Running the `reboot` command in a Linux guest will gracefully bring down the guest
system and also bring a graceful end to the Firecracker process.

Issuing a `SendCtrlAltDel` action command through the Firecracker API will generate a
`Ctrl + Alt + Del` keyboard event in the guest resulting in a clean reboot on most
guest Linux systems.

### How can I create my own rootfs or kernel images?

Check out our [rootfs and kernel image creation guide](
docs/rootfs-and-kernel-setup.md).

### We are seeing page allocation failures from Firecracker in the `dmesg` output.

If you see errors like ...

```
[<TIMESTAMP>] fc_vmm: page allocation failure: order:6, mode:0x140c0c0
(GFP_KERNEL|__GFP_COMP|__GFP_ZERO), nodemask=(null)
[<TIMESTAMP>] fc_vmm cpuset=<GUID> mems_allowed=0
```

... then your host is running out of memory. KVM is attempting to do an
allocation of 2^`order` bytes (in this case, 6) and there aren't sufficient
contiguous pages.

Possible mitigations are:
- Track the failing allocations in the `dmesg` output and rebuild the host
  kernel so as to use `vmalloc` instead of `kmalloc` for them.
- Reduce memory pressure on the host.

### How can I configure and start a microVM without sending API calls?

Passing an optional command line parameter, `--config-file`, to the Firecracker
process allows this type of configuration. This parameter must be the path to a
file that contains the JSON specification that will be used to configure and start
the microVM. One example of such file can be found at `tests/framework/vm_config.json`.

### Firecracker fails to start and returns an Out of Memory error

If the Firecracker process exits with `12` exit code (`Out of memory` error), the root
cause is that there is not enough memory on the host to be used by the Firecracker microVM.

If the microVM was not configured in terms of memory size through an API request,
the host needs to meet the minimum requirement in terms of free memory size,
namely 128 MB of free memory which the microVM defaults to.

### Firecracker fails to start and returns "Resource busy" error

If another hypervisor like VMware or VirtualBox is running on the host and locks `/dev/kvm`,
Firecracker process will fail to start with "Resource busy" error.

This issue can be resolved by terminating the other hypervisor running on the host,
and allowing Firecracker to start.
