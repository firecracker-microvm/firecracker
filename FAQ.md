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
Machine Monitor (crosvm), an open source VMM written in Rust. Today, crosvm and
Firecracker have diverged to serve very different customer needs. We plan to
contribute bug fixes and tests for Rust crates that originated from crosvm, and
any Firecracker functionality that's appealing for crosvm.

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

The Firecracker VMM is built to be processor agnostic. Today, it can run on
Intel processors. AMD and ARM processors will be supported in the near future.

### Can Firecracker be used with Kata containers, Kubernetes or Docker today?

Since release
[1.5.0](https://github.com/kata-containers/runtime/releases/tag/1.5.0)
of Kata Containers, support for the Firecracker VMM has been included.
Docker CLI and Kubernetes can be used with Firecracker when configured
with Kata containers, but there are limitations with Kubernetes use cases.
There is also a work in progress on
[Firecracker-containerd](https://github.com/firecracker-microvm/firecracker-containerd)
to enable containerd to manage containers as Firecracker microVMs. We hope
that others in the communities that build open source container technology find
it useful. We are working to make Firecracker integrate naturally with the
container ecosystem, with the goal to provide seamless integration in the future
to provide more choices in how container workloads are isolated.

### What is the difference between Firecracker and Kata Containers and QEMU?

Kata Containers is an OCI-compliant container runtime that executes containers
within QEMU based virtual machines. Firecracker is a cloud-native alternative to
QEMU that is purpose-built for running containers safely and efficiently, and
nothing more. Firecracker provides a minimal required device model to the guest
operating system while excluding non-essential functionality (there are only 4
emulated devices: virtio-net, virtio-block, serial console, and a 1-button
keyboard controller used only to stop the microVM). This, along with a
streamlined kernel loading process enables a < 125 ms startup time and a reduced
memory footprint. The Firecracker process also provides a RESTful control API,
handles resource rate limiting for microVMs, and provides a microVM metadata
service to enable the sharing of configuration data between the host and guest.

### What operating systems are supported by Firecracker?

Firecracker supports Linux host and guest operating systems with kernel versions
4.14 and above. The long-term support plan is still under discussion. A leading
option is to support Firecracker for the last two Linux stable branch releases.

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

### Are there plans to make Firecracker an OpenStack or CNCF project?

Not at the moment.

## Technical FAQ & Troubleshooting

### I tried using an initrd for boot but it doesn't seem to be used. Is initrd supported?
Right now, initrd is not supported in Firecracker. You can track issue
[#228](https://github.com/firecracker-microvm/firecracker/issues/208) for news on this
topic.

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
