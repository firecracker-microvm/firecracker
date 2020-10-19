![Firecracker Logo Title](docs/images/fc_logo_full_white-bg.png)

Our mission is to enable secure, multi-tenant, minimal-overhead execution of
container and function workloads.

Read more about the Firecracker Charter [here](CHARTER.md).

## What is Firecracker?

Firecracker is an open source virtualization technology that is purpose-built
for creating and managing secure, multi-tenant container and function-based
services that provide serverless operational models. Firecracker runs workloads
in lightweight virtual machines, called microVMs, which combine the security and
isolation properties provided by hardware virtualization technology with the
speed and flexibility of containers.

## Overview
The main component of Firecracker is a virtual machine monitor (VMM) that uses
the Linux Kernel Virtual Machine (KVM) to create and run microVMs. Firecracker
has a minimalist design. It excludes unnecessary devices and guest-facing
functionality to reduce the memory footprint and attack surface area of each
microVM. This improves security, decreases the startup time, and increases
hardware utilization. Firecracker has also been integrated in container runtimes,
for example
[Kata Containers](https://github.com/kata-containers/documentation/wiki/Initial-release-of-Kata-Containers-with-Firecracker-support)
and [Weaveworks Ignite](https://github.com/weaveworks/ignite).

Firecracker was developed at Amazon Web Services to accelerate the speed and
efficiency of services like [AWS Lambda](https://aws.amazon.com/lambda/) and
[AWS Fargate](https://aws.amazon.com/fargate/). Firecracker is open
sourced under [Apache version 2.0](LICENSE).

To read more about Firecracker, check out
[firecracker-microvm.io](https://firecracker-microvm.github.io).

## Getting Started

To get started with Firecracker, download the latest
[release](https://github.com/firecracker-microvm/firecracker/releases) binaries
or build it from source.

You can build Firecracker on any Unix/Linux system that has Docker running
(we use a development container) and `bash` installed, as follows:

```bash
git clone https://github.com/firecracker-microvm/firecracker
cd firecracker
tools/devtool build
toolchain="$(uname -m)-unknown-linux-musl"
```

The Firecracker binary will be placed at
`build/cargo_target/${toolchain}/debug/firecracker`. For more information on
building, testing, and running Firecracker, go to the
[quickstart guide](docs/getting-started.md).

The overall security of Firecracker microVMs, including the ability to meet the
criteria for safe multi-tenant computing, depends on a well configured Linux
host operating system. A configuration that we believe meets this bar is
included in [the production host setup document](docs/prod-host-setup.md).

## Contributing

Firecracker is already running production workloads within AWS, but it's still
Day 1 on the journey guided by our [mission](CHARTER.md). There's a lot more to
build and we welcome all contributions.

To contribute to Firecracker, check out the development setup section in the
[getting started guide](docs/getting-started.md) and then the Firecracker
[contribution guidelines](CONTRIBUTING.md).

## Releases

New Firecracker versions are released via the GitHub repository
[releases](https://github.com/firecracker-microvm/firecracker/releases) page,
typically every two or three months. A history of changes is recorded in our
[changelog](CHANGELOG.md).

The Firecracker release policy is detailed [here](docs/RELEASE_POLICY.md).

## Design

Firecracker's overall architecture is described in
[the design document](docs/design.md).

## Features & Capabilities

Firecracker consists of a single micro Virtual Machine Manager process that
exposes an API endpoint to the host once started. The API is
[specified in OpenAPI format](src/api_server/swagger/firecracker.yaml). Read more
about it in the [API docs](docs/api_requests).

The **API endpoint** can be used to:

- Configure the microvm by:
  - Setting the number of vCPUs (the default is 1).
  - Setting the memory size (the default is 128 MiB).
  - Choosing a CPU template (currently, C3 and T2 are available).
- Add one or more network interfaces to the microVM.
- Add one or more read-write or read-only disks to the microVM, each represented
  by a file-backed block device.
- Trigger a block device re-scan while the guest is running. This enables the
  guest OS to pick up size changes to the block device's backing file.
- Change the backing file for a block device, before or after the guest boots.
- Configure rate limiters for virtio devices which can limit the bandwidth,
  operations per second, or both.
- Configure the logging and metric system.
- `[BETA]` Configure the data tree of the guest-facing metadata service. The
  service is only available to the guest if this resource is configured.
- Add a [vsock socket](docs/vsock.md) to the microVM.
- Start the microVM using a given kernel image, root file system, and boot
  arguments.
- Stop the microVM.

**Built-in Capabilities**:

- Demand fault paging and CPU oversubscription enabled by default.
- Advanced seccomp filters for enhanced security.
- [Jailer](docs/jailer.md) process for starting Firecracker in production
  scenarios; applies a cgroup/namespace isolation barrier and then
  drops privileges.

## Supported platforms

We continuously test Firecracker on machines with the following CPUs 
micro-architectures: Intel Skylake, Intel Cascade Lake, AMD Zen2, ARM Cortex-A 
aarch64.

Firecracker is [generally available](docs/RELEASE_POLICY.md) on Intel x86_64 
and AMD x86_64 CPUs that offer hardware virtualization support, and that are 
released starting with 2015. All production use cases should follow [these 
production host setup instructions](docs/prod-host-setup.md).

Firecracker is in [developer preview](docs/RELEASE_POLICY.md) (and not 
supported for production workloads) on CPUs based on Arm Cortex-A aarch64 cores
 that offer hardware virtualization support, and that are released starting 
with 2015.

Firecracker may work on other x86 and Arm 64-bit CPUs with support for hardware 
virtualization, but any such platform is currently not supported and not fit 
for production. If you want to run Firecracker on such platforms, please 
[open a feature request](https://github.com/firecracker-microvm/firecracker/issues/new?assignees=&labels=&template=feature_request.md&title=%5BFeature+Request%5D+Title).

## Performance

Firecracker's performance characteristics are listed as part of the
[specification documentation](SPECIFICATION.md). All specifications are a part
of our commitment to supporting container and function workloads in serverless
operational models, and are therefore enforced via continuous integration
testing.

## Policy for Security Disclosures

The security of Firecracker is our top priority. If you suspect you have
uncovered a vulnerability, contact us privately, as outlined in our
[security policy document](SECURITY.md); we will immediately prioritize
your disclosure.

## FAQ & Contact

Frequently asked questions are collected in our [FAQ doc](FAQ.md).

You can get in touch with the Firecracker community in the following ways:
- Security-related issues, see our [security policy document](SECURITY.md).
- Chat with us on our
  [Slack workspace](https://join.slack.com/t/firecracker-microvm/shared_invite/enQtNDY2NTUwMzQ3MDE1LWIwMzA0OWFkMTZhMTlmMDZiMmFkYjMyODMxMGQ1ZjliMzJjNjJiNWRhNWNkOGEyNmUxNmRkMjZhYTc3MmVjZjM).
  _Note: most of the maintainers are on a European time zone._
- Open a GitHub issue in this repository.
- Email the maintainers at
  [firecracker-maintainers@amazon.com](mailto:firecracker-maintainers@amazon.com).

When communicating within the Firecracker community, please mind our
[code of conduct](CODE_OF_CONDUCT.md).
