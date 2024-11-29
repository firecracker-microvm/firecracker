# PCIe Support in Firecracker Community Roadmap

This document describes the high-level changes required to support PCIe and
device passthrough in Firecracker and the main responsibilities of the
maintainers and the community to achieve the success of the initiative. This
document was first reviewed on November 6, 2024 and will go through a second
round of review on December 4, 2024. I will upload this document as a PR to the
[poc/pcie](https://github.com/firecracker-microvm/firecracker/tree/poc/pcie)
branch so that everybody will have the opportunity to leave comments along the
way.

## Goals

### MVP

These are the minimal set of goals that we are aiming to achieve:

- Introduce PCIe root complex emulation in Firecracker
  - we should implement PCIe topology from the get-go, and not the legacy PCI
    bus topology.
- Introduce PCIe support for virtual devices (virtio-pci)
  - increases max attached device count - up to 31 devices on a single PCI bus,
    with up to 256 buses, if we add support for multiple buses.
  - allows assigning multiple interrupts per device (MSI-X), improving the
    performance of virtio devices, over legacy IRQ, and opening the door for I/O
    scalability / MQ devices.
- Introduce basic support for VFIO-based physical device passthrough
  - at the bare minimum, ability to pass through and use a single physical GPU
  - initially, this will come at the cost of memory oversubscription (see
    Challenges below)
  - snapshot/resume of an offlined device, or reset after resumption, should be
    supported.

### Stretch Goals

While we would like to get to do these goals, their priority will need to be
revisited once we have completed the MVP:

- Support of native PCIe hotplugging
- Memory oversubscription with passed-through devices

### Out of Scope

We are not looking to support the following features in the medium term, to
focus on the core PCIe implementation. These will be reprioritized after the
goals above have been completed.

- Multi-function devices
- Passthrough of virtual functions (SR-IOV, vGPU)
- PCIe peer-to-peer communication
- GPUDirect Storage
- GPU metrics and observability (eg DCGM) inside Firecracker
  - users of Firecracker will need to build their own monitoring solution around
    the tools offered by Firecracker, like vsock and network ports.
- Snapshot/resume of the internal physical device state

## Challenges

Supporting PCIe in Firecracker and, in particular, device pass-through,
introduces new challenges. Namely:

- **overheads:** supporting the full PCIe specification might negatively impact
  the boot time and memory overheads of Firecracker VMs.
  - For virtio-pci devices, Firecracker will have built-in PCIe support that
    could be toggled on a per-VM basis through VM config or the HTTP API. This
    would allow for use cases that don't want to enable PCIe to keep the
    overheads and kernel footprint low (lightweight virtualization).
  - Regarding support for passed-through VFIO devices, we imagine that support
    would initially be offered as an optional compilation feature.
- **oversubscription:** simple PCIe device passthrough using VFIO requires the
  VMM to allocate the entire physical memory of the VM to allow for DMA from the
  device.
  - Solutions to this exist, the most promising being virtio-iommu, but also
    swiotlb and PCI ATS/PRI
- **security**: the device has access to the entire guest physical memory, which
  may change the security posture of firecracker.
  - The device will need to be cleared before being attached to avoid cross-VM
    interferences.
  - Compatibility with the secret-hiding initiative to harden Firecracker
    security posture needs to be carefully evaluated.
- **snapshot/resume**: it will likely not be possible to snapshot external PCIe
  devices, therefore, snapshot/resume will not be supported for active/online
  passed-through devices.
  - support for resumption with offline device should be possible
  - an alternative to this could be hotplugging a device after resume

## Contribution Guidelines

Before diving deeper into the required changes in Firecracker, it’s important to
be clear on the responsibility split between the maintainers and the community
contributors. As this is a community-driven initiative, it will be the
responsibility of contributors to propose designs, make changes, and work with
the upstream rust-vmm community. Maintainers of Firecracker will provide
guidance, code reviews, project organization, facilitate rust-vmm interactions,
and automated testing of the new features.

### Maintainers

- (DONE) Maintainers will create a separate feature branch `features/pcie` and
  periodically rebase it on top of main (every 3 weeks or on-demand in case of
  required dependencies)
- (DONE) Maintainers will provide a POC reference implementation showcasing
  basic PCIe support:
  [poc/pcie](https://github.com/firecracker-microvm/firecracker/tree/poc/pcie).
  The POC is just a scrappy implementation and will need to be rewritten from
  scratch to meet the quality and security bars of Firecracker.
- (DONE) Maintainers will prepare CI artifacts for PCIe-specific testing, adding
  separate artifacts with PCIe support (eg guest kernels)
- Maintainers will setup test-on-PR for the feature branch to run on PCIe
  specific artifacts
- Maintainers will setup nightly functional and performance testing on the PCIe
  feature branch
- Maintainers will create a new project on GitHub to track the progress of the
  project using public github issues
- (DONE) Maintainers will organize periodic meeting sync-ups with the community
  to organize the work (proposed every 2 weeks)
- Maintainers will provide guidance around the code changes
- Maintainers will review new PRs to the feature branch within one week. Two
  approvals from maintainers are required to merge a PR. Maintainers should
  provide the required approvals or guidance to unblock the PR to unblock within
  two weeks.
- Maintainers will work with the internal Amazon security team to review the
  changes before every merge of the feature branch in main. Any finding will be
  shared with the community to help address the issues.

### Contributors

- Contributors should provide design documents in case of features spanning
  multiple PRs to receive early guidance from maintainers.
- Contributors should not leave open PRs stale for more than two weeks.
- Code refactors to enable PCI features should be split in a refactor merged
  into main and a PCI-specific part merged into the feature branch. For example,
  we need to rework FC device management to support PCI, the development will
  need to be done in main, and then merged to the PCIe feature branch.
- Generic code that is not specific to Firecracker should be discussed with the
  upstream rust-vmm community, and, if possible, merged in rust-vmm, unless
  explicit exemption is granted by the maintainers.
- All usual contribution guidelines apply:
  [CONTRIBUTING.md](https://github.com/firecracker-microvm/firecracker/blob/main/CONTRIBUTING.md).

### Acceptance Criteria

A proposal of the different milestones of the project is defined in the
following sections. Each milestone identifies a point in the project where a
merge of the developed features in the main branch is possible. In order to
accept the merge:

- All Firecracker features and supported CPU architectures are working with PCIe
  - for example, Snapshot/Resume, and ARM
  - exceptions can be agreed in cases where a path forward is identified and
    planned.
- All functional and security tests should pass with the PCIe feature enabled on
  all supported devices.
- Open-source performance tests should not regress with both PCIe enabled or
  disabled for all devices, when compared to MMIO devices. In other words:
  - there should be no performance difference for virtio-MMIO devices in case
    PCIe is opted out.
  - there should be no performance regression for virtio-PCI devices compared to
    virtio-MMIO, in case PCI is opted in.
- Internal performance tests should not regress with the PCIe feature enabled.
  In case of regressions, details and reproducers will be shared with the
  community.
- Approval from internal Amazon security team needs to be granted. In case of
  blockers, details will be shared with the community.
- Overhead of firecracker (startup latency, memory footprint) must not increase
  significantly (more than 5%)
- Oversubscription of firecracker VMs should not be impaired by the changes.
  - Exceptions can be granted if there is a path forward towards mitigation (for
    example, in the case of VFIO support).

## Milestones

This section describes a proposed high-level plan of action to be discussed with
the community. A more detailed plan will need to be provided by contributors
before starting the implementation, which maintainers will help refine.

### 0. Proof of Concept and Definition of Goals

It is important that both maintainers and the community build confidence with
the changes and verify that it’s possible to achieve the respective goals with
this solution. For this reason, the Firecracker team has built a public
proof-of-concept with basic PCI passthrough and virtio-pci support:
[poc/pcie](https://github.com/firecracker-microvm/firecracker/tree/poc/pcie).
The implementation of the POC is scrappy and would require a complete rewrite
from scratch that meets Firecracker quality and security bars, but it showcases
the main features (and drawbacks) of PCIe-passthrough and virtio-pci devices.

Before starting the actual implementation below, we need to be able to answer:

- what are the benefits to internal and external customers for supporting PCIe
  in firecracker?
- how is performance going to improve for virtio devices?
- what are the additional overheads to boot time and memory?
- what are the limitations of PCIe-passthrough? How can we avoid them?

### 1. virtio-pci support

The first milestone will be the support of the virtio-pci transport layer for
virtio. This is not strictly required for PCIe device passthrough, but we
believe it is the easier way to get the bulk of the PCIe code merged into
firecracker and rust-vmm, as there shouldn’t be any concerns from the security
and over-subscription point of view.

With this milestone, Firecracker customers will be able to configure any virtual
device to be attached to the PCIe root complex instead of the MMIO bus through a
per-device config. If no device in the VM uses PCIe, no PCIe functionality will
be created and there will be no changes over the current state. PCIe support
will be a first-class citizen of Firecracker and will be compiled in the
official releases of Firecracker.

Maintainers will:

- setup a new feature branch
- setup testing artifacts and infrastructure (automated test-on-PR and nightly
  tests on the new branch).
- provide guidance and reviews to the community
- share performance results from public and internal tests
- drive the security review with Amazon Security

A proposed high-level plan for the contributions is presented below. A more
detailed plan will need to be provided by contributors before starting the
implementation.

- refactor Firecracker device management code to make it more extensible and
  work with the PCIe bus.
- refactor Firecracker virtio code to abstract the transport layer (mmio vs
  pci).
- implement PCI-specific code to emulate the PCI root device and the PCI
  configuration space.
  - if possible, it would be ideal to create a new PCI crate in rust-vmm. A good
    starting point is cloud-hypervisor implementation.
- (ARM) expose the PCIe root device in the device tree (FDT).
- (x86) implement the MMCONFIG (ECAM) extended PCI configuration space for x86.
- implement the virtio-pci transport code with legacy IRQ
- implement MSI-X interrupts
  - MSI-X is an enhanced way for the device to deliver interrupts to the driver,
    allowing for up to 2048 interrupt lines per device
- add support for snapshot-resume for the virtio-pci devices and PCI bus.

Open questions:

- will it be possible to upstream the pci crate in rust-vmm? Will it require
  using rust-vmm crates not yet used in Firecracker (vm-devices, vm-allocator,
  ...)? How much work will it be to refactor FC device management to start using
  those crates as well?
- do we need to support PCI BAR relocation as well?
  - This should not be a requirement.
- will we need to maintain both PCI and MMIO transport layers for virtio
  devices?
  - Most likely yes

### 2. PCIe-passthrough support design

The second milestone will be the design of the support of VFIO-based
PCIe-passthrough which will allow passing to the guest any physical PCIe device
from the host. This design will need to answer the still open questions around
snapshot/resume and VM oversubscriptability, and will guide the implementation
of the following milestones.

In particular, the main problems to solve are:

- how do we allow for oversubscriptability of VMs with VIRTIO devices?
  - some ideas are to use virtio-iommu or a swiotlb or PCI ATS/PRI
- how do we securely perform DMA from the device if we enable “secret hiding”.
  - "Secret hiding" is the un-mapping of the guest physical memory from the host
    kernel address space to remove sensible information from it, protecting it
    from speculative execution attacks.
  - one idea is the use of a swiotlb in the guest
- how do we manage the snapshot/resume of these vfio devices?
  - can we snapshot/resume with an offline device? Do we need to support
    hotplugging?
- how do we correctly present the right PCIe topology to the guest?
  - the topology will impact the performance of the devices

To enable prototyping of this milestone, maintainers will setup test artifacts
and infrastructure to test on Nvidia GPUs on PR and nightly. Maintainers will
also start early consultation with Amazon Security to identify additional
requirements.

### 3. Basic PCIe-passthrough support implementation

This proposed milestone will cover the basic implementation of PCIe
device-passthrough via VFIO. With this milestone, Firecracker customers will be
able to attach any and as many VFIO devices to the VM before boot. However,
customers will not be able to oversubscribe memory of VMs with PCI-passthrough
devices, as the entire guest physical memory needs to be allocated for DMA. It
should be possible, depending on the investigations in milestone 2, to
snapshot/resume a VM with an offlined VFIO device.

We expect this change to be fairly modular and self-contained as it builds upon
the first milestone, adding just an additional device type. The biggest hurdle
will be the thorough security review and the considerations around its
usefulness for internal customers.

We expect the biggest hurdles for this change to be the security review, as it’s
a change in the current Firecracker threat model. Furthermore, a path forward
towards full oversubscribability needs to be identified and prototyped for this
milestone to be accepted.

### Stretch Goals

Once we reach the MVP goals with the milestones above, we'll need to prioritize
the stretch goals:

#### Memory Oversubscription

Depending on the investigations in milestone 2, we need to implement a way to
oversubscribe memory from VMs with PCI-passthrough devices. The challenge is
that the hypervisor needs to know in advance which guest physical memory ranges
will be used by DMA.

One way to do it would be to ask the guest to configure a virtual IOMMU to
enable DMA from the device. In this case, the hypervisor will know which memory
ranges the guest is using for DMA so that they can be granularly pre-allocated.
This could be done through the `virtio-iommu` device.

One alternative could be PCI ATS/PRI or using a swiotlb in the guest.

#### PCIe hotplugging

This needs to be investigated further, but it's a highly requested feature for
the containerization world (eg Kata containers). One challenge to keep in mind
is the PCIe aperture size of the devices to be hotplugged, which might not be
known in advance, and which requires additional care.

## Appendix

### Meeting Notes

#### November 6, 2024

1. The plan needs more clarity on the objectives and features supported for the
   MVP, refining the acceptance criteria to narrow down the targeted use-cases.
   - are we going to support one single or multiple GPUs? If multiple, what
     about P2P? _We are aiming for simple support of a single GPU._
   - are we going to support just PF or also VF? _In the initial iteration,
     we're focusing on PF, but VF is something we want and we will call it out
     explicitly_
   - are we going straight to hotplugging or do we want to focus on
     cold-plugging first? _In the MVP, we want to focus on simple cold plugging
     with the intention to support hotplugging in the future._
     - note that hotplugging is a requirement for Kata-like workloads due to
       their API. Also, it introduces issues around detecting PCI root port
       topology as the required aperture size might not be known in advance as
       it depends on GPU.
     - note that PCIe native hotplugging is only supported with PCIe root ports
   - what about other features like GPU-direct, NVME support? _Will not be
     supported in the first iterations._
1. We discussed about new features introduced in VFIO core from kernel 6.1,
   supporting `iommufd` as backend. We will look into these.
1. The kata-containers initiative for confidential compute is interested in
   including Firecracker GPU support. Details on how they interact with hardware
   devices can be found here (thanks @zvonkok):
   - Virtualization Reference Architecture:
     https://github.com/kata-containers/kata-containers/blob/main/docs/design/kata-vra.md
   - What happens if you type kubectl apply -f kata-gpu-pod.yaml
     https://docs.google.com/presentation/d/13TDKyASpMfDrVBSRj4JiU6gFeChx0ws4DTenBN1qUnA/edit?usp=sharing
   - The Kubernetes KEP: https://github.com/kubernetes/enhancements/pull/4113
   - Issues tracking the crio and containerd changes:
     https://github.com/cri-o/cri-o/issues/8321,
     https://github.com/containerd/containerd/issues/10282

Next steps:

1. Firecracker team will review the draft roadmap to address the comments
   identified in the meeting #4894
1. Firecracker team will setup testing artifacts with PCIe support for the first
   milestone (just virtio-pci device support, no GPU or device passthrough yet).

- artifacts are available in
  s3://spec.ccfc.min/firecracker-ci/v1.11-pcie-poc/$ARCH
