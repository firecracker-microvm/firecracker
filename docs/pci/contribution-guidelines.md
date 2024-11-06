# PCIe Support in Firecracker Community Roadmap

This document describes the high-level changes required to support PCIe and device passthrough in Firecracker
and the main responsibilities of the maintainers and the community to achieve the success of the initiative.
This document will be discussed during the November 6, 2024 meeting.
I will upload this document as a PR to the [poc/pcie](https://github.com/firecracker-microvm/firecracker/tree/poc/pcie)
branch so that everybody will have the opportunity to leave comments along the way.

## Motivation

Firecracker currently supports only MMIO devices. 
By adding support for PCIe we would get the following benefits:

* Increase max attached device count - up to 31 devices on a single PCI bus, with up to 256 buses, 
  if we add support for multiple buses.
* Ability to assign multiple interrupts per device (MSI-X) - opens the door for I/O scalability / MQ devices
    * MSI-X interrupts also improve virtio-pci performance over virtio-mmio which uses legacy IRQ
* device hot-plugging through PCIe Hotplug
* pass-through of physical devices, like GPUs or EBS volumes, through VFIO.

## Challenges

Supporting PCIe in Firecracker and, in particular, device pass-through, introduces new challenges. Namely:

* **overheads:** supporting the full PCI specification might negatively impact the boot time and 
  memory overheads of Firecracker VMs. 
    * We can mitigate this by allowing for completely disabling PCIe support via VM configuration 
      when more lightweight virtualization is preferred.
* **oversubscription:** simple PCIe device passthrough using VFIO requires the VMM to allocate the 
  entire physical memory of the VM to allow for DMA from the device.
    * Solutions to this exist, the most promising being virtio-iommu, but also swiotlb and PCI ATS/PRI
* **security**: the device has access to the entire guest physical memory, which may change the 
  security posture of firecracker. 
    * The device will need to be cleared before being attached to avoid cross-VM interferences.
    * Compatibility with the secret-hiding initiative to harden Firecracker security posture needs 
      to be carefully evaluated.
* **snapshot/resume**: it will likely not be possible to snapshot external PCIe devices, 
  therefore snapshot/resume will not be supported for active/online passed-through devices.
    * support for resumption with offline device should be possible
    * an alternative to this could be hotplugging a device after resume

## Contribution Guidelines

Before diving deeper into the required changes in Firecracker, it’s important to be clear on the 
responsibility splitbetween the community contributors and the maintainers. 
As this is a community-driven initiative, it will be responsibility of contributors to propose designs, 
make changes, and work with the upstream rust-vmm community. 
Maintainers of Firecracker will provide guidance, code reviews, project organization, facilitate rust-vmm 
interactions, and automated testing of the new features.

### Contributors

* PCIe-specific development will happen on a separate feature branch `features/pcie` which maintainers will setup, 
  with all the required CI artifacts and infrastructure.
* Code refactors to enable PCI features should be split in a refactor merged into main and a PCI-specific part 
  merged into the feature branch. 
  For example, we need to rework FC device management to support PCI, the development will need to be done in main,
  and then merged to the PCIe feature branch.
* Generic code that is not specific to Firecracker should be discussed with the upstream rust-vmm community, and, 
  if possible, merged in rust-vmm, unless explicit exemption is granted by the maintainers.
* Contributors should provide design documents in case of features spanning multiple PRs to receive
  early guidance from maintainers.
* Contributors should not leave open PRs stale for more than two weeks.
* All usual contribution guidelines apply: [CONTRIBUTING.md](https://github.com/firecracker-microvm/firecracker/blob/main/CONTRIBUTING.md).

### Maintainers

* Maintainers will create a separate feature branch and periodically rebase it on top of main
  (every 3 weeks or on-demand in case of dependencies).
* Maintainers will provide a POC reference implementation showcasing basic PCIe support: 
  [poc/pcie](https://github.com/firecracker-microvm/firecracker/tree/poc/pcie).
  The POC is just a scrappy implementation and will need to be rewritten from scratch to meet the quality 
  and security bars of Firecracker.
* Maintainers will prepare CI artifacts for PCIe-specific testing, adding separate artifacts with 
  PCIe support (eg guest kernels)
* Maintainers will setup test-on-PR for the feature branch to run on PCIe specific artifacts
* Maintainers will setup nightly functional and performance testing on the PCIe feature branch
* Maintainers will create a new project on GitHub to track the progress of the project using public github issues
* Maintainers will organize periodic meeting sync-ups with the community to organize the work (proposed every 2 weeks)
* Maintainers will provide guidance around the code changes
* Maintainers will review new PRs to the feature branch within one week. 
  Two approvals from maintainers are required to merge a PR. 
  Maintainers should provide the required approvals or guidance to unblock the PR to unblock within two weeks.
* Maintainers will work with the internal Amazon security team to review the changes 
  before every merge of the feature branch in main. 
  Any finding will be shared with the community to help address the issues.

### Acceptance Criteria

A proposal of the different milestones of the project is defined in the following sections. 
Each milestone identifies a point in the project where a merge of the developed features in the main branch is possible.
In order to accept the merge:

* All Firecracker features and architectures are supported for PCIe (for example, Snapshot Resume, and ARM).
* All functional and security tests should pass with the PCIe feature enabled on all supported devices.
* Open-source performance tests should not regress with the PCIe feature enabled compared to MMIO devices.
* Internal performance tests should not regress with the PCIe feature enabled. 
  In case of regressions, details and reproducers will be shared with the community.
* Approval from internal Amazon security team needs to be granted. 
  In case of blockers, details will be shared with the community.
* Overhead of firecracker must not increase significantly (more than 5%)
* Oversubscription of firecracker VMs should not be impaired by the changes. 
  Exceptions can be granted if there is a path forward towards mitigation (for example, in the case of VFIO support).

## Milestones

This section describes a proposed high-level plan of action to be discussed with the community.
A more detailed plan will need to be provided by contributors before starting the implementation, 
which maintainers will help refine.

### 0. Proof of Concept and Definition of Goals

It is important that both maintainers and the community build confidence with the changes 
and verify that it’s possible to achieve the respective goals with this solution. 
For this reason, the Firecracker team has built a public proof-of-concept with basic PCI passthrough and virtio-pci support:
[poc/pcie](https://github.com/firecracker-microvm/firecracker/tree/poc/pcie).
The implementation of the POC is scrappy and would require a complete rewrite from scratch that meets 
Firecracker quality and security bars, but it showcases the main features (and drawbacks) of 
PCIe-passthrough and virtio-pci devices.

Before starting the actual implementation below, we need to be able to answer:

* what are the benefits to internal and external customers for supporting PCIe in firecracker?
* how is performance going to improve for virtio devices?
* what are the additional overheads to boot time and memory?
* what are the limitations of PCIe-passthrough? How can we avoid them?

### 1. virtio-pci support

The first milestone will be the support of the virtio-pci transport layer for virtio.
This is not strictly required for PCIe device passthrough, but we believe it is the easier way to get
the bulk of the PCI code merged into firecracker and rust-vmm, as there shouldn’t be any concerns from
the security and over-subscription point of view.

With this milestone, Firecracker customers will be able to configure any device to be attached on the
PCI bus instead of the MMIO bus through a per-device config.
If no device in the VM uses PCI, no PCI bus will be created and there will be no changes over the current state.
PCI support will be a first-class citizen of Firecracker and will be compiled in the official releases of Firecracker.

Maintainers will:

* setup a new feature branch
* setup testing artifacts and infrastructure (automated test-on-PR and nightly tests on the new branch).
* provide guidance and reviews to the community
* share performance results from public and internal tests
* drive the security review with Amazon Security

A proposed high-level plan for the contributions is presented below. 
A more detailed plan will need to be provided by contributors before starting the implementation.

* refactor Firecracker device management code to make it more extensible and work with the PCI bus.
* refactor Firecracker virtio code to abstract the transport layer (mmio vs pci).
* implement PCI-specific code to emulate the PCI root device and the PCI configuration space.
    * if possible, it would be ideal to create a new PCI crate in rust-vmm. 
      A good starting point is cloud-hypervisor implementation.
* (x86) implement the MMCONFIG extended PCI configuration space for x86.
* (ARM) expose the PCI root device in the device tree (double check).
* implement the virtio-pci transport code with legacy irq
* implement MSI-X interrupts
    * MSI-X is an enhanced way for the device to deliver interrupts to the driver, 
      allowing for up to 2048 interrupt lines per device
* add support for snapshot-resume for the virtio-pci devices and PCI bus.

Open questions:

* will it be possible to upstream the pci crate in rust-vmm? 
  Will it require using rust-vmm crates not yet used in Firecracker (vm-devices, vm-allocator, ...)? 
  How much work will it be to refactor FC device management to start using those crates as well?
* do we need to support PCI BAR relocation as well?
* will we need to maintain both PCI and MMIO transport layers for virtio devices?

### 2. PCIe-passthrough support design

The second milestone will be the design of the support of VFIO-based PCI-passthrough 
which will allow passing to the guest any PCIe device from the host. 
This design will need to answer the still open questions around snapshot/resume and VM oversubscriptability,
and will guide the implementation of the following milestones.

In particular, the main problems to solve are:

* how do we allow for oversubscriptability of VMs with VIRTIO devices?
    * some ideas are to use virtio-iommu or a swiotlb or PCI ATS/PRI
* how do we securely perform DMA from the device if we enable “secret hiding”.
    * "Secret hiding" is the un-mapping the guest physical memory from the host kernel address space 
      to remove sensible information from it, protecting it from speculative execution attacks.
    * one idea is the use of a swiotlb in the guest
* how do we manage the snapshot/resume of these vfio devices?
    * can we snapshot/resume with an offline device? Do we need to support hotplugging?

To enable prototyping of this milestone, maintainers will setup test artifacts and infrastructure to
test on Nvidia GPUs on PR and nightly.
Maintainers will also start early consultation with Amazon Security to identify additional requirements.

### 3. Basic PCIe-passthrough support implementation

This proposed milestone will cover the basic implementation of PCIe device-passthrough via VFIO.
With this milestone, Firecracker customers will be able to attach any and as many VFIO devices to the VM before boot.
However, customers will not be able to oversubscribe memory of VMs with PCI-passthrough devices, 
as the entire guest physical memory needs to be allocated for DMA.
It should be possible, depending on the investigations in milestone 2, to snapshot/resume a VM with an offlined VFIO device.

We expect this change to be fairly modular and self-contained as it builds upon the first milestone,
adding just an additional device type.
The biggest hurdle will be the thorough security review and the considerations around its usefulness for internal customers.

We expect the biggest hurdles for this change to be the security review, as it’s a change in the current Firecracker threat model.
Furthermore, a path forward towards full oversubscribability needs to be identified and prototyped for this milestone to be accepted.

### 4. Over-subscriptable PCIe-passthrough VMs

Depending on the investigations in milestone 2, we need to implement a way to oversubscribe memory
from VMs with PCI-passthrough devices.
The challenge is that the hypervisor needs to know in advance which guest physical memory ranges will be used by DMA. 

One way to do it would be to ask the guest to configure a virtual IOMMU to enable DMA from the device.
In this case, the hypervisor will know which memory ranges the guest is using for DMA so that they can be granularly pre-allocated.
This could be done through the `virtio-iommu` device.

One alternative could be PCI ATS/PRI or using a swiotlb in the guest.
