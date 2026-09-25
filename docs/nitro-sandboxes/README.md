# Nitro Sandboxes

A Nitro Sandbox is a lightweight virtual machine launched by a process inside an
Amazon EC2 instance. It runs alongside that instance, isolated from it by the
AWS Nitro System. The instance that launches a sandbox is its *parent*, and it
contributes the vCPUs and memory the sandbox runs on. For more details on the
security design of the AWS Nitro System, see
[The Security Design of the AWS Nitro System](https://docs.aws.amazon.com/whitepapers/latest/security-design-of-aws-nitro-system/security-design-of-aws-nitro-system.html).

A sandbox runs in one of two modes. In *confidential* mode, the default, the
parent has no access to the sandbox's memory and the workload can attest what it
runs. In *direct* mode the parent keeps access to that memory, reducing I/O
overhead. For more about the two modes, see
[Memory modes](how-it-works.md#memory-modes).

Firecracker can launch and manage Nitro Sandboxes as an alternative backend to
KVM, from release v1.18. Instead of creating a microVM through `/dev/kvm`, it
uses the Linux Nitro Enclaves driver at `/dev/nitro_enclaves` to create,
configure and boot a sandbox with a standard virtio-pci device model with block,
network, vsock and, in direct mode, entropy devices, all backed by Firecracker
in the parent instance. Because sandboxes build on
[AWS Nitro Enclaves](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html),
Firecracker calls a sandbox an *enclave* in its API, configuration and error
messages, for example `PUT /enclave` and the `enclave` key of the configuration
file. For more about the naming, see [Enclave](#glossary) in the glossary.

![Nitro Sandbox architecture](../images/enclave-architecture.png?raw=true "Nitro Sandbox architecture")

The guest inside the sandbox runs a standard Linux kernel with virtio-pci
drivers, plus the DMB (Device Memory Buffer) virtio patches in confidential
mode. For more about the guest kernel requirements, see
[Guest kernel](getting-started.md#guest-kernel).

Sandboxes run on instance types that support AWS Nitro Enclaves, on x86_64 and
AWS Graviton. For the supported instance types, see
[Parent instance](getting-started.md#parent-instance).

These documents cover running sandboxes with Firecracker. For the Nitro
Sandboxes feature as a whole, including an overview of its isolation model,
supported instance types and per-instance limits, see the Nitro Sandboxes topic
of the
[Amazon EC2 User Guide](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/amazon-ec2-nitro-sandboxes.html).

## Contents

- [How it works](how-it-works.md). The isolation model, the two memory modes,
  how a sandbox boots, and its lifecycle.
- [Getting started](getting-started.md). What the parent instance, parent kernel
  and guest kernel need, worked examples, and troubleshooting.
- [Features](features.md). Devices, hotplug, CPU allocation and accounting, NUMA
  placement, attestation, the serial console, and the jailer.
- [Comparison with KVM microVMs](comparison-with-kvm.md). Which Firecracker
  features apply to a sandbox, how the two modes differ, and the limits.

## When to use a Nitro Sandbox

A Nitro Sandbox gives a container-scale workload the isolation of an EC2
instance without dedicating an instance to it. The parent runs no hypervisor of
its own, as it would with KVM on a bare-metal instance or under nested
virtualization. Isolation holds in both directions: a sandbox cannot access the
parent's memory or another sandbox's, and in confidential mode the parent cannot
access the sandbox's either. For how a sandbox differs from a KVM microVM in
Firecracker, see [Comparison with KVM microVMs](comparison-with-kvm.md).

Typical uses are isolating containers or Kubernetes pods from each other in a
multi-tenant cluster, with many sandboxes on one instance, and running attested
containers or lightweight virtual machines, where a confidential sandbox proves
its isolation and integrity through the Nitro Secure Module (NSM) before it
receives secrets.

## Glossary

| Term                  | Meaning                                                                                                                                                                                                                                                                                                                                                                                      |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Parent instance**   | The EC2 instance a sandbox is launched from. It contributes the sandbox's vCPUs and memory and runs its device backends.                                                                                                                                                                                                                                                                     |
| **Parent operator**   | Whoever runs the parent instance. When sandboxes are driven with Firecracker directly, the parent operator builds the guest images, runs the device backends and accounts for the resources the parent contributes.                                                                                                                                                                          |
| **Sandbox**           | The isolated virtual machine itself.                                                                                                                                                                                                                                                                                                                                                         |
| **Confidential mode** | The default mode. The parent has no access to the sandbox's memory, device I/O goes through DMBs, and the sandbox can attest what it runs. For more about the two modes, see [Memory modes](how-it-works.md#memory-modes).                                                                                                                                                                   |
| **Direct mode**       | The mode where the parent keeps read/write access to the sandbox's memory. It has no attestation, and the guest does not need the DMB virtio drivers. For more about the two modes, see [Memory modes](how-it-works.md#memory-modes).                                                                                                                                                        |
| **Enclave**           | The term the Firecracker API and code base use for a sandbox, because sandboxes are built on Nitro Enclaves. The configuration endpoint is `PUT /enclave`, its errors name enclaves, and the kernel interface is `/dev/nitro_enclaves`. Read it as a synonym for sandbox throughout. It is not the same thing as an AWS Nitro Enclave, which has a single vsock channel and no device model. |
| **Frontend**          | The process in the parent that owns a sandbox's API, device backends and lifecycle. Firecracker is one such frontend.                                                                                                                                                                                                                                                                        |
| **EIF**               | Enclave Image Format, the measured boot artifact a sandbox boots from. For its contents and the two ways to obtain one, see [Booting](how-it-works.md#booting).                                                                                                                                                                                                                              |
| **DMB**               | Device Memory Buffer, a per-device memory region shared between the guest and the device backend in the parent, in which that device's virtqueues live. Confidential mode uses one per device, sized by its `dmb_size_mib`. For more about sizing DMBs, see [DMB size](features.md#dmb-size).                                                                                                |
| **NSM**               | Nitro Secure Module, the attestation device present in a confidential sandbox. It measures the sandbox at boot and signs attestation documents. For more about attestation, see [Attestation](features.md#attestation).                                                                                                                                                                      |
| **PCR**               | Platform Configuration Register, one of the measurement slots the NSM records the sandbox's contents into and reports in an attestation document.                                                                                                                                                                                                                                            |
| **CPU pool**          | CPUs on the parent instance that may be handed to sandboxes as dedicated cores. It holds whole cores and reports its size in CPU threads.                                                                                                                                                                                                                                                    |
| **Memory pool**       | The physically contiguous parent memory the driver donates to sandboxes, accounted per NUMA node.                                                                                                                                                                                                                                                                                            |
| **Slot**              | The Nitro System resource each sandbox occupies from creation to exit. The parent's slot budget caps how many sandboxes it can hold at once. For more about the slot budget, see [Slot budget](getting-started.md#slot-budget).                                                                                                                                                              |
| **Donation**          | Handing parent memory to a sandbox. In confidential mode the parent loses access to it until the sandbox exits; in direct mode the parent keeps access.                                                                                                                                                                                                                                      |
