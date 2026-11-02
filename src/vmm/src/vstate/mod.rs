// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Module with the implementation of a Bus that can hold devices.
pub mod bus;
/// Consumer of the ring KVM buffers coalesced MMIO and port I/O writes in.
#[cfg(target_arch = "x86_64")]
pub mod coalesced_io;
/// VM interrupts implementation.
pub mod interrupts;
/// Module with Kvm implementation.
pub mod kvm;
/// Module with GuestMemory implementation.
pub mod memory;
/// Resolved ranges of guest memory.
pub mod memory_slice;
/// Resource manager for devices.
pub mod resources;
/// Module with Vcpu implementation.
pub mod vcpu;
/// Module with Vm implementation.
pub mod vm;
