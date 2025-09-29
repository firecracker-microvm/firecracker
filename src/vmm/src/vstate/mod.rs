// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Module with the implementation of a Bus that can hold devices.
pub mod bus;
/// VM interrupts implementation.
pub mod interrupts;
/// Module with Kvm implementation.
pub mod kvm;
/// Module with GuestMemory implementation.
pub mod memory;
/// Resource manager for devices.
pub mod resources;
/// Module with Vcpu implementation.
pub mod vcpu;
/// Module with Vm implementation.
pub mod vm;
