// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Layout for this aarch64 system.
pub mod layout;
/// Logic for configuring aarch64 registers.

/// The start of the memory area reserved for MMIO devices.
pub const MMIO_MEM_START: u64 = layout::MAPPED_IO_START;
/// The size of the memory area reserved for MMIO devices.
pub const MMIO_MEM_SIZE: u64 = layout::DRAM_MEM_START - layout::MAPPED_IO_START; //>> 1GB
