// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//

// Typically, on x86 systems 24 IRQs are used (0-23).
/// First usable IRQ ID for virtio device interrupts on x86_64.
pub const IRQ_BASE: u32 = 5;
/// Last usable IRQ ID for virtio device interrupts on x86_64.
pub const IRQ_MAX: u32 = 23;
