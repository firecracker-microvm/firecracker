// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::fadt::Fadt;

#[inline(always)]
pub(crate) fn fadt_platform_init(_fadt: &mut Fadt) {}

pub(crate) fn create_apic_structures(_num_cpus: usize) -> Vec<u8> {
    vec![]
}

pub(crate) fn local_interrupt_controller_address() -> u32 {
    0
}
