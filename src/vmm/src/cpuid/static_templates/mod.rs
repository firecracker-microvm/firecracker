// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_arch = "x86_64")]
use crate::arch_gen::x86::msr_index::MSR_IA32_ARCH_CAPABILITIES;

/// Hardcoded C3 template
#[cfg(target_arch = "x86_64")]
pub mod c3;
/// Hardcoded T2 template
#[cfg(target_arch = "x86_64")]
pub mod t2;
/// Hardcoded T2a template
#[cfg(target_arch = "x86_64")]
pub mod t2a;
/// Hardcoded T2cl template
#[cfg(target_arch = "x86_64")]
pub mod t2cl;
/// Hardcoded T2s template
#[cfg(target_arch = "x86_64")]
pub mod t2s;

/// Tolerance for TSC frequency expected variation.
/// The value of 250 parts per million is based on
/// the QEMU approach, more details here:
/// https://bugzilla.redhat.com/show_bug.cgi?id=1839095
#[cfg(target_arch = "x86_64")]
pub const TSC_KHZ_TOL: f64 = 250.0 / 1_000_000.0;

#[allow(clippy::missing_docs_in_private_items)]
#[cfg(target_arch = "x86_64")]
static EXTRA_MSR_ENTRIES: &[u32] = &[MSR_IA32_ARCH_CAPABILITIES];

/// Return a list of MSRs specific to this T2S template.
#[inline]
#[must_use]
#[cfg(target_arch = "x86_64")]
pub fn msr_entries_to_save() -> &'static [u32] {
    EXTRA_MSR_ENTRIES
}
