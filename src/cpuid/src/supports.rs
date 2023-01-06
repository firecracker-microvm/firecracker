// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::cmp::Ordering;

#[allow(clippy::wildcard_imports)]
use super::leaves::*;
use super::registers;

/// Trait defining if a CPUID component supports another.
pub trait Supports {
    /// Error type.
    type Error;

    /// Returns `Ok(())` if `self` supports `other` or `Err(reason)` if it does not.
    ///
    /// # Errors
    ///
    /// When `self` does not support `other`.
    fn supports(&self, other: &Self) -> Result<(), Self::Error>;
}

/// Logs a warning depending on which registers where not fully checked within a leaf.
macro_rules! warn_support {
    ($a:literal, $eax:literal, $ebx:literal, $ecx:literal, $edx:literal) => {
        if let Some(msg) = $crate::support_warn($eax, $ebx, $ecx, $edx) {
            log::warn!(
                "Could not fully validate support for CPUID leaf {} due to being unable to fully \
                 compare register/s: {}.",
                $a,
                msg
            );
        }
    };
}

pub(crate) use warn_support;

/// Returns a static string depending on the register booleans.
#[allow(clippy::fn_params_excessive_bools)]
pub(crate) const fn support_warn(
    eax: bool,
    ebx: bool,
    ecx: bool,
    edx: bool,
) -> Option<&'static str> {
    match (eax, ebx, ecx, edx) {
        (true, true, true, true) => None,
        (false, true, true, true) => Some("EAX"),
        (true, false, true, true) => Some("EBX"),
        (true, true, false, true) => Some("ECX"),
        (true, true, true, false) => Some("EDX"),
        (false, false, true, true) => Some("EAX and EBX"),
        (false, true, false, true) => Some("EAX and ECX"),
        (false, true, true, false) => Some("EAX and EDX"),
        (true, false, false, true) => Some("EBX and ECX"),
        (true, false, true, false) => Some("EBX and EDX"),
        (true, true, false, false) => Some("ECX and EDX"),
        (false, false, false, true) => Some("EAX, EBX and ECX"),
        (false, false, true, false) => Some("EAX, EBX and EDX"),
        (false, true, false, false) => Some("EAX, ECX and EDX"),
        (true, false, false, false) => Some("EBX, ECX and EDX"),
        (false, false, false, false) => Some("EAX, EBX, ECX and EDX"),
    }
}

/// Error type for [`<Leaf0 as Supports>::supports`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Leaf0NotSupported {
    /// Maximum input value.
    #[error("Maximum input value: {0} < {1}.")]
    MaximumInputValue(u32, u32),
    /// Manufacturer ID.
    #[error("Manufacturer ID: {0:?} != {1:?}.")]
    ManufacturerId([u32; 3], [u32; 3]),
}

impl Supports for Leaf0 {
    type Error = Leaf0NotSupported;
    /// We check the manufacturer id e.g. 'GenuineIntel' is an exact match and that
    /// 'Maximum Input Value for Basic CPUID Information.' is >=
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        warn_support!("0x0", true, true, true, true);

        if !(self.ebx == other.ebx && self.ecx == other.ecx && self.edx == other.edx) {
            return Err(Leaf0NotSupported::ManufacturerId(
                [self.ebx, self.ecx, self.edx],
                [other.ebx, other.ecx, other.edx],
            ));
        }
        if self.eax < other.eax {
            return Err(Leaf0NotSupported::MaximumInputValue(self.eax, other.eax));
        }

        Ok(())
    }
}

/// Error type for [`<Leaf1 as Supports>::supports`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Leaf1NotSupported {
    /// CLFlush.
    #[error("CLFlush")]
    CLFlush,
    /// MaxAddressableLogicalProcessorIds
    #[error("MaxAddressableLogicalProcessorIds")]
    MaxAddressableLogicalProcessorIds,
    /// Ecx
    #[error("Ec")]
    Ecx,
    /// Edx
    #[error("Edx")]
    Edx,
}

impl Supports for Leaf1 {
    type Error = Leaf1NotSupported;
    /// We check ECX and EDX are super sets and 'CLFLUSH line size' >= and
    /// 'Maximum number of addressable IDs for logical processors in this physical package' >=
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        warn_support!("0x1", false, false, true, true);

        if self.ebx.clflush() < other.ebx.clflush() {
            return Err(Leaf1NotSupported::CLFlush);
        }
        if self.ebx.max_addressable_logical_processor_ids()
            < other.ebx.max_addressable_logical_processor_ids()
        {
            return Err(Leaf1NotSupported::MaxAddressableLogicalProcessorIds);
        }

        // We ignore `tsc_deadline` and `osxs` by masking them both to 0 in `self` and `other` in
        // the comparison.
        {
            let (self_ecx_masked, other_ecx_masked) = {
                let mask = {
                    let mut temp = registers::Leaf1Ecx::from(0);
                    temp.tsc_deadline_mut().on();
                    temp.osxsave_mut().on();
                    !temp
                };
                (self.ecx & mask, other.ecx & mask)
            };
            if matches!(
                self_ecx_masked.cmp_flags(&other_ecx_masked),
                Some(Ordering::Less) | None
            ) {
                return Err(Leaf1NotSupported::Ecx);
            }
        }

        // We ignore `htt` by masking it to 0 in `self` and `other` in the comparison.
        {
            let (self_edx_masked, other_edx_masked) = {
                let mask = {
                    let mut temp = registers::Leaf1Edx::from(0);
                    temp.htt_mut().on();
                    !temp
                };
                (self.edx & mask, other.edx & mask)
            };
            if matches!(
                self_edx_masked.cmp_flags(&other_edx_masked),
                Some(Ordering::Less) | None
            ) {
                return Err(Leaf1NotSupported::Edx);
            }
        }

        Ok(())
    }
}
