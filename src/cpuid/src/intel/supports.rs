// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::cmp::Ordering;

#[allow(clippy::wildcard_imports)]
use super::leaves::*;
use crate::{warn_support, Supports};

/// Error type for [`<Leaf5 as Supports>::supports`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Leaf5NotSupported {
    /// SmallestMonitorLineSize.
    #[error("SmallestMonitorLineSize.")]
    SmallestMonitorLineSize,
    /// LargestMonitorLineSize.
    #[error("LargestMonitorLineSize.")]
    LargestMonitorLineSize,
    /// Ecx.
    #[error("Ecx.")]
    Ecx,
}

impl Supports for Leaf5 {
    type Error = Leaf5NotSupported;
    /// We check everything here.
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        warn_support!("0x5", true, true, true, false);
        // We compare `<=` therefore `Ordering::Less` corresponds  greater support and to
        // `Ordering::Greater` for support, thus we reverse the result of the comparison.
        if self.eax.smallest_monitor_line_size() > other.eax.smallest_monitor_line_size() {
            return Err(Leaf5NotSupported::SmallestMonitorLineSize);
        }
        if self.ebx.largest_monitor_line_size() < other.ebx.largest_monitor_line_size() {
            return Err(Leaf5NotSupported::LargestMonitorLineSize);
        }
        if matches!(self.ecx.cmp_flags(&other.ecx), Some(Ordering::Less) | None) {
            return Err(Leaf5NotSupported::Ecx);
        }

        Ok(())
    }
}

/// Error type for [`<Leaf6 as Supports>::supports`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Leaf6NotSupported {
    /// Eax.
    #[error("Eax.")]
    Eax,
    /// NumberOfInterruptThresholdsInDigitalThermalSensor.
    #[error("NumberOfInterruptThresholdsInDigitalThermalSensor.")]
    NumberOfInterruptThresholdsInDigitalThermalSensor,
    /// IntelThreadDirectorClasses.
    #[error("IntelThreadDirectorClasses.")]
    IntelThreadDirectorClasses,
    /// Ecx.
    #[error("Ecx.")]
    Ecx,
}

impl Supports for Leaf6 {
    type Error = Leaf6NotSupported;
    /// We do not currently check EDX.
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        warn_support!("0x6", true, true, true, false);
        match self.eax.cmp_flags(&other.eax) {
            Some(Ordering::Greater | Ordering::Equal) => (),
            Some(Ordering::Less) | None => {
                return Err(Leaf6NotSupported::Eax);
            }
        }
        if self
            .ebx
            .number_of_interrupt_thresholds_in_digital_thermal_sensor()
            < other
                .ebx
                .number_of_interrupt_thresholds_in_digital_thermal_sensor()
        {
            return Err(Leaf6NotSupported::NumberOfInterruptThresholdsInDigitalThermalSensor);
        }
        if self.ecx.intel_thread_director_classes() < other.ecx.intel_thread_director_classes() {
            return Err(Leaf6NotSupported::IntelThreadDirectorClasses);
        }
        if matches!(self.ecx.cmp_flags(&other.ecx), Some(Ordering::Less) | None) {
            return Err(Leaf6NotSupported::Ecx);
        }

        Ok(())
    }
}

/// Error type for [`<Leaf7 as Supports>::supports`] and [`<Leaf7Mut as Supports>::supports`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Leaf7NotSupported {
    /// MissingSubleaf0.
    #[error("MissingSubleaf0.")]
    MissingSubleaf0,
    /// Subleaf0.
    #[error("Subleaf0: {0}")]
    Subleaf0(Leaf7Subleaf0NotSupported),
    /// MissingSubleaf1.
    #[error("MissingSubleaf1.")]
    MissingSubleaf1,
    /// Subleaf1.
    #[error("Subleaf1: {0}")]
    Subleaf1(Leaf7Subleaf1NotSupported),
}

impl Supports for Leaf7<'_> {
    type Error = Leaf7NotSupported;
    /// We do not currently check EDX.
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        match (self.0, other.0) {
            (_, None) => (),
            (None, Some(_)) => return Err(Leaf7NotSupported::MissingSubleaf0),
            (Some(a), Some(b)) => a.supports(b).map_err(Leaf7NotSupported::Subleaf0)?,
        }
        match (self.1, other.1) {
            (_, None) => (),
            (None, Some(_)) => return Err(Leaf7NotSupported::MissingSubleaf1),
            (Some(a), Some(b)) => a.supports(b).map_err(Leaf7NotSupported::Subleaf1)?,
        }

        Ok(())
    }
}

impl Supports for Leaf7Mut<'_> {
    type Error = Leaf7NotSupported;
    /// We do not currently check EDX.
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        match (self.0.as_ref(), other.0.as_ref()) {
            (_, None) => (),
            (None, Some(_)) => return Err(Leaf7NotSupported::MissingSubleaf0),
            (Some(a), Some(b)) => a.supports(b).map_err(Leaf7NotSupported::Subleaf0)?,
        }
        match (self.1.as_ref(), other.1.as_ref()) {
            (_, None) => (),
            (None, Some(_)) => return Err(Leaf7NotSupported::MissingSubleaf1),
            (Some(a), Some(b)) => a.supports(b).map_err(Leaf7NotSupported::Subleaf1)?,
        }

        Ok(())
    }
}

/// Error type for [`<Leaf7Subleaf0 as Supports>::supports`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Leaf7Subleaf0NotSupported {
    /// MaxInputValueSubleaf.
    #[error("MaxInputValueSubleaf: {0} vs {1}.")]
    MaxInputValueSubleaf(u32, u32),
    /// Ebx.
    #[error("Ebx: {0} vs {1}.")]
    Ebx(u32, u32),
    /// Ecx.
    #[error("Ecx: {0} vs {1}.")]
    Ecx(u32, u32),
    /// Edx.
    #[error("Edx: {0} vs {1}.")]
    Edx(u32, u32),
}

impl Supports for Leaf7Subleaf0 {
    type Error = Leaf7Subleaf0NotSupported;
    /// We check everything here.
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        debug_assert!(
            self.eax.max_input_value_subleaf() == 1 || self.eax.max_input_value_subleaf() == 0
        );
        debug_assert!(
            other.eax.max_input_value_subleaf() == 1 || other.eax.max_input_value_subleaf() == 0
        );
        warn_support!("0x7 sub-leaf 0", true, true, true, true);

        if self.eax.max_input_value_subleaf() < other.eax.max_input_value_subleaf() {
            return Err(Leaf7Subleaf0NotSupported::MaxInputValueSubleaf(
                self.eax.max_input_value_subleaf().read(),
                other.eax.max_input_value_subleaf().read(),
            ));
        }
        if matches!(self.ebx.cmp_flags(&other.ebx), Some(Ordering::Less) | None) {
            return Err(Leaf7Subleaf0NotSupported::Ebx(self.ebx.0, other.ebx.0));
        }

        // KVM automtically sets OSPKE as active, but will return that it is not supported,
        // therefore we mask it out when comparing KMV CPUID support.
        let mask = !super::registers::Leaf7Subleaf0Ecx::OSPKE;
        if matches!(
            (self.ecx & mask).cmp_flags(&(other.ecx & mask)),
            Some(Ordering::Less) | None
        ) {
            return Err(Leaf7Subleaf0NotSupported::Ecx(self.ecx.0, other.ecx.0));
        }
        if matches!(self.edx.cmp_flags(&other.edx), Some(Ordering::Less) | None) {
            return Err(Leaf7Subleaf0NotSupported::Edx(self.edx.0, other.edx.0));
        }

        Ok(())
    }
}

/// Error type for [`<Leaf7Subleaf1 as Supports>::supports`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Leaf7Subleaf1NotSupported {
    /// Eax.
    #[error("Eax.")]
    Eax,
    /// Ebx.
    #[error("Ebx.")]
    Ebx,
}

impl Supports for Leaf7Subleaf1 {
    type Error = Leaf7Subleaf1NotSupported;
    /// We check everything here.
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        warn_support!("0x7 sub-leaf 1", true, true, true, true);
        if matches!(self.eax.cmp_flags(&other.eax), Some(Ordering::Less) | None) {
            return Err(Leaf7Subleaf1NotSupported::Eax);
        }
        if matches!(self.ebx.cmp_flags(&other.ebx), Some(Ordering::Less) | None) {
            return Err(Leaf7Subleaf1NotSupported::Ebx);
        }
        Ok(())
    }
}

/// Error type for [`<LeafA as Supports>::supports`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum LeafANotSupported {
    /// Ebx.
    #[error("Ebx.")]
    Ebx,
}

impl Supports for LeafA {
    type Error = LeafANotSupported;
    /// We do not currently check EAX, ECX and EDX.
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        warn_support!("0xA", false, true, false, false);
        if matches!(self.ebx.cmp_flags(&other.ebx), Some(Ordering::Less) | None) {
            return Err(LeafANotSupported::Ebx);
        }
        Ok(())
    }
}

/// Error type for [`<LeafF as Supports>::supports`] and [`<LeafFMut as Supports>::supports`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum LeafFNotSupported {
    /// MissingSubleaf0.
    #[error("MissingSubleaf0.")]
    MissingSubleaf0,
    /// Subleaf0.
    #[error("Subleaf0: {0}")]
    Subleaf0(LeafFSubleaf0NotSupported),
    /// MissingSubleaf1.
    #[error("MissingSubleaf1.")]
    MissingSubleaf1,
    /// Subleaf1.
    #[error("Subleaf1: {0}")]
    Subleaf1(LeafFSubleaf1NotSupported),
}

impl Supports for LeafF<'_> {
    type Error = LeafFNotSupported;
    /// We check sub-leaves 0 and 1.
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        match (self.0, other.0) {
            (_, None) => (),
            (None, Some(_)) => return Err(LeafFNotSupported::MissingSubleaf0),
            (Some(a), Some(b)) => a.supports(b).map_err(LeafFNotSupported::Subleaf0)?,
        }
        match (self.1, other.1) {
            (_, None) => (),
            (None, Some(_)) => return Err(LeafFNotSupported::MissingSubleaf1),
            (Some(a), Some(b)) => a.supports(b).map_err(LeafFNotSupported::Subleaf1)?,
        }
        Ok(())
    }
}

impl Supports for LeafFMut<'_> {
    type Error = LeafFNotSupported;
    /// We check sub-leaves 0 and 1.
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        match (self.0.as_ref(), other.0.as_ref()) {
            (_, None) => (),
            (None, Some(_)) => return Err(LeafFNotSupported::MissingSubleaf0),
            (Some(a), Some(b)) => a.supports(b).map_err(LeafFNotSupported::Subleaf0)?,
        }
        match (self.1.as_ref(), other.1.as_ref()) {
            (_, None) => (),
            (None, Some(_)) => return Err(LeafFNotSupported::MissingSubleaf1),
            (Some(a), Some(b)) => a.supports(b).map_err(LeafFNotSupported::Subleaf1)?,
        }
        Ok(())
    }
}

/// Error type for [`<LeafFSubleaf0 as Supports>::supports`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum LeafFSubleaf0NotSupported {
    /// MaxRmidRange.
    #[error("MaxRmidRange.")]
    MaxRmidRange,
    /// Edx.
    #[error("Edx.")]
    Edx,
}

impl Supports for LeafFSubleaf0 {
    type Error = LeafFSubleaf0NotSupported;
    /// We check everything here.
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        warn_support!("0xF sub-leaf 0", true, true, true, true);
        if self.ebx.max_rmid_range() < other.ebx.max_rmid_range() {
            return Err(LeafFSubleaf0NotSupported::MaxRmidRange);
        }
        if matches!(self.edx.cmp_flags(&other.edx), Some(Ordering::Less) | None) {
            return Err(LeafFSubleaf0NotSupported::Edx);
        }

        Ok(())
    }
}

/// Error type for [`<LeafFSubleaf1 as Supports>::supports`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum LeafFSubleaf1NotSupported {
    /// RmidMax.
    #[error("RmidMax.")]
    RmidMax,
    /// Edx.
    #[error("Edx.")]
    Edx,
}

impl Supports for LeafFSubleaf1 {
    type Error = LeafFSubleaf1NotSupported;
    /// We do not check EBX.
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        warn_support!("0xF sub-leaf 1", true, false, true, true);
        if self.ecx.rmid_max() < other.ecx.rmid_max() {
            return Err(LeafFSubleaf1NotSupported::RmidMax);
        }
        if matches!(self.edx.cmp_flags(&other.edx), Some(Ordering::Less) | None) {
            return Err(LeafFSubleaf1NotSupported::Edx);
        }

        Ok(())
    }
}

/// Error type for [`<Leaf10 as Supports>::supports`] and [`<Leaf10Mut as Supports>::supports`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Leaf10NotSupported {
    /// MissingSubleaf0.
    #[error("MissingSubleaf0.")]
    MissingSubleaf0,
    /// Subleaf0.
    #[error("Subleaf0: {0}")]
    Subleaf0(Leaf10Subleaf0NotSupported),
    /// MissingSubleaf1.
    #[error("MissingSubleaf1.")]
    MissingSubleaf1,
    /// Subleaf1.
    #[error("Subleaf1: {0}")]
    Subleaf1(Leaf10Subleaf1NotSupported),
    /// MissingSubleaf3.
    #[error("MissingSubleaf3.")]
    MissingSubleaf3,
    /// Subleaf3.
    #[error("Subleaf3: {0}")]
    Subleaf3(Leaf10Subleaf3NotSupported),
}

impl Supports for Leaf10<'_> {
    type Error = Leaf10NotSupported;
    /// We check sub-leaves 0 and 1.
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        log::warn!(
            "Could not fully validate support for Intel CPUID leaf 0x10 due to being unable to \
             validate sub-leaf 2."
        );
        match (self.0, other.0) {
            (_, None) => (),
            (None, Some(_)) => return Err(Leaf10NotSupported::MissingSubleaf0),
            (Some(a), Some(b)) => a.supports(b).map_err(Leaf10NotSupported::Subleaf0)?,
        }
        match (self.1, other.1) {
            (_, None) => (),
            (None, Some(_)) => return Err(Leaf10NotSupported::MissingSubleaf1),
            (Some(a), Some(b)) => a.supports(b).map_err(Leaf10NotSupported::Subleaf1)?,
        }
        match (self.3, other.3) {
            (_, None) => (),
            (None, Some(_)) => return Err(Leaf10NotSupported::MissingSubleaf3),
            (Some(a), Some(b)) => a.supports(b).map_err(Leaf10NotSupported::Subleaf3)?,
        }
        Ok(())
    }
}

impl Supports for Leaf10Mut<'_> {
    type Error = Leaf10NotSupported;
    /// We check sub-leaves 0 and 1.
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        log::warn!(
            "Could not fully validate support for Intel CPUID leaf 0x10 due to being unable to \
             validate sub-leaf 2."
        );
        match (self.0.as_ref(), other.0.as_ref()) {
            (_, None) => (),
            (None, Some(_)) => return Err(Leaf10NotSupported::MissingSubleaf0),
            (Some(a), Some(b)) => a.supports(b).map_err(Leaf10NotSupported::Subleaf0)?,
        }
        match (self.1.as_ref(), other.1.as_ref()) {
            (_, None) => (),
            (None, Some(_)) => return Err(Leaf10NotSupported::MissingSubleaf1),
            (Some(a), Some(b)) => a.supports(b).map_err(Leaf10NotSupported::Subleaf1)?,
        }
        match (self.3.as_ref(), other.3.as_ref()) {
            (_, None) => (),
            (None, Some(_)) => return Err(Leaf10NotSupported::MissingSubleaf3),
            (Some(a), Some(b)) => a.supports(b).map_err(Leaf10NotSupported::Subleaf3)?,
        }
        Ok(())
    }
}

/// Error type for [`<Leaf10Subleaf0 as Supports>::supports`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Leaf10Subleaf0NotSupported {
    /// Ebx.
    #[error("Ebx.")]
    Ebx,
}

impl Supports for Leaf10Subleaf0 {
    type Error = Leaf10Subleaf0NotSupported;
    /// We check everything here.
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        warn_support!("0x10 sub-leaf 0", true, true, true, true);
        if matches!(self.ebx.cmp_flags(&other.ebx), Some(Ordering::Less) | None) {
            return Err(Leaf10Subleaf0NotSupported::Ebx);
        }
        Ok(())
    }
}

/// Error type for [`<Leaf10Subleaf1 as Supports>::supports`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Leaf10Subleaf1NotSupported {
    /// Ecx.
    #[error("Ecx.")]
    Ecx,
}

impl Supports for Leaf10Subleaf1 {
    type Error = Leaf10Subleaf1NotSupported;
    /// We only check ECX.
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        warn_support!("0x10 sub-leaf 1", false, false, true, false);
        if matches!(self.ecx.cmp_flags(&other.ecx), Some(Ordering::Less) | None) {
            return Err(Leaf10Subleaf1NotSupported::Ecx);
        }
        Ok(())
    }
}

/// Error type for [`<Leaf10Subleaf3 as Supports>::supports`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Leaf10Subleaf3NotSupported {
    /// Ecx.
    #[error("Ecx.")]
    Ecx,
}

impl Supports for Leaf10Subleaf3 {
    type Error = Leaf10Subleaf3NotSupported;
    /// We only check ECX.
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        warn_support!("0x10 sub-leaf 3", false, false, true, false);
        if matches!(self.ecx.cmp_flags(&other.ecx), Some(Ordering::Less) | None) {
            return Err(Leaf10Subleaf3NotSupported::Ecx);
        }
        Ok(())
    }
}

/// Error type for [`<Leaf14 as Supports>::supports`] and [`<Leaf14Mut as Supports>::supports`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Leaf14NotSupported {
    /// MissingSubleaf0.
    #[error("MissingSubleaf0.")]
    MissingSubleaf0,
    /// Subleaf0.
    #[error("Subleaf0: {0}")]
    Subleaf0(Leaf14Subleaf0NotSupported),
}

impl Supports for Leaf14<'_> {
    type Error = Leaf14NotSupported;
    /// Only checks subleaf 1.
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        log::warn!(
            "Could not fully validate support for Intel CPUID leaf 0x14 due to being unable to \
             validate sub-leaf 1."
        );
        match (self.0, other.0) {
            (_, None) => (),
            (None, Some(_)) => return Err(Leaf14NotSupported::MissingSubleaf0),
            (Some(a), Some(b)) => a.supports(b).map_err(Leaf14NotSupported::Subleaf0)?,
        }
        Ok(())
    }
}

impl Supports for Leaf14Mut<'_> {
    type Error = Leaf14NotSupported;
    /// Only checks subleaf 1.
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        log::warn!(
            "Could not fully validate support for Intel CPUID leaf 0x14 due to being unable to \
             validate sub-leaf 1."
        );
        match (self.0.as_ref(), other.0.as_ref()) {
            (_, None) => (),
            (None, Some(_)) => return Err(Leaf14NotSupported::MissingSubleaf0),
            (Some(a), Some(b)) => a.supports(b).map_err(Leaf14NotSupported::Subleaf0)?,
        }
        Ok(())
    }
}

/// Error type for [`<Leaf14Subleaf0 as Supports>::supports`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Leaf14Subleaf0NotSupported {
    /// MaxSubleaf.
    #[error("MaxSubleaf.")]
    MaxSubleaf,
    /// Ebx.
    #[error("Ebx.")]
    Ebx,
    /// Ecx.
    #[error("Ecx.")]
    Ecx,
}

impl Supports for Leaf14Subleaf0 {
    type Error = Leaf14Subleaf0NotSupported;
    /// We check everything here.
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        warn_support!("0x14 sub-leaf 0", true, true, true, true);
        if self.eax.max_subleaf() < other.eax.max_subleaf() {
            return Err(Leaf14Subleaf0NotSupported::MaxSubleaf);
        }
        if matches!(self.ebx.cmp_flags(&other.ebx), Some(Ordering::Less) | None) {
            return Err(Leaf14Subleaf0NotSupported::Ebx);
        }
        if matches!(self.ecx.cmp_flags(&other.ecx), Some(Ordering::Less) | None) {
            return Err(Leaf14Subleaf0NotSupported::Ebx);
        }
        Ok(())
    }
}

/// Error type for [`<Leaf18 as Supports>::supports`] and [`<Leaf18Mut as Supports>::supports`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Leaf18NotSupported {
    /// MissingSubleaf0.
    #[error("MissingSubleaf0.")]
    MissingSubleaf0,
    /// Subleaf0.
    #[error("Subleaf0: {0}")]
    Subleaf0(Leaf18Subleaf0NotSupported),
}

impl Supports for Leaf18<'_> {
    type Error = Leaf18NotSupported;
    /// Only checks subleaf 1.
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        log::warn!(
            "Could not fully validate support for Intel CPUID leaf 0x18 due to being unable to \
             validate sub-leaf 1."
        );
        match (self.0.as_ref(), other.0.as_ref()) {
            (_, None) => (),
            (None, Some(_)) => return Err(Leaf18NotSupported::MissingSubleaf0),
            (Some(a), Some(b)) => a.supports(b).map_err(Leaf18NotSupported::Subleaf0)?,
        }
        Ok(())
    }
}

impl Supports for Leaf18Mut<'_> {
    type Error = Leaf18NotSupported;
    /// Only checks subleaf 1.
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        log::warn!(
            "Could not fully validate support for Intel CPUID leaf 0x18 due to being unable to \
             validate sub-leaf 1."
        );
        match (self.0.as_ref(), other.0.as_ref()) {
            (_, None) => (),
            (None, Some(_)) => return Err(Leaf18NotSupported::MissingSubleaf0),
            (Some(a), Some(b)) => a.supports(b).map_err(Leaf18NotSupported::Subleaf0)?,
        }
        Ok(())
    }
}

/// Error type for [`<Leaf18Subleaf0 as Supports>::supports`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Leaf18Subleaf0NotSupported {
    /// MissingSubleaf0.
    #[error("MissingSubleaf0.")]
    MaxSubleaf,
    /// Ebx.
    #[error("Ebx.")]
    Ebx,
}

impl Supports for Leaf18Subleaf0 {
    type Error = Leaf18Subleaf0NotSupported;
    /// We do not check ECX or EDX.
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        warn_support!("0x18 sub-leaf 0", true, true, false, false);
        if self.eax.max_subleaf() < other.eax.max_subleaf() {
            return Err(Leaf18Subleaf0NotSupported::MaxSubleaf);
        }
        if matches!(self.ebx.cmp_flags(&other.ebx), Some(Ordering::Less) | None) {
            return Err(Leaf18Subleaf0NotSupported::Ebx);
        }
        Ok(())
    }
}

/// Error type for [`<Leaf19 as Supports>::supports`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Leaf19NotSupported {
    /// Eax.
    #[error("Eax.")]
    Eax,
    /// Ebx.
    #[error("Ebx.")]
    Ebx,
    /// Ecx.
    #[error("Ecx.")]
    Ecx,
}

impl Supports for Leaf19 {
    type Error = Leaf19NotSupported;
    /// We check everything here.
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        warn_support!("0x19", true, true, true, true);
        if matches!(self.eax.cmp_flags(&other.eax), Some(Ordering::Less) | None) {
            return Err(Leaf19NotSupported::Eax);
        }
        if matches!(self.ebx.cmp_flags(&other.ebx), Some(Ordering::Less) | None) {
            return Err(Leaf19NotSupported::Ebx);
        }
        if matches!(self.ecx.cmp_flags(&other.ecx), Some(Ordering::Less) | None) {
            return Err(Leaf19NotSupported::Ecx);
        }
        Ok(())
    }
}

/// Error type for [`<Leaf1C as Supports>::supports`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Leaf1CNotSupported {
    /// Eax.
    #[error("Eax.")]
    Eax,
    /// Ebx.
    #[error("Ebx.")]
    Ebx,
    /// Ecx.
    #[error("Ecx.")]
    Ecx,
}

impl Supports for Leaf1C {
    type Error = Leaf1CNotSupported;
    /// We do not check EAX.
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        warn_support!("0x1C", true, true, true, true);
        if matches!(self.eax.cmp_flags(&other.eax), Some(Ordering::Less) | None) {
            return Err(Leaf1CNotSupported::Eax);
        }
        if matches!(self.ebx.cmp_flags(&other.ebx), Some(Ordering::Less) | None) {
            return Err(Leaf1CNotSupported::Ebx);
        }
        if matches!(self.ecx.cmp_flags(&other.ecx), Some(Ordering::Less) | None) {
            return Err(Leaf1CNotSupported::Ecx);
        }
        Ok(())
    }
}

/// Error type for [`<Leaf20 as Supports>::supports`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Leaf20NotSupported {
    /// MaxSubleaves.
    #[error("MaxSubleaves.")]
    MaxSubleaves,
    /// Ebx.
    #[error("Ebx.")]
    Ebx,
}

impl Supports for Leaf20 {
    type Error = Leaf20NotSupported;
    /// We do not check EBX.
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        debug_assert_eq!(self.eax.max_subleaves(), 1);
        debug_assert_eq!(other.eax.max_subleaves(), 1);
        warn_support!("0x1C", true, true, true, true);

        if self.eax.max_subleaves() < other.eax.max_subleaves() {
            return Err(Leaf20NotSupported::MaxSubleaves);
        }
        if matches!(self.ebx.cmp_flags(&other.ebx), Some(Ordering::Less) | None) {
            return Err(Leaf20NotSupported::Ebx);
        }
        Ok(())
    }
}

/// Error type for [`<Leaf80000000 as Supports>::supports`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Leaf80000000NotSupported {
    /// MaxExtendedFunctionInput.
    #[error("MaxExtendedFunctionInput.")]
    MaxExtendedFunctionInput,
}

impl Supports for Leaf80000000 {
    type Error = Leaf80000000NotSupported;
    /// We check everything here.
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        warn_support!("0x80000000", true, true, true, true);

        if self.eax.max_extend_function_input() < other.eax.max_extend_function_input() {
            return Err(Leaf80000000NotSupported::MaxExtendedFunctionInput);
        }
        Ok(())
    }
}

/// Error type for [`<Leaf80000001 as Supports>::supports`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Leaf80000001NotSupported {
    /// Ecx.
    #[error("Ecx.")]
    Ecx,
    /// Edx.
    #[error("Edx.")]
    Edx,
}

impl Supports for Leaf80000001 {
    type Error = Leaf80000001NotSupported;
    /// We do not check EAX.
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        warn_support!("0x80000001", true, true, true, true);

        if matches!(self.ecx.cmp_flags(&other.ecx), Some(Ordering::Less) | None) {
            return Err(Leaf80000001NotSupported::Ecx);
        }
        if matches!(self.edx.cmp_flags(&other.edx), Some(Ordering::Less) | None) {
            return Err(Leaf80000001NotSupported::Edx);
        }
        Ok(())
    }
}

/// Error type for [`<Leaf80000007 as Supports>::supports`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Leaf80000007NotSupported {
    /// Edx.
    #[error("Edx.")]
    Edx,
}

impl Supports for Leaf80000007 {
    type Error = Leaf80000007NotSupported;
    /// We check everything here.
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        warn_support!("0x80000007", true, true, true, true);

        if matches!(self.edx.cmp_flags(&other.edx), Some(Ordering::Less) | None) {
            return Err(Leaf80000007NotSupported::Edx);
        }
        Ok(())
    }
}

/// Error type for [`<Leaf80000008 as Supports>::supports`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Leaf80000008NotSupported {
    /// PhysicalAddressBits.
    #[error("PhysicalAddressBits.")]
    PhysicalAddressBits,
    /// LinearAddressBits.
    #[error("LinearAddressBits.")]
    LinearAddressBits,
    /// Ebx.
    #[error("Ebx.")]
    Ebx,
}

impl Supports for Leaf80000008 {
    type Error = Leaf80000008NotSupported;
    /// We check everything here.
    #[inline]
    fn supports(&self, other: &Self) -> Result<(), Self::Error> {
        warn_support!("0x80000008", true, true, true, true);

        if self.eax.physical_address_bits() < other.eax.physical_address_bits() {
            return Err(Leaf80000008NotSupported::PhysicalAddressBits);
        }
        if self.eax.linear_address_bits() < other.eax.linear_address_bits() {
            return Err(Leaf80000008NotSupported::LinearAddressBits);
        }
        if matches!(self.ebx.cmp_flags(&other.ebx), Some(Ordering::Less) | None) {
            return Err(Leaf80000008NotSupported::Ebx);
        }
        Ok(())
    }
}
