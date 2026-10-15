// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The microVM features syscall rules can be tagged with.

use std::fmt;
use std::ops::{BitOr, BitOrAssign};
use std::str::FromStr;

/// Define [`SeccompFeature`], [`SeccompFeature::ALL`] and [`SeccompFeature::name`] from one list, so
/// that a feature cannot be added without its name and its place in `ALL`, which the set
/// operations, parsing and display rely on.
macro_rules! seccomp_features {
    ($( $(#[$doc:meta])* $variant:ident => $name:literal, )+) => {
        /// A capability of the microVM that some syscall rules are only needed for.
        ///
        /// Syscall rules in the JSON filters can be tagged with one or more features. seccompiler
        /// compiles tagged rules into separate BPF fragments which are only included in a thread's
        /// filter when one of their features is enabled for the running microVM, see
        /// [`SeccompFilter::compose`](crate::SeccompFilter::compose).
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[repr(u8)]
        pub enum SeccompFeature {
            $( $(#[$doc])* $variant, )+
        }

        impl SeccompFeature {
            /// Every feature, in bit order.
            pub const ALL: [SeccompFeature; [$(SeccompFeature::$variant),+].len()] =
                [$(SeccompFeature::$variant),+];

            /// The name used to tag rules with this feature in the JSON filters.
            pub const fn name(self) -> &'static str {
                match self {
                    $(SeccompFeature::$variant => $name,)+
                }
            }
        }
    };
}

seccomp_features! {
    /// Runtime control of the microVM through the API: pausing and resuming it, and saving its
    /// state for a snapshot.
    Api => "api",
    /// VirtIO devices attached over the PCI transport (MSI-X, BAR relocation, teardown).
    Pci => "pci",
    /// Hot-plugging and unplugging devices through the API after boot, which is possible when the
    /// API is enabled and the PCI transport is used.
    Hotplug => "hotplug",
    /// virtio-block devices.
    Block => "block",
    /// virtio-block devices using the asynchronous (io_uring) file engine.
    AsyncIo => "async-io",
    /// virtio-net devices.
    Net => "net",
    /// The virtio-vsock device.
    Vsock => "vsock",
    /// virtio-pmem devices.
    Pmem => "pmem",
    /// virtio-mem memory hotplug.
    MemoryHotplug => "memory-hotplug",
}

impl SeccompFeature {
    const fn bit(self) -> u32 {
        1 << (self as u32)
    }
}

impl fmt::Display for SeccompFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Unknown seccomp feature: {0}
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
pub struct UnknownSeccompFeature(pub String);

impl FromStr for SeccompFeature {
    type Err = UnknownSeccompFeature;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        SeccompFeature::ALL
            .into_iter()
            .find(|feature| feature.name() == name)
            .ok_or_else(|| UnknownSeccompFeature(name.to_string()))
    }
}

/// A set of [`SeccompFeature`]s.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct SeccompFeatures(u32);

impl SeccompFeatures {
    /// The empty set.
    pub const fn empty() -> Self {
        SeccompFeatures(0)
    }

    /// The set of all features.
    pub const fn all() -> Self {
        SeccompFeatures((1 << SeccompFeature::ALL.len()) - 1)
    }

    /// Whether `feature` is in the set.
    pub const fn contains(self, feature: SeccompFeature) -> bool {
        self.0 & feature.bit() != 0
    }

    /// Whether the two sets have a feature in common.
    pub const fn intersects(self, other: SeccompFeatures) -> bool {
        self.0 & other.0 != 0
    }

    /// Whether the set is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Add `feature` to the set.
    pub fn insert(&mut self, feature: SeccompFeature) {
        self.0 |= feature.bit();
    }

    /// The features in the set, in bit order.
    pub fn iter(self) -> impl Iterator<Item = SeccompFeature> {
        SeccompFeature::ALL
            .into_iter()
            .filter(move |feature| self.contains(*feature))
    }
}

impl From<SeccompFeature> for SeccompFeatures {
    fn from(feature: SeccompFeature) -> Self {
        SeccompFeatures(feature.bit())
    }
}

impl FromIterator<SeccompFeature> for SeccompFeatures {
    fn from_iter<I: IntoIterator<Item = SeccompFeature>>(iter: I) -> Self {
        let mut set = SeccompFeatures::empty();
        for feature in iter {
            set.insert(feature);
        }
        set
    }
}

impl BitOr for SeccompFeatures {
    type Output = SeccompFeatures;

    fn bitor(self, rhs: SeccompFeatures) -> SeccompFeatures {
        SeccompFeatures(self.0 | rhs.0)
    }
}

impl BitOr<SeccompFeature> for SeccompFeatures {
    type Output = SeccompFeatures;

    fn bitor(self, rhs: SeccompFeature) -> SeccompFeatures {
        SeccompFeatures(self.0 | rhs.bit())
    }
}

impl BitOrAssign for SeccompFeatures {
    fn bitor_assign(&mut self, rhs: SeccompFeatures) {
        self.0 |= rhs.0;
    }
}

impl BitOrAssign<SeccompFeature> for SeccompFeatures {
    fn bitor_assign(&mut self, rhs: SeccompFeature) {
        self.insert(rhs);
    }
}

impl fmt::Debug for SeccompFeatures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

impl fmt::Display for SeccompFeatures {
    /// Comma separated feature names.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, feature) in self.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            f.write_str(feature.name())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seccomp_features() {
        assert!(SeccompFeatures::empty().is_empty());
        assert!(!SeccompFeatures::all().is_empty());
        for (bit, feature) in SeccompFeature::ALL.into_iter().enumerate() {
            // `ALL` lists every variant once, in bit order.
            assert_eq!(feature as usize, bit);
            assert!(SeccompFeatures::all().contains(feature));
            assert!(!SeccompFeatures::empty().contains(feature));
            // Names round-trip and are stable identifiers.
            assert_eq!(feature.name().parse::<SeccompFeature>().unwrap(), feature);
            assert_eq!(feature.to_string(), feature.name());
        }
        assert_eq!(
            "no-such-feature".parse::<SeccompFeature>().unwrap_err(),
            UnknownSeccompFeature("no-such-feature".to_string())
        );
        assert_eq!(
            SeccompFeatures::all().iter().collect::<Vec<_>>(),
            SeccompFeature::ALL.to_vec()
        );

        let mut set = SeccompFeatures::from(SeccompFeature::Net);
        set |= SeccompFeature::Block;
        set |= SeccompFeatures::from(SeccompFeature::Pci);
        assert!(set.contains(SeccompFeature::Net));
        assert!(set.contains(SeccompFeature::Block));
        assert!(set.contains(SeccompFeature::Pci));
        assert!(!set.contains(SeccompFeature::Vsock));
        assert!(set.intersects(SeccompFeature::Pci.into()));
        assert!(!set.intersects(SeccompFeature::Vsock.into()));
        assert_eq!(set.to_string(), "pci,block,net");
        assert_eq!(format!("{set:?}"), "{Pci, Block, Net}");
        assert_eq!(
            set,
            [
                SeccompFeature::Pci,
                SeccompFeature::Block,
                SeccompFeature::Net
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(
            set | SeccompFeature::Vsock,
            set | SeccompFeatures::from(SeccompFeature::Vsock)
        );
    }
}
