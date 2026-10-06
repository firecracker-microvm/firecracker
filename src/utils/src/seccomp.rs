// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Feature names shared by Firecracker and its seccomp policy compiler.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

pub mod bpf;

/// Unknown seccomp feature: {0}
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
pub struct UnknownSeccompFeature(pub String);

macro_rules! features {
    ($(#[doc = $doc:literal] $variant:ident, $flag:ident, $name:literal;)*) => {
        /// A single capability that a syscall rule can be tagged with.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        pub enum SeccompFeature { $(#[doc = $doc] $variant,)* }

        impl SeccompFeature {
            /// All features in canonical tag order.
            pub const ALL: &'static [Self] = &[$(Self::$variant,)*];

            /// Name used in policies, command-line selections and logs.
            pub const fn name(self) -> &'static str {
                match self { $(Self::$variant => $name,)* }
            }
        }

        impl FromStr for SeccompFeature {
            type Err = UnknownSeccompFeature;

            fn from_str(name: &str) -> Result<Self, Self::Err> {
                match name {
                    $($name => Ok(Self::$variant),)*
                    _ => Err(UnknownSeccompFeature(name.to_owned())),
                }
            }
        }

        bitflags::bitflags! {
            /// The capabilities enabled for a microVM. Any matching tag selects a rule.
            #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
            pub struct SeccompFeatures: u32 {
                $(#[doc = $doc] const $flag = 1 << SeccompFeature::$variant as u32;)*
            }
        }

        impl From<SeccompFeature> for SeccompFeatures {
            fn from(feature: SeccompFeature) -> Self {
                match feature { $(SeccompFeature::$variant => Self::$flag,)* }
            }
        }
    };
}

features! {
    /// Runtime control through the API, including pause, resume and snapshot.
    Api, API, "api";
    /// VirtIO devices attached over PCI.
    Pci, PCI, "pci";
    /// Adding and removing devices through the API after boot.
    Hotplug, HOTPLUG, "hotplug";
    /// VirtIO block devices.
    Block, BLOCK, "block";
    /// Drives using the asynchronous file engine.
    AsyncIo, ASYNC_IO, "async-io";
    /// VirtIO network devices.
    Net, NET, "net";
    /// The virtio-vsock device.
    Vsock, VSOCK, "vsock";
    /// VirtIO persistent memory devices.
    Pmem, PMEM, "pmem";
    /// Virtio-mem memory hotplug.
    MemoryHotplug, MEMORY_HOTPLUG, "memory-hotplug";
}

impl SeccompFeatures {
    /// Parse a single policy tag, not a feature selection.
    pub fn from_tag(name: &str) -> Result<Self, UnknownSeccompFeature> {
        name.parse::<SeccompFeature>().map(Self::from)
    }

    fn from_tags(tags: &[String]) -> Result<Self, UnknownSeccompFeature> {
        tags.iter().map(|tag| Self::from_tag(tag)).collect()
    }

    fn names(self) -> impl Iterator<Item = &'static str> {
        SeccompFeature::ALL
            .iter()
            .copied()
            .filter(move |&feature| self.contains(feature.into()))
            .map(SeccompFeature::name)
    }
}

// The filter file stores a list of canonical tag names, not the in-memory bit mask.
impl Serialize for SeccompFeatures {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Bitcode needs the sequence length before it writes the first name.
        self.names().collect::<Vec<_>>().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SeccompFeatures {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::from_tags(&Vec::<String>::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

impl FromStr for SeccompFeatures {
    type Err = UnknownSeccompFeature;

    /// `all`, `none`, or a comma-separated list of individual tags.
    fn from_str(list: &str) -> Result<Self, Self::Err> {
        match list.trim() {
            "all" => Ok(Self::all()),
            "none" => Ok(Self::empty()),
            _ => list
                .split(',')
                .map(|name| Self::from_tag(name.trim()))
                .collect(),
        }
    }
}

impl fmt::Display for SeccompFeatures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut names = self.names();
        if let Some(first) = names.next() {
            f.write_str(first)?;
            for feature in names {
                write!(f, ",{feature}")?;
            }
        }
        Ok(())
    }
}
