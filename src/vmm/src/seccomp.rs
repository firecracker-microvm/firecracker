// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fmt;
use std::io::Read;
use std::str::FromStr;

use utils::seccomp::BpfPart as SerializedPart;

use crate::logger::{info, warn};

// This byte limit is passed to `bitcode` to guard against a potential memory
// allocation DOS caused by binary filters that are too large.
// This limit can be safely determined since the maximum length of a BPF
// filter is 4096 instructions and Firecracker has a finite number of threads.
const DESERIALIZATION_BYTES_LIMIT: usize = 100_000;

/// Each BPF instruction is 8 bytes long and 4 byte aligned.
/// This alignment needs to be satisfied in order for a BPF code to be accepted
/// by the syscalls. Using u64 here is is safe as it has same size and even bigger alignment.
pub type BpfInstruction = u64;

/// Program made up of a sequence of BPF instructions.
pub type BpfProgram = Vec<BpfInstruction>;

/// Reference to program made up of a sequence of BPF instructions.
pub type BpfProgramRef<'a> = &'a [BpfInstruction];

bitflags::bitflags! {
    /// A set of microVM capabilities that some syscall rules are only needed for.
    ///
    /// Syscall rules in the JSON filters can be tagged with one or more stable feature names
    /// (`async-io` for [`SeccompFeatures::ASYNC_IO`]), see [`SeccompFeatures::from_tag`].
    /// seccompiler compiles tagged rules into separate parts of a thread's filter, which are only
    /// included when one of their features is enabled for the running microVM, see
    /// [`SeccompFilter::compose`].
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
    pub struct SeccompFeatures: u32 {
        /// Runtime control of the microVM through the API: pausing and resuming it, and saving
        /// its state for a snapshot.
        const API = 1 << 0;
        /// VirtIO devices attached over the PCI transport (MSI-X, BAR relocation, teardown).
        const PCI = 1 << 1;
        /// Hot-plugging and unplugging devices through the API after boot, which is possible
        /// when the API is enabled and the PCI transport is used.
        const HOTPLUG = 1 << 2;
        /// virtio-block devices.
        const BLOCK = 1 << 3;
        /// virtio-block devices using the asynchronous (io_uring) file engine.
        const ASYNC_IO = 1 << 4;
        /// virtio-net devices.
        const NET = 1 << 5;
        /// The virtio-vsock device.
        const VSOCK = 1 << 6;
        /// virtio-pmem devices.
        const PMEM = 1 << 7;
        /// virtio-mem memory hotplug.
        const MEMORY_HOTPLUG = 1 << 8;
    }
}

/// Unknown seccomp feature: {0}
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
pub struct UnknownSeccompFeature(pub String);

impl SeccompFeatures {
    // Stable external tags in display order, independent of the Rust constant names.
    const TAGS: &'static [(Self, &'static str)] = &[
        (Self::API, "api"),
        (Self::PCI, "pci"),
        (Self::HOTPLUG, "hotplug"),
        (Self::BLOCK, "block"),
        (Self::ASYNC_IO, "async-io"),
        (Self::NET, "net"),
        (Self::VSOCK, "vsock"),
        (Self::PMEM, "pmem"),
        (Self::MEMORY_HOTPLUG, "memory-hotplug"),
    ];

    /// The feature that `name` tags rules with in the JSON filters.
    pub fn from_tag(name: &str) -> Result<Self, UnknownSeccompFeature> {
        Self::TAGS
            .iter()
            .find_map(|&(feature, tag)| (tag == name).then_some(feature))
            .ok_or_else(|| UnknownSeccompFeature(name.to_string()))
    }
}

impl FromStr for SeccompFeatures {
    type Err = UnknownSeccompFeature;

    /// `all`, or a comma-separated list of feature names.
    fn from_str(list: &str) -> Result<Self, Self::Err> {
        if list.trim() == "all" {
            return Ok(Self::all());
        }
        list.split(',')
            .map(|name| Self::from_tag(name.trim()))
            .collect()
    }
}

impl fmt::Display for SeccompFeatures {
    /// Comma separated feature names.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<_> = Self::TAGS
            .iter()
            .filter_map(|&(feature, tag)| self.contains(feature).then_some(tag))
            .collect();
        f.write_str(&names.join(","))
    }
}

/// Part of the seccomp filter of a thread category.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterPart {
    /// Features that enable this part, any one of them is sufficient. A part without features is
    /// always included.
    pub features: SeccompFeatures,
    /// BPF code. Every part but the last falls through to the next one when none of its rules
    /// match the syscall being filtered.
    pub code: BpfProgram,
}

/// The seccomp filter of one thread category, as compiled by seccompiler: a sequence of parts that
/// [`SeccompFilter::compose`] assembles into the program that gets installed on a thread.
///
/// A filter without feature-gated rules is a single complete program. Otherwise the first part
/// holds the rules that are always needed and falls through instead of returning the default
/// action, the feature-gated fragments follow, and an epilogue returns the default action.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeccompFilter(pub Vec<FilterPart>);

impl SeccompFilter {
    /// Assemble the program for a microVM with `enabled` features: the parts without features
    /// and the ones with at least one enabled feature, in order.
    pub fn compose(&self, enabled: SeccompFeatures) -> BpfProgram {
        self.0
            .iter()
            .filter(|part| part.features.is_empty() || part.features.intersects(enabled))
            .flat_map(|part| part.code.iter().copied())
            .collect()
    }
}

/// Type that associates a thread category to its seccomp filter.
pub type BpfThreadMap = HashMap<String, SeccompFilter>;

/// Compose the program the `thread` threads install for a microVM with `features`, and log what
/// they get, so that a syscall they later trip over can be traced back to the composed filter.
pub fn compose_for_thread(
    filter: &SeccompFilter,
    thread: &str,
    features: SeccompFeatures,
) -> BpfProgram {
    let program = filter.compose(features);
    if program.is_empty() {
        warn!("No seccomp filter is installed on the {thread} thread");
    } else {
        info!(
            "Seccomp filter of the {thread} thread: {} instructions, features [{features}]",
            program.len()
        );
    }
    program
}

/// Binary filter deserialization errors.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum DeserializationError {
    /// Failed to read input: {0}
    InputRead(std::io::Error),
    /// Input size {0} exceeds limit of {1} bytes
    SizeLimitExceeded(usize, usize),
    /// Bitcode deserialization failed: {0}
    Bitcode(#[from] bitcode::Error),
    /// Filter part tagged with an unknown feature: {0}
    UnknownFeature(#[from] UnknownSeccompFeature),
}

/// Retrieve empty seccomp filters.
pub fn get_empty_filters() -> BpfThreadMap {
    let mut map = BpfThreadMap::new();
    map.insert("vmm".to_string(), SeccompFilter::default());
    map.insert("api".to_string(), SeccompFilter::default());
    map.insert("vcpu".to_string(), SeccompFilter::default());
    map
}

/// Deserialize binary with bpf filters
pub fn deserialize_binary<R: Read>(reader: R) -> Result<BpfThreadMap, DeserializationError> {
    // Check size limit before reading the full file to prevent DOS attacks
    let mut buf = Vec::new();
    let bytes_read = reader
        .take((DESERIALIZATION_BYTES_LIMIT + 1) as u64)
        .read_to_end(&mut buf)
        .map_err(DeserializationError::InputRead)?;

    if bytes_read > DESERIALIZATION_BYTES_LIMIT {
        return Err(DeserializationError::SizeLimitExceeded(
            bytes_read,
            DESERIALIZATION_BYTES_LIMIT,
        ));
    }

    let result: HashMap<String, Vec<SerializedPart>> = bitcode::deserialize(&buf)?;

    // A typo in a feature tag fails here rather than silently leaving a rule out.
    let part = |part: SerializedPart| {
        let features = part
            .features
            .iter()
            .map(|name| SeccompFeatures::from_tag(name))
            .collect::<Result<_, _>>()?;
        Ok::<_, DeserializationError>(FilterPart {
            features,
            code: part.code,
        })
    };
    result
        .into_iter()
        .map(|(k, parts)| {
            let parts = parts.into_iter().map(part).collect::<Result<_, _>>()?;
            Ok((k.to_lowercase(), SeccompFilter(parts)))
        })
        .collect()
}

/// Filter installation errors.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum InstallationError {
    /// Filter length exceeds the maximum size of {BPF_MAX_LEN:} instructions
    FilterTooLarge,
    /// prctl` syscall failed with error code: {0}
    Prctl(std::io::Error),
}

/// The maximum seccomp-BPF program length allowed by the linux kernel.
pub const BPF_MAX_LEN: usize = 4096;

/// BPF structure definition for filter array.
/// See /usr/include/linux/filter.h .
#[repr(C)]
#[derive(Debug)]
struct SockFprog {
    len: u16,
    filter: *const BpfInstruction,
}

/// Apply bpf filter.
pub fn apply_filter(bpf_filter: BpfProgramRef) -> Result<(), InstallationError> {
    // If the program is empty, don't install the filter.
    if bpf_filter.is_empty() {
        return Ok(());
    }

    // If the program length is greater than the limit allowed by the kernel,
    // fail quickly. Otherwise, `prctl` will give a more cryptic error code.
    if BPF_MAX_LEN < bpf_filter.len() {
        return Err(InstallationError::FilterTooLarge);
    }

    let bpf_filter_len =
        u16::try_from(bpf_filter.len()).map_err(|_| InstallationError::FilterTooLarge)?;

    // SAFETY: Safe because the parameters are valid.
    unsafe {
        {
            let rc = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            if rc != 0 {
                return Err(InstallationError::Prctl(std::io::Error::last_os_error()));
            }
        }

        let bpf_prog = SockFprog {
            len: bpf_filter_len,
            filter: bpf_filter.as_ptr(),
        };
        let bpf_prog_ptr = &bpf_prog as *const SockFprog;
        {
            let rc = libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                0,
                bpf_prog_ptr,
            );
            if rc != 0 {
                return Err(InstallationError::Prctl(std::io::Error::last_os_error()));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]

    use std::collections::HashMap;
    use std::thread;

    use super::*;

    /// Serialize `filters` the way seccompiler writes a compiled filter file.
    fn encode(filters: Vec<(&str, Vec<SerializedPart>)>) -> Vec<u8> {
        let filters: HashMap<_, _> = filters.into_iter().collect();
        bitcode::serialize(&filters).unwrap()
    }

    fn serialized(features: &[&str], code: BpfProgram) -> SerializedPart {
        let features = features.iter().map(|name| name.to_string()).collect();
        SerializedPart { features, code }
    }

    #[test]
    fn test_deserialize_binary() {
        // Garbage, and the map of complete programs an older seccompiler wrote.
        for data in [
            &b"adassafvc"[..],
            &bitcode::serialize(&HashMap::from([("vmm", vec![0u64; 3])])).unwrap()[..],
        ] {
            assert!(matches!(
                deserialize_binary(data).unwrap_err(),
                DeserializationError::Bitcode(_)
            ));
        }

        // Test that the binary deserialization is correct, and that the thread keys
        // have been lowercased.
        let bytes = encode(vec![
            (
                "VcpU",
                vec![
                    serialized(&[], vec![0; 2]),
                    serialized(&["net", "hotplug"], vec![1; 3]),
                    serialized(&[], vec![2]),
                ],
            ),
            ("vmm", vec![]),
        ]);
        let part = |features, code| FilterPart { features, code };
        let expected = BpfThreadMap::from([
            (
                "vcpu".to_string(),
                SeccompFilter(vec![
                    part(SeccompFeatures::empty(), vec![0; 2]),
                    part(SeccompFeatures::NET | SeccompFeatures::HOTPLUG, vec![1; 3]),
                    part(SeccompFeatures::empty(), vec![2]),
                ]),
            ),
            ("vmm".to_string(), SeccompFilter::default()),
        ]);
        assert_eq!(deserialize_binary(&bytes[..]).unwrap(), expected);

        // Parts tagged with a feature this Firecracker does not know are rejected.
        let bytes = encode(vec![("vmm", vec![serialized(&["warp-drive"], vec![1])])]);
        assert!(matches!(
            deserialize_binary(&bytes[..]).unwrap_err(),
            DeserializationError::UnknownFeature(UnknownSeccompFeature(name)) if name == "warp-drive"
        ));

        // Test filter too large - create data that will exceed the deserialization limit
        // Create a large buffer that when serialized will exceed DESERIALIZATION_BYTES_LIMIT
        let large_data = vec![0u8; DESERIALIZATION_BYTES_LIMIT + 1000];
        assert!(matches!(
            deserialize_binary(&large_data[..]).unwrap_err(),
            DeserializationError::SizeLimitExceeded(..)
        ));
    }

    #[test]
    fn test_seccomp_feature_tags_complete() {
        let mut mapped = SeccompFeatures::empty();
        let mut tags = std::collections::HashSet::new();
        for &(feature, tag) in SeccompFeatures::TAGS {
            assert_eq!(feature.bits().count_ones(), 1);
            assert!(!mapped.intersects(feature), "Duplicate feature {feature:?}");
            assert!(tags.insert(tag), "Duplicate tag {tag}");
            assert_eq!(SeccompFeatures::from_tag(tag), Ok(feature));
            assert_eq!(feature.to_string(), tag);
            mapped |= feature;
        }
        assert_eq!(mapped, SeccompFeatures::all());
    }

    #[test]
    fn test_seccomp_features() {
        for feature in SeccompFeatures::all().iter() {
            assert_eq!(SeccompFeatures::from_tag(&feature.to_string()), Ok(feature));
        }
        assert_eq!(
            SeccompFeatures::all().to_string(),
            "api,pci,hotplug,block,async-io,net,vsock,pmem,memory-hotplug"
        );
        assert_eq!(SeccompFeatures::empty().to_string(), "");
        assert_eq!(
            SeccompFeatures::from_tag("warp-drive"),
            Err(UnknownSeccompFeature("warp-drive".to_string()))
        );

        assert_eq!("all".parse(), Ok(SeccompFeatures::all()));
        assert_eq!(
            " net, block,hotplug".parse(),
            Ok(SeccompFeatures::NET | SeccompFeatures::BLOCK | SeccompFeatures::HOTPLUG)
        );
        for (list, unknown) in [("", ""), ("net,,block", ""), ("net,all", "all")] {
            assert_eq!(
                list.parse::<SeccompFeatures>(),
                Err(UnknownSeccompFeature(unknown.to_string()))
            );
        }
    }

    #[test]
    fn test_compose() {
        let part = |features, code| FilterPart { features, code };
        assert!(
            SeccompFilter::default()
                .compose(SeccompFeatures::all())
                .is_empty()
        );

        let filter = SeccompFilter(vec![
            part(SeccompFeatures::empty(), vec![1, 2]),
            part(SeccompFeatures::NET, vec![10, 11]),
            part(
                SeccompFeatures::PMEM | SeccompFeatures::MEMORY_HOTPLUG,
                vec![20],
            ),
            part(SeccompFeatures::empty(), vec![3]),
        ]);
        for (enabled, expected) in [
            (SeccompFeatures::empty(), vec![1, 2, 3]),
            (SeccompFeatures::NET, vec![1, 2, 10, 11, 3]),
            // Any one of a part's features enables it.
            (SeccompFeatures::PMEM, vec![1, 2, 20, 3]),
            (SeccompFeatures::MEMORY_HOTPLUG, vec![1, 2, 20, 3]),
            (SeccompFeatures::BLOCK, vec![1, 2, 3]),
            (SeccompFeatures::all(), vec![1, 2, 10, 11, 20, 3]),
        ] {
            assert_eq!(filter.compose(enabled), expected, "{enabled}");
        }
    }

    #[test]
    fn test_filter_apply() {
        // Test filter too large.
        thread::spawn(|| {
            let filter: BpfProgram = vec![0; 5000];

            // Apply seccomp filter.
            assert!(matches!(
                apply_filter(&filter).unwrap_err(),
                InstallationError::FilterTooLarge
            ));
        })
        .join()
        .unwrap();

        // Test empty filter.
        thread::spawn(|| {
            let filter: BpfProgram = vec![];

            assert_eq!(filter.len(), 0);

            let seccomp_level = unsafe { libc::prctl(libc::PR_GET_SECCOMP) };
            assert_eq!(seccomp_level, 0);

            apply_filter(&filter).unwrap();

            // test that seccomp level remains 0 on failure.
            let seccomp_level = unsafe { libc::prctl(libc::PR_GET_SECCOMP) };
            assert_eq!(seccomp_level, 0);
        })
        .join()
        .unwrap();

        // Test invalid BPF code.
        thread::spawn(|| {
            let filter = vec![0xFF; 1];

            let seccomp_level = unsafe { libc::prctl(libc::PR_GET_SECCOMP) };
            assert_eq!(seccomp_level, 0);

            assert!(matches!(
                apply_filter(&filter).unwrap_err(),
                InstallationError::Prctl(_)
            ));

            // test that seccomp level remains 0 on failure.
            let seccomp_level = unsafe { libc::prctl(libc::PR_GET_SECCOMP) };
            assert_eq!(seccomp_level, 0);
        })
        .join()
        .unwrap();
    }
}
