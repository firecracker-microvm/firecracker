// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fmt;
use std::io::Read;
use std::ops::{BitOr, BitOrAssign};
use std::str::FromStr;

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

/// A capability of the microVM that some syscall rules are only needed for.
///
/// Syscall rules in the JSON filters can be tagged with one or more features. seccompiler compiles
/// tagged rules into separate BPF fragments which are only included in a thread's filter when one
/// of their features is enabled for the running microVM, see [`SeccompFilter::compose`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SeccompFeature {
    /// Runtime control of the microVM through the API: pausing and resuming it, and saving its
    /// state for a snapshot.
    Api = 0,
    /// VirtIO devices attached over the PCI transport (MSI-X, BAR relocation, teardown).
    Pci,
    /// Hot-plugging and unplugging devices through the API after boot, which is possible when the
    /// API is enabled and the PCI transport is used.
    Hotplug,
    /// virtio-block devices.
    Block,
    /// virtio-block devices using the asynchronous (io_uring) file engine.
    AsyncIo,
    /// virtio-net devices.
    Net,
    /// The virtio-vsock device.
    Vsock,
    /// virtio-pmem devices.
    Pmem,
    /// virtio-mem memory hotplug.
    MemoryHotplug,
}

impl SeccompFeature {
    /// Every feature, in bit order.
    pub const ALL: [SeccompFeature; 9] = [
        SeccompFeature::Api,
        SeccompFeature::Pci,
        SeccompFeature::Hotplug,
        SeccompFeature::Block,
        SeccompFeature::AsyncIo,
        SeccompFeature::Net,
        SeccompFeature::Vsock,
        SeccompFeature::Pmem,
        SeccompFeature::MemoryHotplug,
    ];

    /// The name used to tag rules with this feature in the JSON filters.
    pub const fn name(self) -> &'static str {
        match self {
            SeccompFeature::Api => "api",
            SeccompFeature::Pci => "pci",
            SeccompFeature::Hotplug => "hotplug",
            SeccompFeature::Block => "block",
            SeccompFeature::AsyncIo => "async-io",
            SeccompFeature::Net => "net",
            SeccompFeature::Vsock => "vsock",
            SeccompFeature::Pmem => "pmem",
            SeccompFeature::MemoryHotplug => "memory-hotplug",
        }
    }

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

/// Part of a seccomp filter that is only needed when one of its features is enabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterFragment {
    /// Features that enable this fragment; any one of them is sufficient.
    pub features: SeccompFeatures,
    /// Position independent BPF code. It falls through to the next fragment when its rule does
    /// not match the syscall being filtered.
    pub code: BpfProgram,
}

/// The seccomp filter of one thread category, as compiled by seccompiler.
///
/// `base` holds the rules that are always needed. When the filter has feature-gated parts, the
/// base does not return the default action itself but falls through to the code appended after it:
/// the `fragments` of the enabled features followed by the `epilogue`, which returns the default
/// action. [`SeccompFilter::compose`] assembles the program that gets installed on a thread.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeccompFilter {
    base: BpfProgram,
    fragments: Vec<FilterFragment>,
    epilogue: BpfProgram,
}

impl SeccompFilter {
    /// Create a filter from its parts.
    pub fn new(base: BpfProgram, fragments: Vec<FilterFragment>, epilogue: BpfProgram) -> Self {
        SeccompFilter {
            base,
            fragments,
            epilogue,
        }
    }

    /// Create a filter from a complete program that has no feature-gated parts.
    pub fn from_program(program: BpfProgram) -> Self {
        SeccompFilter::new(program, Vec::new(), Vec::new())
    }

    /// Whether composing this filter yields an empty program, i.e. no filter gets installed.
    pub fn is_empty(&self) -> bool {
        self.base.is_empty()
            && self.epilogue.is_empty()
            && self
                .fragments
                .iter()
                .all(|fragment| fragment.code.is_empty())
    }

    /// The features for which this filter has fragments.
    pub fn features(&self) -> SeccompFeatures {
        self.fragments
            .iter()
            .fold(SeccompFeatures::empty(), |set, fragment| {
                set | fragment.features
            })
    }

    /// Assemble the program for a microVM with `enabled` features: the base, the fragments that
    /// have at least one enabled feature and the epilogue.
    pub fn compose(&self, enabled: SeccompFeatures) -> BpfProgram {
        let fragments = self
            .fragments
            .iter()
            .filter(|fragment| fragment.features.intersects(enabled));
        let mut program = Vec::with_capacity(
            self.base.len()
                + self.epilogue.len()
                + fragments
                    .clone()
                    .map(|fragment| fragment.code.len())
                    .sum::<usize>(),
        );
        program.extend_from_slice(&self.base);
        for fragment in fragments {
            program.extend_from_slice(&fragment.code);
        }
        program.extend_from_slice(&self.epilogue);
        program
    }
}

/// Type that associates a thread category to its seccomp filter.
pub type BpfThreadMap = HashMap<String, SeccompFilter>;

/// Binary filter deserialization errors.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum DeserializationError {
    /// Failed to read input: {0}
    InputRead(std::io::Error),
    /// Input size {0} exceeds limit of {1} bytes
    SizeLimitExceeded(usize, usize),
    /// Bitcode deserialization failed: {0}
    Bitcode(#[from] bitcode::Error),
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

    let result: HashMap<String, BpfProgram> = bitcode::deserialize(&buf)?;

    Ok(result
        .into_iter()
        .map(|(k, v)| (k.to_lowercase(), SeccompFilter::from_program(v)))
        .collect())
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

    #[test]
    fn test_deserialize_binary() {
        // Malformed bitcode binary.
        let data = "adassafvc".to_string();
        deserialize_binary(data.as_bytes()).unwrap_err();

        // Test that the binary deserialization is correct, and that the thread keys
        // have been lowercased.
        let bpf_prog = vec![0; 2];
        let mut filter_map: HashMap<String, BpfProgram> = HashMap::new();
        filter_map.insert("VcpU".to_string(), bpf_prog.clone());
        let bytes = bitcode::serialize(&filter_map).unwrap();

        let mut expected_res = BpfThreadMap::new();
        expected_res.insert("vcpu".to_string(), SeccompFilter::from_program(bpf_prog));
        assert_eq!(deserialize_binary(&bytes[..]).unwrap(), expected_res);

        // Test filter too large - create data that will exceed the deserialization limit
        // Create a large buffer that when serialized will exceed DESERIALIZATION_BYTES_LIMIT
        let large_data = vec![0u8; DESERIALIZATION_BYTES_LIMIT + 1000];
        deserialize_binary(&large_data[..]).unwrap_err();
    }

    #[test]
    fn test_seccomp_features() {
        assert!(SeccompFeatures::empty().is_empty());
        assert!(!SeccompFeatures::all().is_empty());
        for feature in SeccompFeature::ALL {
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

    #[test]
    fn test_compose() {
        let empty = SeccompFilter::default();
        assert!(empty.is_empty());
        assert!(empty.compose(SeccompFeatures::all()).is_empty());

        let plain = SeccompFilter::from_program(vec![1, 2, 3]);
        assert!(!plain.is_empty());
        assert_eq!(plain.features(), SeccompFeatures::empty());
        assert_eq!(plain.compose(SeccompFeatures::empty()), vec![1, 2, 3]);
        assert_eq!(plain.compose(SeccompFeatures::all()), vec![1, 2, 3]);

        let filter = SeccompFilter::new(
            vec![1, 2],
            vec![
                FilterFragment {
                    features: SeccompFeature::Net.into(),
                    code: vec![10, 11],
                },
                FilterFragment {
                    features: SeccompFeatures::from(SeccompFeature::Pmem)
                        | SeccompFeature::MemoryHotplug,
                    code: vec![20],
                },
            ],
            vec![3],
        );
        assert!(!filter.is_empty());
        assert_eq!(
            filter.features(),
            SeccompFeatures::from(SeccompFeature::Net)
                | SeccompFeature::Pmem
                | SeccompFeature::MemoryHotplug
        );
        assert_eq!(filter.compose(SeccompFeatures::empty()), vec![1, 2, 3]);
        assert_eq!(
            filter.compose(SeccompFeature::Net.into()),
            vec![1, 2, 10, 11, 3]
        );
        // Any one of a fragment's features enables it.
        assert_eq!(
            filter.compose(SeccompFeature::Pmem.into()),
            vec![1, 2, 20, 3]
        );
        assert_eq!(
            filter.compose(SeccompFeature::MemoryHotplug.into()),
            vec![1, 2, 20, 3]
        );
        assert_eq!(filter.compose(SeccompFeature::Block.into()), vec![1, 2, 3]);
        assert_eq!(
            filter.compose(SeccompFeatures::all()),
            vec![1, 2, 10, 11, 20, 3]
        );
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
