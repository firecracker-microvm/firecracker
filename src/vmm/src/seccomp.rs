// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fmt;
use std::io::Read;
use std::str::FromStr;

use serde::Deserialize;
#[cfg(test)]
use serde::Serialize;

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
    /// Syscall rules in the JSON filters can be tagged with one or more features, named after these
    /// constants in kebab case (`async-io` for [`SeccompFeatures::ASYNC_IO`]). seccompiler compiles
    /// tagged rules into separate parts of a thread's filter, which are only included when one of
    /// their features is enabled for the running microVM, see [`SeccompFilter::compose`].
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
    /// The feature that `name` tags rules with in the JSON filters.
    pub fn from_tag(name: &str) -> Result<Self, UnknownSeccompFeature> {
        Self::all()
            .iter()
            .find(|feature| feature.to_string() == name)
            .ok_or_else(|| UnknownSeccompFeature(name.to_string()))
    }
}

impl FromStr for SeccompFeatures {
    type Err = UnknownSeccompFeature;

    /// `all`, `none`, or a comma-separated list of feature names.
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
    /// Comma separated feature names.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<_> = self
            .iter_names()
            .map(|(name, _)| name.to_lowercase().replace('_', "-"))
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

    /// Check that the filter has the layout seccompiler gives it, so that every composition of
    /// its parts is a well-formed program in which each part either returns or falls through to
    /// the next one.
    ///
    /// An empty filter installs nothing, and a single part must be a complete program. Several
    /// parts must be an untagged base, tagged fragments and an untagged `ret K` epilogue. The
    /// base and the fragments must not return the epilogue's action nor `A`, and may only jump
    /// within themselves or to the start of the next part. Only jumps and returns are checked.
    pub fn validate(&self) -> Result<(), FilterLayoutError> {
        let parts = &self.0;
        let len: usize = parts.iter().map(|part| part.code.len()).sum();
        if len > BPF_MAX_LEN {
            return Err(FilterLayoutError::TooLong(len));
        }
        if let Some(index) = parts.iter().position(|part| part.code.is_empty()) {
            return Err(FilterLayoutError::EmptyPart(index));
        }
        let (epilogue, body) = match parts.as_slice() {
            [] => return Ok(()),
            [part, ..] if !part.features.is_empty() => return Err(FilterLayoutError::TaggedBase),
            [part] => {
                let last = part.code.len() - 1;
                if decode(part.code[last]).0 & BPF_CLASS_MASK != BPF_RET {
                    return Err(FilterLayoutError::NoFinalReturn);
                }
                return check_jumps(0, &part.code, last);
            }
            [body @ .., epilogue] => (epilogue, body),
        };

        if !epilogue.features.is_empty() {
            return Err(FilterLayoutError::TaggedEpilogue);
        }
        let default_action = match epilogue.code.as_slice() {
            &[instruction] if decode(instruction).0 == BPF_RET_K => decode(instruction).3,
            _ => return Err(FilterLayoutError::InvalidEpilogue),
        };
        for (index, part) in body.iter().enumerate() {
            if index > 0 && part.features.is_empty() {
                return Err(FilterLayoutError::UntaggedFragment(index));
            }
            for (pc, &instruction) in part.code.iter().enumerate() {
                match decode(instruction) {
                    (BPF_RET_K, _, _, k) if k == default_action => {
                        return Err(FilterLayoutError::DefaultReturn(index, pc));
                    }
                    (BPF_RET_A, ..) => {
                        return Err(FilterLayoutError::ReturnAccumulator(index, pc));
                    }
                    _ => (),
                }
            }
            // Landing right after the part continues in the next one.
            check_jumps(index, &part.code, part.code.len())?;
        }
        Ok(())
    }
}

/// Ways in which a compiled filter does not have the layout seccompiler gives it.
#[derive(Debug, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
pub enum FilterLayoutError {
    /// The program with every part included has {0} instructions, more than the maximum of {BPF_MAX_LEN:}
    TooLong(usize),
    /// Part {0} contains no instructions
    EmptyPart(usize),
    /// The first part is tagged with features, it must always be installed
    TaggedBase,
    /// The last part is tagged with features, it must always be installed
    TaggedEpilogue,
    /// Part {0} is not tagged with features, only the first and last parts can be untagged
    UntaggedFragment(usize),
    /// The last part is not a single `ret` instruction returning the default action of the filter
    InvalidEpilogue,
    /// The program does not end with a `ret` instruction
    NoFinalReturn,
    /// Instruction {1} of part {0} jumps past the end of its part
    JumpOutOfPart(usize, usize),
    /// Instruction {1} of part {0} returns the default action instead of falling through to the next part
    DefaultReturn(usize, usize),
    /// Instruction {1} of part {0} returns the accumulator, only a single-part filter may do so
    ReturnAccumulator(usize, usize),
}

/// Mask of the instruction class in the code of a BPF instruction.
const BPF_CLASS_MASK: u16 = 0x07;
/// Mask of the operation in the code of a BPF instruction.
const BPF_OP_MASK: u16 = 0xf0;
/// Class of the jump instructions.
const BPF_JMP: u16 = 0x05;
/// Operation of the unconditional jump, to `pc + 1 + k`, in the jump class.
const BPF_JA: u16 = 0x00;
/// Class of the return instructions.
const BPF_RET: u16 = 0x06;
/// `BPF_RET | BPF_K`: return `k`.
const BPF_RET_K: u16 = 0x06;
/// `BPF_RET | BPF_A`: return the accumulator.
const BPF_RET_A: u16 = 0x16;

/// Decode one `struct sock_filter { u16 code; u8 jt; u8 jf; u32 k; }` instruction into
/// `(code, jt, jf, k)`.
fn decode(instruction: BpfInstruction) -> (u16, u8, u8, u32) {
    let b = instruction.to_le_bytes();
    (
        u16::from_le_bytes([b[0], b[1]]),
        b[2],
        b[3],
        u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
    )
}

/// Check that no jump of part `index`, whose instructions are `program`, goes past `max_target`.
fn check_jumps(
    index: usize,
    program: BpfProgramRef,
    max_target: usize,
) -> Result<(), FilterLayoutError> {
    for (pc, &instruction) in program.iter().enumerate() {
        let (code, jt, jf, k) = decode(instruction);
        if code & BPF_CLASS_MASK != BPF_JMP {
            continue;
        }
        let offset = if code & BPF_OP_MASK == BPF_JA {
            u64::from(k)
        } else {
            u64::from(jt.max(jf))
        };
        // Counted in u64, since a `ja` can jump up to u32::MAX instructions ahead.
        let target = u64::try_from(pc + 1).map_or(u64::MAX, |next| next.saturating_add(offset));
        if u64::try_from(max_target).is_ok_and(|max| target > max) {
            return Err(FilterLayoutError::JumpOutOfPart(index, pc));
        }
    }
    Ok(())
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
    /// Filter in the format of an older seccompiler-bin, recompile it with the one of this release
    OlderFormat,
    /// Filter part tagged with an unknown feature: {0}
    UnknownFeature(#[from] UnknownSeccompFeature),
    /// Invalid seccomp filter for the {0} thread: {1}
    Layout(String, FilterLayoutError),
}

/// Serialized form of [`FilterPart`], as written by seccompiler (`BpfPart` in its types).
///
/// Firecracker does not depend on seccompiler, which links libseccomp, so the layout is mirrored
/// here and must be kept in sync.
#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(Serialize))]
struct SerializedPart {
    features: Vec<String>,
    code: BpfProgram,
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

    let result: HashMap<String, Vec<SerializedPart>> = match bitcode::deserialize(&buf) {
        Ok(result) => result,
        // Earlier releases wrote a single complete program per thread.
        Err(_) if bitcode::deserialize::<HashMap<String, BpfProgram>>(&buf).is_ok() => {
            return Err(DeserializationError::OlderFormat);
        }
        Err(err) => return Err(err.into()),
    };

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
            let thread = k.to_lowercase();
            let parts = parts.into_iter().map(part).collect::<Result<_, _>>()?;
            // A malformed filter fails here rather than when a thread installs it, if ever.
            let filter = SeccompFilter(parts);
            filter
                .validate()
                .map_err(|err| DeserializationError::Layout(thread.clone(), err))?;
            Ok((thread, filter))
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

    const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

    /// Encode one `sock_filter` instruction.
    fn insn(code: u16, jt: u8, jf: u8, k: u32) -> BpfInstruction {
        u64::from(code) | (u64::from(jt) << 16) | (u64::from(jf) << 24) | (u64::from(k) << 32)
    }

    /// Allow syscall `nr`, and fall through to whatever follows for the others.
    fn allow(nr: u32) -> BpfProgram {
        vec![
            // ld [0]: the syscall number.
            insn(0x20, 0, 0, 0),
            // jeq #nr, 0, 1
            insn(0x15, 0, 1, nr),
            insn(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW),
        ]
    }

    /// Return the default action of the test filters.
    fn trap() -> BpfProgram {
        vec![insn(BPF_RET_K, 0, 0, SECCOMP_RET_TRAP)]
    }

    #[test]
    fn test_deserialize_binary() {
        assert!(matches!(
            deserialize_binary(&b"adassafvc"[..]).unwrap_err(),
            DeserializationError::Bitcode(_)
        ));

        // The map of complete programs an older seccompiler wrote is told apart.
        let older = bitcode::serialize(&HashMap::from([("vmm", vec![0u64; 3])])).unwrap();
        assert!(matches!(
            deserialize_binary(&older[..]).unwrap_err(),
            DeserializationError::OlderFormat
        ));

        // Test that the binary deserialization is correct, and that the thread keys
        // have been lowercased.
        let bytes = encode(vec![
            (
                "VcpU",
                vec![
                    serialized(&[], allow(1)),
                    serialized(&["net", "hotplug"], allow(2)),
                    serialized(&[], trap()),
                ],
            ),
            ("API", vec![serialized(&[], [allow(3), trap()].concat())]),
            ("vmm", vec![]),
        ]);
        let part = |features, code| FilterPart { features, code };
        let expected = BpfThreadMap::from([
            (
                "vcpu".to_string(),
                SeccompFilter(vec![
                    part(SeccompFeatures::empty(), allow(1)),
                    part(SeccompFeatures::NET | SeccompFeatures::HOTPLUG, allow(2)),
                    part(SeccompFeatures::empty(), trap()),
                ]),
            ),
            (
                "api".to_string(),
                SeccompFilter(vec![part(
                    SeccompFeatures::empty(),
                    [allow(3), trap()].concat(),
                )]),
            ),
            ("vmm".to_string(), SeccompFilter::default()),
        ]);
        assert_eq!(deserialize_binary(&bytes[..]).unwrap(), expected);

        // Parts tagged with a feature this Firecracker does not know are rejected.
        let bytes = encode(vec![(
            "vmm",
            vec![
                serialized(&[], allow(1)),
                serialized(&["warp-drive"], allow(2)),
                serialized(&[], trap()),
            ],
        )]);
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
    fn test_deserialize_binary_layout() {
        // A fragment that would fall through into the epilogue without returning its rules'
        // action is rejected when the file is loaded, naming the thread.
        let bytes = encode(vec![
            ("vmm", vec![serialized(&[], [allow(1), trap()].concat())]),
            (
                "VCPU",
                vec![
                    serialized(&[], allow(1)),
                    serialized(&["net"], trap()),
                    serialized(&[], trap()),
                ],
            ),
        ]);
        let err = deserialize_binary(&bytes[..]).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Invalid seccomp filter for the vcpu thread: Instruction 0 of part 1 returns the \
             default action instead of falling through to the next part"
        );
        assert!(matches!(
            err,
            DeserializationError::Layout(thread, FilterLayoutError::DefaultReturn(1, 0))
                if thread == "vcpu"
        ));
    }

    #[test]
    fn test_validate() {
        use FilterLayoutError::*;

        let base = |code| FilterPart {
            features: SeccompFeatures::empty(),
            code,
        };
        let tagged = |code| FilterPart {
            features: SeccompFeatures::NET | SeccompFeatures::BLOCK,
            code,
        };
        let ja = |k| insn(0x05, 0, 0, k);
        let ret_a = insn(BPF_RET_A, 0, 0, 0);

        let valid = [
            // No filter.
            vec![],
            // A complete program.
            vec![base([allow(1), trap()].concat())],
            vec![base(trap())],
            // A base, fragments falling through, and the epilogue.
            vec![
                base(allow(1)),
                tagged(allow(2)),
                tagged([allow(3), vec![ja(0)], allow(4)].concat()),
                base(trap()),
            ],
            // Jumps landing right after their part, in the next one.
            vec![
                base(vec![ja(0)]),
                tagged(vec![insn(0x15, 1, 0, 1), ja(0)]),
                base(trap()),
            ],
            // A complete program can return the accumulator.
            vec![base(vec![ja(0), ret_a])],
            // A base and the epilogue.
            vec![base(allow(1)), base(trap())],
            // Returns of another action than the epilogue's.
            vec![
                base(vec![insn(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW)]),
                base(trap()),
            ],
        ];
        for parts in valid {
            let filter = SeccompFilter(parts);
            assert_eq!(filter.validate(), Ok(()), "{filter:?}");
        }

        let too_long = vec![insn(BPF_RET_K, 0, 0, SECCOMP_RET_TRAP); BPF_MAX_LEN];
        let invalid = [
            (
                vec![base(too_long.clone()), base(trap())],
                TooLong(BPF_MAX_LEN + 1),
            ),
            (
                vec![base([too_long, trap()].concat())],
                TooLong(BPF_MAX_LEN + 1),
            ),
            (vec![base(vec![])], EmptyPart(0)),
            (
                vec![base(allow(1)), tagged(vec![]), base(trap())],
                EmptyPart(1),
            ),
            (vec![base(allow(1)), base(vec![])], EmptyPart(1)),
            (vec![tagged([allow(1), trap()].concat())], TaggedBase),
            (vec![tagged(allow(1)), base(trap())], TaggedBase),
            (vec![base(allow(1)), tagged(trap())], TaggedEpilogue),
            (
                vec![base(allow(1)), base(allow(2)), base(trap())],
                UntaggedFragment(1),
            ),
            (
                vec![
                    base(allow(1)),
                    tagged(allow(2)),
                    base(allow(3)),
                    base(trap()),
                ],
                UntaggedFragment(2),
            ),
            (
                vec![base(allow(1)), base([trap(), trap()].concat())],
                InvalidEpilogue,
            ),
            (vec![base(allow(1)), base(vec![ret_a])], InvalidEpilogue),
            (vec![base(allow(1)), base(vec![ja(0)])], InvalidEpilogue),
            (vec![base(allow(1))], JumpOutOfPart(0, 1)),
            (vec![base(vec![insn(0x20, 0, 0, 0)])], NoFinalReturn),
            (vec![base([trap(), vec![ja(0)]].concat())], NoFinalReturn),
            (
                vec![base(vec![ja(1), insn(0x15, 0, 2, 1), ret_a, ret_a])],
                JumpOutOfPart(0, 1),
            ),
            (
                vec![base(allow(1)), tagged(vec![ja(1)]), base(trap())],
                JumpOutOfPart(1, 0),
            ),
            (
                vec![base(allow(1)), tagged(vec![ja(u32::MAX)]), base(trap())],
                JumpOutOfPart(1, 0),
            ),
            (
                vec![base(vec![insn(0x15, 2, 0, 1), ja(0)]), base(trap())],
                JumpOutOfPart(0, 0),
            ),
            (
                vec![
                    base(allow(1)),
                    tagged([allow(2), trap()].concat()),
                    base(trap()),
                ],
                DefaultReturn(1, 3),
            ),
            (
                vec![base([trap(), allow(1)].concat()), base(trap())],
                DefaultReturn(0, 0),
            ),
            (
                vec![base([allow(1), vec![ret_a]].concat()), base(trap())],
                ReturnAccumulator(0, 3),
            ),
        ];
        for (parts, expected) in invalid {
            let filter = SeccompFilter(parts);
            assert_eq!(filter.validate(), Err(expected), "{filter:?}");
        }
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
        assert_eq!(" none ".parse(), Ok(SeccompFeatures::empty()));
        assert_eq!(
            " net, block,hotplug".parse(),
            Ok(SeccompFeatures::NET | SeccompFeatures::BLOCK | SeccompFeatures::HOTPLUG)
        );
        for (list, unknown) in [
            ("", ""),
            ("net,,block", ""),
            ("net,all", "all"),
            ("none,net", "none"),
        ] {
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
