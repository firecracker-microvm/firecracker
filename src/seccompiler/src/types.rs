// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::ffi::CString;
use std::str::FromStr;

use serde::*;

// use libseccomp::{ScmpAction, ScmpArch, ScmpCompareOp};
use crate::bindings::*;

/// Comparison to perform when matching a condition.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeccompCmpOp {
    Eq,
    Ge,
    Gt,
    Le,
    Lt,
    MaskedEq(u64),
    Ne,
}

/// Seccomp argument value length.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SeccompCmpArgLen {
    /// Argument value length is 4 bytes.
    Dword,
    /// Argument value length is 8 bytes.
    Qword,
}

/// Condition that syscall must match in order to satisfy a rule.
///
/// Unknown keys are rejected, so that a misspelled key cannot silently drop a condition.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeccompCondition {
    pub index: u8,
    pub op: SeccompCmpOp,
    pub val: u64,
    #[serde(rename = "type")]
    pub val_len: SeccompCmpArgLen,
    /// Free-form documentation of the condition, ignored by the compiler.
    #[serde(default)]
    pub comment: Option<String>,
}

impl SeccompCondition {
    pub fn to_scmp_type(&self) -> scmp_arg_cmp {
        match self.op {
            SeccompCmpOp::Eq => {
                // When using EQ libseccomp compares the whole 64 bits. In
                // general this is not a problem, but for example we have
                // observed musl `ioctl` to leave garbage in the upper bits of
                // the `request` argument. There is a GH issue to allow 32bit
                // comparisons (see
                // https://github.com/seccomp/libseccomp/issues/383) but is not
                // merged yet. Until that is available, do a masked comparison
                // with the upper 32bits set to 0, so we will compare that `hi32
                // & 0x0 == 0`, which is always true. This costs one additional
                // instruction, but will be likely be optimized away by the BPF
                // JIT.
                match self.val_len {
                    SeccompCmpArgLen::Dword => scmp_arg_cmp {
                        arg: self.index as u32,
                        op: scmp_compare::SCMP_CMP_MASKED_EQ,
                        datum_a: 0x00000000FFFFFFFF,
                        datum_b: self.val,
                    },
                    SeccompCmpArgLen::Qword => scmp_arg_cmp {
                        arg: self.index as u32,
                        op: scmp_compare::SCMP_CMP_EQ,
                        datum_a: self.val,
                        datum_b: 0,
                    },
                }
            }
            SeccompCmpOp::Ge => scmp_arg_cmp {
                arg: self.index as u32,
                op: scmp_compare::SCMP_CMP_GE,
                datum_a: self.val,
                datum_b: 0,
            },
            SeccompCmpOp::Gt => scmp_arg_cmp {
                arg: self.index as u32,
                op: scmp_compare::SCMP_CMP_GT,
                datum_a: self.val,
                datum_b: 0,
            },
            SeccompCmpOp::Le => scmp_arg_cmp {
                arg: self.index as u32,
                op: scmp_compare::SCMP_CMP_LE,
                datum_a: self.val,
                datum_b: 0,
            },
            SeccompCmpOp::Lt => scmp_arg_cmp {
                arg: self.index as u32,
                op: scmp_compare::SCMP_CMP_LT,
                datum_a: self.val,
                datum_b: 0,
            },
            SeccompCmpOp::Ne => scmp_arg_cmp {
                arg: self.index as u32,
                op: scmp_compare::SCMP_CMP_NE,
                datum_a: self.val,
                datum_b: 0,
            },

            SeccompCmpOp::MaskedEq(m) => scmp_arg_cmp {
                arg: self.index as u32,
                op: scmp_compare::SCMP_CMP_MASKED_EQ,
                datum_a: m,
                datum_b: self.val,
            },
        }
    }
}

/// Actions that `seccomp` can apply to process calling a syscall.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeccompAction {
    Allow,
    Errno(u16),
    KillThread,
    KillProcess,
    Log,
    Trace(u16),
    Trap,
}

impl SeccompAction {
    pub fn to_scmp_type(&self) -> u32 {
        match self {
            SeccompAction::Allow => SCMP_ACT_ALLOW,
            SeccompAction::Errno(e) => SCMP_ACT_ERRNO(*e),
            SeccompAction::KillThread => SCMP_ACT_KILL_THREAD,
            SeccompAction::KillProcess => SCMP_ACT_KILL_PROCESS,
            SeccompAction::Log => SCMP_ACT_LOG,
            SeccompAction::Trace(t) => SCMP_ACT_TRACE(*t),
            SeccompAction::Trap => SCMP_ACT_TRAP,
        }
    }
}

/// Rule that `seccomp` attempts to match for a syscall.
///
/// If all conditions match then rule gets matched.
/// The action of the first rule that matches will be applied to the calling process.
/// If no rule matches the default action is applied.
///
/// A rule can be tagged with the features of the microVM it is needed for, either as
/// `"feature": "net"` or as `"features": ["pmem", "memory-hotplug"]`. Tagged rules are compiled
/// into separate BPF fragments which Firecracker only installs when one of the features is in use;
/// untagged rules are always installed. Unknown keys are rejected, so that a misspelled tag key
/// cannot silently turn a tagged rule into an always installed one.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyscallRule {
    pub syscall: CString,
    pub args: Option<Vec<SeccompCondition>>,
    #[serde(default, alias = "feature", deserialize_with = "deserialize_features")]
    pub features: Option<Vec<String>>,
    /// Free-form documentation of the rule, ignored by the compiler.
    #[serde(default)]
    pub comment: Option<String>,
}

/// Accept a single feature name as well as a list of them.
fn deserialize_features<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Features {
        One(String),
        Many(Vec<String>),
    }

    Ok(Some(match Features::deserialize(deserializer)? {
        Features::One(feature) => vec![feature],
        Features::Many(features) => features,
    }))
}

/// Filter containing rules assigned to syscall numbers.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filter {
    pub default_action: SeccompAction,
    pub filter_action: SeccompAction,
    pub filter: Vec<SyscallRule>,
}

/// Deserializable object that represents the Json filter file.
#[derive(Debug, Deserialize)]
pub struct BpfJson(pub BTreeMap<String, Filter>);

/// BPF code of the feature-tagged rules sharing a feature set, as stored in the compiled filter.
///
/// The code is position independent and falls through when its rule does not match, so
/// fragments can be concatenated in any order after the base program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BpfFragment {
    /// The features the fragment is needed for; any one of them being in use is sufficient.
    pub features: Vec<String>,
    /// The BPF instructions of the fragment.
    pub code: Vec<u64>,
}

/// The compiled filter of one thread category.
///
/// `base` is the libseccomp program of the untagged rules. When the filter has tagged rules, the
/// base does not return the default action but falls through to the code appended after it, and
/// ends with a prologue re-checking the architecture; the enabled `fragments` follow and the
/// `epilogue` returns the default action. Without tagged rules the base is the whole program and
/// the other two parts are empty.
///
/// Firecracker reads this layout in `vmm::seccomp`, which must be kept in sync with it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BpfFilter {
    pub base: Vec<u64>,
    pub fragments: Vec<BpfFragment>,
    pub epilogue: Vec<u64>,
}

impl BpfFilter {
    /// The program with the fragments `selection` picks included.
    pub fn compose(&self, selection: &FeatureSelection) -> Vec<u64> {
        let mut program = self.base.clone();
        for fragment in &self.fragments {
            let included = match selection {
                FeatureSelection::All => true,
                FeatureSelection::None => false,
                FeatureSelection::Only(features) => fragment
                    .features
                    .iter()
                    .any(|feature| features.contains(feature)),
            };
            if included {
                program.extend_from_slice(&fragment.code);
            }
        }
        program.extend_from_slice(&self.epilogue);
        program
    }

    /// The program with every fragment included.
    pub fn compose_all(&self) -> Vec<u64> {
        self.compose(&FeatureSelection::All)
    }
}

/// Which fragments to include when composing a thread's program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeatureSelection {
    /// Every fragment.
    All,
    /// No fragment: only the base program and the epilogue.
    None,
    /// The fragments tagged with at least one of these features.
    Only(Vec<String>),
}

impl FromStr for FeatureSelection {
    type Err = String;

    /// `all`, `none`, or a comma-separated list of feature names.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "all" => Ok(FeatureSelection::All),
            "none" => Ok(FeatureSelection::None),
            list => {
                let features: Vec<String> = list.split(',').map(|f| f.trim().to_string()).collect();
                if features.iter().any(String::is_empty) {
                    return Err(format!("empty feature name in {s:?}"));
                }
                Ok(FeatureSelection::Only(features))
            }
        }
    }
}

/// The compiled filters of all thread categories, keyed by thread name.
pub type BpfMap = BTreeMap<String, BpfFilter>;

/// First bytes of a compiled filter file, followed by [`BPF_FILTER_FORMAT_VERSION`] as a little
/// endian `u32` and the bitcode serialized [`BpfMap`].
pub const BPF_FILTER_MAGIC: [u8; 4] = *b"FCBF";

/// Version of the compiled filter file format, bumped whenever the layout of [`BpfFilter`] or
/// its serialization changes.
pub const BPF_FILTER_FORMAT_VERSION: u32 = 1;

/// Supported target architectures.
#[derive(Debug)]
pub enum TargetArch {
    X86_64,
    Aarch64,
}

impl TargetArch {
    pub fn to_scmp_type(&self) -> u32 {
        match self {
            TargetArch::X86_64 => SCMP_ARCH_X86_64,
            TargetArch::Aarch64 => SCMP_ARCH_AARCH64,
        }
    }
}

impl FromStr for TargetArch {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "x86_64" => Ok(TargetArch::X86_64),
            "aarch64" => Ok(TargetArch::Aarch64),
            _ => Err(s.to_string()),
        }
    }
}
