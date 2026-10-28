// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::ffi::CString;
use std::str::FromStr;

use serde::*;
pub use utils::seccomp::BpfPart;

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

/// The compiled filter of one thread category.
///
/// Without tagged rules this is a single part holding the libseccomp program of all rules.
/// Otherwise the first part holds the libseccomp program of the untagged rules, every following
/// part but the last the one of the tagged rules sharing a set of features, each with its default
/// returns redirected so that it falls through into the next part, and the last part returns the
/// default action.
pub type BpfFilter = Vec<BpfPart>;

/// The program of `filter` with the untagged parts and the ones tagged with one of `features`.
/// `all` selects every part, and a name no part is tagged with, such as `none`, selects none.
pub fn compose<S: AsRef<str>>(filter: &[BpfPart], features: &[S]) -> Vec<u64> {
    let selected = |part: &BpfPart| {
        part.features.is_empty()
            || features.iter().any(|feature| {
                let feature = feature.as_ref();
                feature == "all" || part.features.iter().any(|tag| tag == feature)
            })
    };
    filter
        .iter()
        .filter(|part| selected(part))
        .flat_map(|part| part.code.iter().copied())
        .collect()
}

/// The compiled filters of all thread categories, keyed by thread name.
pub type BpfMap = BTreeMap<String, BpfFilter>;

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
