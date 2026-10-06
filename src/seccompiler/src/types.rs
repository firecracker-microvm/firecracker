// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, HashSet};
use std::ffi::CString;
use std::fmt;
use std::str::FromStr;

use serde::*;
pub use utils::seccomp::bpf::{BpfPart, SockFilter, compose};
pub use utils::seccomp::{SeccompFeature, SeccompFeatures};

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
    pub features: Option<Vec<SeccompFeature>>,
    /// Free-form documentation of the rule, ignored by the compiler.
    #[serde(default)]
    pub comment: Option<String>,
}

/// Accept a single feature name as well as a list of them.
fn deserialize_features<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<SeccompFeature>>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Features {
        One(String),
        Many(Vec<String>),
    }

    let names = match Features::deserialize(deserializer)? {
        Features::One(feature) => vec![feature],
        Features::Many(features) => features,
    };
    if names.is_empty() || names.iter().any(String::is_empty) {
        return Err(de::Error::custom("empty feature tag"));
    }
    let mut features = names
        .iter()
        .map(|name| name.parse())
        .collect::<Result<Vec<_>, _>>()
        .map_err(de::Error::custom)?;
    features.sort_unstable();
    features.dedup();
    Ok(Some(features))
}

/// Filter containing rules assigned to syscall numbers.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filter {
    pub default_action: SeccompAction,
    pub filter_action: SeccompAction,
    pub filter: Vec<SyscallRule>,
}

/// A JSON policy keyed by thread names, which must be unique ignoring case.
#[derive(Debug)]
pub struct BpfJson(pub BTreeMap<String, Filter>);

impl<'de> Deserialize<'de> for BpfJson {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct FiltersVisitor;

        impl<'de> de::Visitor<'de> for FiltersVisitor {
            type Value = BpfJson;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a map of thread names to seccomp filters")
            }

            fn visit_map<M: de::MapAccess<'de>>(self, mut map: M) -> Result<BpfJson, M::Error> {
                let mut filters = BTreeMap::new();
                let mut names = HashSet::new();
                while let Some(name) = map.next_key::<String>()? {
                    if !names.insert(name.to_lowercase()) {
                        return Err(de::Error::custom(format!("duplicate thread name: {name}")));
                    }
                    filters.insert(name, map.next_value()?);
                }
                Ok(BpfJson(filters))
            }
        }

        deserializer.deserialize_map(FiltersVisitor)
    }
}

/// A compiled filter before conversion to the on-disk sequence of parts.
pub(crate) enum BpfFilter {
    Complete(Vec<SockFilter>),
    Composed {
        base: Vec<SockFilter>,
        fragments: Vec<BpfPart>,
        epilogue: SockFilter,
    },
}

impl BpfFilter {
    pub(crate) fn new(
        mut base: Vec<SockFilter>,
        mut fragments: Vec<BpfPart>,
        default_action: u32,
    ) -> Result<Self, crate::bpf::BpfError> {
        use crate::bpf::{BPF_MAX_LEN, BpfError, epilogue, redirect_default_returns};
        let len = base.len()
            + fragments.iter().map(|part| part.code.len()).sum::<usize>()
            + usize::from(!fragments.is_empty());
        if len > BPF_MAX_LEN {
            return Err(BpfError::TooLong(len));
        }
        if fragments.is_empty() {
            return Ok(Self::Complete(base));
        }
        redirect_default_returns(&mut base, default_action)?;
        for fragment in &mut fragments {
            redirect_default_returns(&mut fragment.code, default_action)?;
        }
        Ok(Self::Composed {
            base,
            fragments,
            epilogue: epilogue(default_action),
        })
    }

    pub(crate) fn into_parts(self) -> Vec<BpfPart> {
        let untagged = |code| BpfPart {
            features: SeccompFeatures::empty(),
            code,
        };
        match self {
            Self::Complete(program) => vec![untagged(program)],
            Self::Composed {
                base,
                fragments,
                epilogue,
            } => {
                let mut parts = Vec::with_capacity(fragments.len() + 2);
                parts.push(untagged(base));
                parts.extend(fragments);
                parts.push(untagged(vec![epilogue]));
                parts
            }
        }
    }
}

/// The compiled filters of all thread categories, keyed by thread name.
pub type BpfMap = BTreeMap<String, Vec<BpfPart>>;

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
