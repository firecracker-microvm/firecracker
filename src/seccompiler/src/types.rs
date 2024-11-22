// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use libseccomp::{ScmpAction, ScmpArch, ScmpCompareOp};
use serde::*;

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

impl SeccompCmpOp {
    pub fn to_scmp_type(&self) -> ScmpCompareOp {
        match self {
            SeccompCmpOp::Eq => ScmpCompareOp::Equal,
            SeccompCmpOp::Ge => ScmpCompareOp::GreaterEqual,
            SeccompCmpOp::Gt => ScmpCompareOp::Greater,
            SeccompCmpOp::Le => ScmpCompareOp::LessOrEqual,
            SeccompCmpOp::Lt => ScmpCompareOp::Less,
            SeccompCmpOp::MaskedEq(me) => ScmpCompareOp::MaskedEqual(*me),
            SeccompCmpOp::Ne => ScmpCompareOp::NotEqual,
        }
    }
}

/// Condition that syscall must match in order to satisfy a rule.
#[derive(Debug, Deserialize)]
pub struct SeccompCondition {
    pub index: u8,
    pub op: SeccompCmpOp,
    pub val: u64,
}

/// Actions that `seccomp` can apply to process calling a syscall.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeccompAction {
    Allow,
    Errno(i32),
    KillThread,
    KillProcess,
    Log,
    Trace(u16),
    Trap,
}

impl SeccompAction {
    pub fn to_scmp_type(&self) -> ScmpAction {
        match self {
            SeccompAction::Allow => ScmpAction::Allow,
            SeccompAction::Errno(e) => ScmpAction::Errno(*e),
            SeccompAction::KillThread => ScmpAction::KillThread,
            SeccompAction::KillProcess => ScmpAction::KillProcess,
            SeccompAction::Log => ScmpAction::Log,
            SeccompAction::Trace(t) => ScmpAction::Trace(*t),
            SeccompAction::Trap => ScmpAction::Trap,
        }
    }
}

/// Rule that `seccomp` attempts to match for a syscall.
///
/// If all conditions match then rule gets matched.
/// The action of the first rule that matches will be applied to the calling process.
/// If no rule matches the default action is applied.
#[derive(Debug, Deserialize)]
pub struct SyscallRule {
    pub syscall: String,
    pub args: Option<Vec<SeccompCondition>>,
}

/// Filter containing rules assigned to syscall numbers.
#[derive(Debug, Deserialize)]
pub struct Filter {
    pub default_action: SeccompAction,
    pub filter_action: SeccompAction,
    pub filter: Vec<SyscallRule>,
}

/// Deserializable object that represents the Json filter file.
#[derive(Debug, Deserialize)]
pub struct BpfJson(pub BTreeMap<String, Filter>);

/// Supported target architectures.
#[derive(Debug)]
pub enum TargetArch {
    X86_64,
    Aarch64,
}

impl TargetArch {
    pub fn to_scmp_type(&self) -> ScmpArch {
        match self {
            TargetArch::X86_64 => ScmpArch::X8664,
            TargetArch::Aarch64 => ScmpArch::Aarch64,
        }
    }
}

impl TryInto<TargetArch> for &str {
    type Error = String;
    fn try_into(self) -> std::result::Result<TargetArch, String> {
        match self.to_lowercase().as_str() {
            "x86_64" => Ok(TargetArch::X86_64),
            "aarch64" => Ok(TargetArch::Aarch64),
            _ => Err(self.to_string()),
        }
    }
}
