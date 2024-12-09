// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeMap, ffi::CString};

// use libseccomp::{ScmpAction, ScmpArch, ScmpCompareOp};
use crate::bindings::*;
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
#[derive(Debug, Deserialize)]
pub struct SyscallRule {
    pub syscall: CString,
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

/// Each BPF instruction is 8 bytes long and 4 byte aligned.
/// This alignment needs to be satisfied in order for a BPF code to be accepted
/// by the syscalls. Using u64 here is is safe as it has same size and even bigger alignment.
pub type BpfInstruction = u64;

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
