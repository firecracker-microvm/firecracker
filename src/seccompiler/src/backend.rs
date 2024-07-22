// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![cfg(target_endian = "little")]
//! This module defines the data structures used for the intermmediate representation (IR),
//! as well as the logic for compiling the filter into BPF code, the final form of the filter.

use std::collections::BTreeMap;
use std::convert::{Into, TryFrom, TryInto};

use serde::{Deserialize, Deserializer};

use crate::common::{sock_filter, BpfProgram, BPF_MAX_LEN};

// BPF Instruction classes.
// See /usr/include/linux/bpf_common.h .
const BPF_LD: u16 = 0x00;
const BPF_ALU: u16 = 0x04;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;

// BPF ld/ldx fields.
// See /usr/include/linux/bpf_common.h .
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;

// BPF alu fields.
// See /usr/include/linux/bpf_common.h .
const BPF_AND: u16 = 0x50;

// BPF jmp fields.
// See /usr/include/linux/bpf_common.h .
const BPF_JA: u16 = 0x00;
const BPF_JEQ: u16 = 0x10;
const BPF_JGT: u16 = 0x20;
const BPF_JGE: u16 = 0x30;
const BPF_K: u16 = 0x00;

// Return codes for BPF programs.
// See /usr/include/linux/seccomp.h .
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_KILL_THREAD: u32 = 0x0000_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_LOG: u32 = 0x7ffc_0000;
const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
const SECCOMP_RET_MASK: u32 = 0x0000_ffff;

// Architecture identifier.
// See /usr/include/linux/audit.h .

// Defined as:
// `#define AUDIT_ARCH_X86_64	(EM_X86_64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)`
const AUDIT_ARCH_X86_64: u32 = 62 | 0x8000_0000 | 0x4000_0000;

// Defined as:
// `#define AUDIT_ARCH_AARCH64	(EM_AARCH64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)`
const AUDIT_ARCH_AARCH64: u32 = 183 | 0x8000_0000 | 0x4000_0000;

// The maximum number of a syscall argument.
// A syscall can have at most 6 arguments.
// Arguments are numbered from 0 to 5.
const ARG_NUMBER_MAX: u8 = 5;

// The maximum number of BPF statements that a condition will be translated into.
const CONDITION_MAX_LEN: u8 = 6;

// `struct seccomp_data` offsets and sizes of fields in bytes:
//
// ```c
// struct seccomp_data {
//     int nr;
//     __u32 arch;
//     __u64 instruction_pointer;
//     __u64 args[6];
// };
// ```
const SECCOMP_DATA_NR_OFFSET: u8 = 0;
const SECCOMP_DATA_ARGS_OFFSET: u8 = 16;
const SECCOMP_DATA_ARG_SIZE: u8 = 8;

/// Dummy placeholder type for a JSON comment. Holds no value.
#[derive(PartialEq, Debug, Clone)]
pub struct Comment;

impl<'de> Deserialize<'de> for Comment {
    fn deserialize<D>(_deserializer: D) -> std::result::Result<Comment, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(_deserializer)?;

        Ok(Comment {})
    }
}

/// Seccomp filter errors.
#[derive(Debug, PartialEq, thiserror::Error, displaydoc::Display)]
pub enum FilterError {
    /// The seccomp rules vector is empty.
    EmptyRulesVector,
    /// The seccomp filter contains too many BPF instructions.
    FilterTooLarge,
    /// The seccomp rule contains an invalid argument number.
    InvalidArgumentNumber,
    /// {0}
    Arch(TargetArchError),
    /// Syscall {0} has conflicting rules.
    ConflictingRules(i64),
}

/// Supported target architectures.
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum TargetArch {
    /// x86_64 arch
    x86_64,
    /// aarch64 arch
    aarch64,
}

/// Errors related to target arch.
#[derive(Debug, PartialEq, thiserror::Error, displaydoc::Display)]
pub enum TargetArchError {
    /// Invalid target arch string: {0}
    InvalidString(String),
}

impl TargetArch {
    /// Get the arch audit value.
    fn get_audit_value(self) -> u32 {
        match self {
            TargetArch::x86_64 => AUDIT_ARCH_X86_64,
            TargetArch::aarch64 => AUDIT_ARCH_AARCH64,
        }
    }

    /// Get the string representation.
    fn to_string(self) -> &'static str {
        match self {
            TargetArch::x86_64 => "x86_64",
            TargetArch::aarch64 => "aarch64",
        }
    }
}

impl TryInto<TargetArch> for &str {
    type Error = TargetArchError;
    fn try_into(self) -> std::result::Result<TargetArch, TargetArchError> {
        match self.to_lowercase().as_str() {
            "x86_64" => Ok(TargetArch::x86_64),
            "aarch64" => Ok(TargetArch::aarch64),
            _ => Err(TargetArchError::InvalidString(self.to_string())),
        }
    }
}

impl From<TargetArch> for &str {
    fn from(target_arch: TargetArch) -> Self {
        target_arch.to_string()
    }
}

/// Comparison to perform when matching a condition.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SeccompCmpOp {
    /// Argument value is equal to the specified value.
    Eq,
    /// Argument value is greater than or equal to the specified value.
    Ge,
    /// Argument value is greater than specified value.
    Gt,
    /// Argument value is less than or equal to the specified value.
    Le,
    /// Argument value is less than specified value.
    Lt,
    /// Masked bits of argument value are equal to masked bits of specified value.
    MaskedEq(u64),
    /// Argument value is not equal to specified value.
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
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeccompCondition {
    /// Index of the argument that is to be compared.
    #[serde(rename = "index")]
    arg_number: u8,
    /// Length of the argument value that is to be compared.
    #[serde(rename = "type")]
    arg_len: SeccompCmpArgLen,
    /// Comparison to perform.
    #[serde(rename = "op")]
    operator: SeccompCmpOp,
    /// The value that will be compared with the argument value.
    #[serde(rename = "val")]
    value: u64,
    /// Optional empty value, represents a `comment` property in the JSON file.
    comment: Option<Comment>,
}

/// Actions that `seccomp` can apply to process calling a syscall.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeccompAction {
    /// Allows syscall.
    Allow,
    /// Returns from syscall with specified error number.
    Errno(u32),
    /// Kills calling thread.
    KillThread,
    /// Kills calling process.
    KillProcess,
    /// Same as allow but logs call.
    Log,
    /// Notifies tracing process of the caller with respective number.
    Trace(u32),
    /// Sends `SIGSYS` to the calling process.
    Trap,
}

/// Rule that `seccomp` attempts to match for a syscall.
///
/// If all conditions match then rule gets matched.
/// The action of the first rule that matches will be applied to the calling process.
/// If no rule matches the default action is applied.
#[derive(Clone, Debug, PartialEq)]
pub struct SeccompRule {
    /// Conditions of rule that need to match in order for the rule to get matched.
    conditions: Vec<SeccompCondition>,
    /// Action applied to calling process if rule gets matched.
    action: SeccompAction,
}

/// Type that associates the syscall number to its SeccompRules.
pub type SeccompRuleMap = BTreeMap<i64, Vec<SeccompRule>>;

/// Filter containing rules assigned to syscall numbers.
#[derive(Clone, Debug, PartialEq)]
pub struct SeccompFilter {
    /// Map of syscall numbers and corresponding rule chains.
    rules: SeccompRuleMap,
    /// Default action to apply to syscall numbers that do not exist in the hash map.
    default_action: SeccompAction,
    /// Target architecture of the generated BPF filter.
    target_arch: TargetArch,
}

impl SeccompCondition {
    /// Validates the SeccompCondition data
    pub fn validate(&self) -> Result<(), FilterError> {
        // Checks that the given argument number is valid.
        if self.arg_number > ARG_NUMBER_MAX {
            return Err(FilterError::InvalidArgumentNumber);
        }

        Ok(())
    }

    /// Splits the [`SeccompCondition`] into 32 bit chunks and offsets.
    ///
    /// Returns most significant half, least significant half of the `value` field of
    /// [`SeccompCondition`], as well as the offsets of the most significant and least significant
    /// half of the argument specified by `arg_number` relative to `struct seccomp_data` passed to
    /// the BPF program by the kernel.
    ///
    /// [`SeccompCondition`]: struct.SeccompCondition.html
    fn value_segments(&self) -> (u32, u32, u8, u8) {
        // Splits the specified value into its most significant and least significant halves.
        let (msb, lsb) = ((self.value >> 32) as u32, (self.value & 0xFFFFFFFF) as u32);

        // Offset to the argument specified by `arg_number`.
        // Cannot overflow because the value will be at most 16 + 6 * 8 = 64.
        let arg_offset = SECCOMP_DATA_ARGS_OFFSET + self.arg_number * SECCOMP_DATA_ARG_SIZE;

        // Extracts offsets of most significant and least significant halves of argument.
        // Addition cannot overflow because it's at most `arg_offset` + 4 = 68.
        let (msb_offset, lsb_offset) = { (arg_offset + SECCOMP_DATA_ARG_SIZE / 2, arg_offset) };

        (msb, lsb, msb_offset, lsb_offset)
    }

    /// Translates the `eq` (equal) condition into BPF statements.
    ///
    /// # Arguments
    ///
    /// * `offset` - The given jump offset to the start of the next rule.
    ///
    /// The jump is performed if the condition fails and thus the current rule does not match so
    /// `seccomp` tries to match the next rule by jumping out of the current rule.
    ///
    /// In case the condition is part of the last rule, the jump offset is to the default action of
    /// respective filter.
    ///
    /// The most significant and least significant halves of the argument value are compared
    /// separately since the BPF operand and accumulator are 4 bytes whereas an argument value is 8.
    fn into_eq_bpf(self, offset: u8) -> Vec<sock_filter> {
        let (msb, lsb, msb_offset, lsb_offset) = self.value_segments();

        let mut bpf = match self.arg_len {
            SeccompCmpArgLen::Dword => vec![],
            SeccompCmpArgLen::Qword => vec![
                BPF_STMT(BPF_LD + BPF_W + BPF_ABS, u32::from(msb_offset)),
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, msb, 0, offset + 2),
            ],
        };

        bpf.append(&mut vec![
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, u32::from(lsb_offset)),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, lsb, 0, offset),
        ]);
        bpf
    }

    /// Translates the `ge` (greater than or equal) condition into BPF statements.
    ///
    /// # Arguments
    ///
    /// * `offset` - The given jump offset to the start of the next rule.
    fn into_ge_bpf(self, offset: u8) -> Vec<sock_filter> {
        let (msb, lsb, msb_offset, lsb_offset) = self.value_segments();

        let mut bpf = match self.arg_len {
            SeccompCmpArgLen::Dword => vec![],
            SeccompCmpArgLen::Qword => vec![
                BPF_STMT(BPF_LD + BPF_W + BPF_ABS, u32::from(msb_offset)),
                BPF_JUMP(BPF_JMP + BPF_JGT + BPF_K, msb, 3, 0),
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, msb, 0, offset + 2),
            ],
        };

        bpf.append(&mut vec![
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, u32::from(lsb_offset)),
            BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, lsb, 0, offset),
        ]);
        bpf
    }

    /// Translates the `gt` (greater than) condition into BPF statements.
    ///
    /// # Arguments
    ///
    /// * `offset` - The given jump offset to the start of the next rule.
    fn into_gt_bpf(self, offset: u8) -> Vec<sock_filter> {
        let (msb, lsb, msb_offset, lsb_offset) = self.value_segments();

        let mut bpf = match self.arg_len {
            SeccompCmpArgLen::Dword => vec![],
            SeccompCmpArgLen::Qword => vec![
                BPF_STMT(BPF_LD + BPF_W + BPF_ABS, u32::from(msb_offset)),
                BPF_JUMP(BPF_JMP + BPF_JGT + BPF_K, msb, 3, 0),
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, msb, 0, offset + 2),
            ],
        };

        bpf.append(&mut vec![
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, u32::from(lsb_offset)),
            BPF_JUMP(BPF_JMP + BPF_JGT + BPF_K, lsb, 0, offset),
        ]);
        bpf
    }

    /// Translates the `le` (less than or equal) condition into BPF statements.
    ///
    /// # Arguments
    ///
    /// * `offset` - The given jump offset to the start of the next rule.
    fn into_le_bpf(self, offset: u8) -> Vec<sock_filter> {
        let (msb, lsb, msb_offset, lsb_offset) = self.value_segments();

        let mut bpf = match self.arg_len {
            SeccompCmpArgLen::Dword => vec![],
            SeccompCmpArgLen::Qword => vec![
                BPF_STMT(BPF_LD + BPF_W + BPF_ABS, u32::from(msb_offset)),
                BPF_JUMP(BPF_JMP + BPF_JGT + BPF_K, msb, offset + 3, 0),
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, msb, 0, 2),
            ],
        };

        bpf.append(&mut vec![
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, u32::from(lsb_offset)),
            BPF_JUMP(BPF_JMP + BPF_JGT + BPF_K, lsb, offset, 0),
        ]);
        bpf
    }

    /// Translates the `lt` (less than) condition into BPF statements.
    ///
    /// # Arguments
    ///
    /// * `offset` - The given jump offset to the start of the next rule.
    fn into_lt_bpf(self, offset: u8) -> Vec<sock_filter> {
        let (msb, lsb, msb_offset, lsb_offset) = self.value_segments();

        let mut bpf = match self.arg_len {
            SeccompCmpArgLen::Dword => vec![],
            SeccompCmpArgLen::Qword => vec![
                BPF_STMT(BPF_LD + BPF_W + BPF_ABS, u32::from(msb_offset)),
                BPF_JUMP(BPF_JMP + BPF_JGT + BPF_K, msb, offset + 3, 0),
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, msb, 0, 2),
            ],
        };

        bpf.append(&mut vec![
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, u32::from(lsb_offset)),
            BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, lsb, offset, 0),
        ]);
        bpf
    }

    /// Translates the `masked_eq` (masked equal) condition into BPF statements.
    ///
    /// The `masked_eq` condition is `true` if the result of logical `AND` between the given value
    /// and the mask is the value being compared against.
    ///
    /// # Arguments
    ///
    /// * `offset` - The given jump offset to the start of the next rule.
    fn into_masked_eq_bpf(self, offset: u8, mask: u64) -> Vec<sock_filter> {
        let (_, _, msb_offset, lsb_offset) = self.value_segments();
        let masked_value = self.value & mask;
        let (msb, lsb) = (
            (masked_value >> 32) as u32,
            (masked_value & 0xFFFFFFFF) as u32,
        );
        let (mask_msb, mask_lsb) = ((mask >> 32) as u32, (mask & 0xFFFFFFFF) as u32);

        let mut bpf = match self.arg_len {
            SeccompCmpArgLen::Dword => vec![],
            SeccompCmpArgLen::Qword => vec![
                BPF_STMT(BPF_LD + BPF_W + BPF_ABS, u32::from(msb_offset)),
                BPF_STMT(BPF_ALU + BPF_AND + BPF_K, mask_msb),
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, msb, 0, offset + 3),
            ],
        };

        bpf.append(&mut vec![
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, u32::from(lsb_offset)),
            BPF_STMT(BPF_ALU + BPF_AND + BPF_K, mask_lsb),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, lsb, 0, offset),
        ]);
        bpf
    }

    /// Translates the `ne` (not equal) condition into BPF statements.
    ///
    /// # Arguments
    ///
    /// * `offset` - The given jump offset to the start of the next rule.
    fn into_ne_bpf(self, offset: u8) -> Vec<sock_filter> {
        let (msb, lsb, msb_offset, lsb_offset) = self.value_segments();

        let mut bpf = match self.arg_len {
            SeccompCmpArgLen::Dword => vec![],
            SeccompCmpArgLen::Qword => vec![
                BPF_STMT(BPF_LD + BPF_W + BPF_ABS, u32::from(msb_offset)),
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, msb, 0, 2),
            ],
        };

        bpf.append(&mut vec![
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, u32::from(lsb_offset)),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, lsb, offset, 0),
        ]);
        bpf
    }

    /// Translates the [`SeccompCondition`] into BPF statements.
    ///
    /// # Arguments
    ///
    /// * `offset` - The given jump offset to the start of the next rule.
    ///
    /// [`SeccompCondition`]: struct.SeccompCondition.html
    fn into_bpf(self, offset: u8) -> Vec<sock_filter> {
        let result = match self.operator {
            SeccompCmpOp::Eq => self.into_eq_bpf(offset),
            SeccompCmpOp::Ge => self.into_ge_bpf(offset),
            SeccompCmpOp::Gt => self.into_gt_bpf(offset),
            SeccompCmpOp::Le => self.into_le_bpf(offset),
            SeccompCmpOp::Lt => self.into_lt_bpf(offset),
            SeccompCmpOp::MaskedEq(mask) => self.into_masked_eq_bpf(offset, mask),
            SeccompCmpOp::Ne => self.into_ne_bpf(offset),
        };

        // Verifies that the `CONDITION_MAX_LEN` constant was properly updated.
        assert!(result.len() <= CONDITION_MAX_LEN as usize);

        result
    }
}

impl From<SeccompAction> for u32 {
    /// Return codes of the BPF program for each action.
    ///
    /// # Arguments
    ///
    /// * `action` - The [`SeccompAction`] that the kernel will take.
    ///
    /// [`SeccompAction`]: struct.SeccompAction.html
    fn from(action: SeccompAction) -> Self {
        match action {
            SeccompAction::Allow => SECCOMP_RET_ALLOW,
            SeccompAction::Errno(x) => SECCOMP_RET_ERRNO | (x & SECCOMP_RET_MASK),
            SeccompAction::KillThread => SECCOMP_RET_KILL_THREAD,
            SeccompAction::KillProcess => SECCOMP_RET_KILL_PROCESS,
            SeccompAction::Log => SECCOMP_RET_LOG,
            SeccompAction::Trace(x) => SECCOMP_RET_TRACE | (x & SECCOMP_RET_MASK),
            SeccompAction::Trap => SECCOMP_RET_TRAP,
        }
    }
}

impl SeccompRule {
    /// Creates a new rule. Rules with 0 conditions always match.
    ///
    /// # Arguments
    ///
    /// * `conditions` - Vector of [`SeccompCondition`] that the syscall must match.
    /// * `action` - Action taken if the syscall matches the conditions. See [`SeccompAction`].
    ///
    /// [`SeccompCondition`]: struct.SeccompCondition.html
    /// [`SeccompAction`]: struct.SeccompAction.html
    pub fn new(conditions: Vec<SeccompCondition>, action: SeccompAction) -> Self {
        Self { conditions, action }
    }

    /// Appends a condition of the rule to an accumulator.
    ///
    /// The length of the rule and offset to the next rule are updated.
    ///
    /// # Arguments
    ///
    /// * `condition` - The condition added to the rule.
    /// * `accumulator` - Accumulator of BPF statements that compose the BPF program.
    /// * `rule_len` - Number of conditions in the rule.
    /// * `offset` - Offset (in number of BPF statements) to the next rule.
    fn append_condition(
        condition: SeccompCondition,
        accumulator: &mut Vec<Vec<sock_filter>>,
        rule_len: &mut usize,
        offset: &mut u8,
    ) {
        // Tries to detect whether prepending the current condition will produce an unjumpable
        // offset (since BPF jumps are a maximum of 255 instructions, which is u8::MAX).
        if offset.checked_add(CONDITION_MAX_LEN + 1).is_none() {
            // If that is the case, three additional helper jumps are prepended and the offset
            // is reset to 1.
            //
            // - The first jump continues the evaluation of the condition chain by jumping to the
            //   next condition or the action of the rule if the last condition was matched.
            // - The second, jumps out of the rule, to the next rule or the default action of the
            //   filter in case of the last rule in the rule chain of a syscall.
            // - The third jumps out of the rule chain of the syscall, to the rule chain of the next
            //   syscall number to be checked or the default action of the filter in the case of the
            //   last rule chain.
            let helper_jumps = vec![
                BPF_STMT(BPF_JMP + BPF_JA, 2),
                BPF_STMT(BPF_JMP + BPF_JA, u32::from(*offset) + 1),
                BPF_STMT(BPF_JMP + BPF_JA, u32::from(*offset) + 1),
            ];
            *rule_len += helper_jumps.len();
            accumulator.push(helper_jumps);
            *offset = 1;
        }

        let condition = condition.into_bpf(*offset);
        *rule_len += condition.len();
        // Safe to unwrap since we checked that condition length is less than `CONDITION_MAX_LEN`.
        *offset += u8::try_from(condition.len()).unwrap();
        accumulator.push(condition);
    }
}

impl From<SeccompRule> for BpfProgram {
    /// Translates a rule into BPF statements.
    ///
    /// Each rule starts with 2 jump statements:
    /// * The first jump enters the rule, attempting a match.
    /// * The second jump points to the end of the rule chain for one syscall, into the rule chain
    ///   for the next syscall or the default action if the current syscall is the last one. It
    ///   essentially jumps out of the current rule chain.
    fn from(rule: SeccompRule) -> Self {
        // Rule is built backwards, last statement is the action of the rule.
        // The offset to the next rule is 1.
        let mut accumulator =
            Vec::with_capacity(rule.conditions.len() * CONDITION_MAX_LEN as usize);
        let mut rule_len = 1;
        let mut offset = 1;
        accumulator.push(vec![BPF_STMT(BPF_RET + BPF_K, u32::from(rule.action))]);

        // Conditions are translated into BPF statements and prepended to the rule.
        rule.conditions.into_iter().for_each(|condition| {
            SeccompRule::append_condition(condition, &mut accumulator, &mut rule_len, &mut offset)
        });

        // The two initial jump statements are prepended to the rule.
        let rule_jumps = vec![
            BPF_STMT(BPF_JMP + BPF_JA, 1),
            BPF_STMT(BPF_JMP + BPF_JA, u32::from(offset) + 1),
        ];
        rule_len += rule_jumps.len();
        accumulator.push(rule_jumps);

        // Finally, builds the translated rule by consuming the accumulator.
        let mut result = Vec::with_capacity(rule_len);
        accumulator
            .into_iter()
            .rev()
            .for_each(|mut instructions| result.append(&mut instructions));

        result
    }
}

impl SeccompFilter {
    /// Creates a new filter with a set of rules and a default action.
    ///
    /// # Arguments
    ///
    /// * `rules` - Map of syscall numbers and the rules that will be applied to each of them.
    /// * `default_action` - Action taken for all syscalls that do not match any rule.
    /// * `target_arch` - Target architecture of the generated BPF filter.
    pub fn new(
        rules: SeccompRuleMap,
        default_action: SeccompAction,
        target_arch: &str,
    ) -> Result<Self, FilterError> {
        let instance = Self {
            rules,
            default_action,
            target_arch: target_arch.try_into().map_err(FilterError::Arch)?,
        };

        instance.validate()?;

        Ok(instance)
    }

    /// Performs semantic checks on the SeccompFilter.
    fn validate(&self) -> Result<(), FilterError> {
        for (syscall_number, syscall_rules) in self.rules.iter() {
            // All inserted syscalls must have at least one rule, otherwise BPF code will break.
            if syscall_rules.is_empty() {
                return Err(FilterError::EmptyRulesVector);
            }

            // Now check for conflicting rules.
            // Match on the number of empty rules for the given syscall.
            // An `empty rule` is a rule that doesn't have any argument checks.
            match syscall_rules
                .iter()
                .filter(|rule| rule.conditions.is_empty())
                .count()
            {
                // If the syscall has an empty rule, it may only have that rule.
                1 if syscall_rules.len() > 1 => {
                    return Err(FilterError::ConflictingRules(*syscall_number));
                }
                // This syscall only has the one rule, so is valid.
                1 if syscall_rules.len() <= 1 => {}
                // The syscall has no empty rules.
                0 => {}
                // For a greater than 1 number of empty rules, error out.
                _ => {
                    return Err(FilterError::ConflictingRules(*syscall_number));
                }
            }
        }

        Ok(())
    }

    /// Appends a chain of rules to an accumulator, updating the length of the filter.
    ///
    /// # Arguments
    ///
    /// * `syscall_number` - The syscall to which the rules apply.
    /// * `chain` - The chain of rules for the specified syscall.
    /// * `default_action` - The action to be taken in none of the rules apply.
    /// * `accumulator` - The expanding BPF program.
    /// * `filter_len` - The size (in number of BPF statements) of the BPF program. This is limited
    ///   to 4096. If the limit is exceeded, the filter is invalidated.
    fn append_syscall_chain(
        syscall_number: i64,
        chain: Vec<SeccompRule>,
        default_action: u32,
        accumulator: &mut Vec<Vec<sock_filter>>,
        filter_len: &mut usize,
    ) -> Result<(), FilterError> {
        // The rules of the chain are translated into BPF statements.
        let chain: Vec<_> = chain.into_iter().map(SeccompRule::into).collect();
        let chain_len: usize = chain.iter().map(std::vec::Vec::len).sum();

        // The chain starts with a comparison checking the loaded syscall number against the
        // syscall number of the chain.
        let mut built_syscall = Vec::with_capacity(1 + chain_len + 1);
        built_syscall.push(BPF_JUMP(
            BPF_JMP + BPF_JEQ + BPF_K,
            u32::try_from(syscall_number).unwrap(),
            0,
            1,
        ));

        // The rules of the chain are appended.
        chain
            .into_iter()
            .for_each(|mut rule| built_syscall.append(&mut rule));

        // The default action is appended, if the syscall number comparison matched and then all
        // rules fail to match, the default action is reached.
        built_syscall.push(BPF_STMT(BPF_RET + BPF_K, default_action));

        // The chain is appended to the result.
        *filter_len += built_syscall.len();
        accumulator.push(built_syscall);

        // BPF programs are limited to 4096 statements.
        if *filter_len >= usize::from(BPF_MAX_LEN) {
            return Err(FilterError::FilterTooLarge);
        }

        Ok(())
    }
}

impl TryInto<BpfProgram> for SeccompFilter {
    type Error = FilterError;
    fn try_into(self) -> Result<BpfProgram, FilterError> {
        // Initialize the result with the precursory architecture check.
        let mut result = VALIDATE_ARCHITECTURE(self.target_arch);

        // If no rules are set up, the filter will always return the default action,
        // so let's short-circuit the function.
        if self.rules.is_empty() {
            result.extend(vec![BPF_STMT(
                BPF_RET + BPF_K,
                u32::from(self.default_action),
            )]);

            return Ok(result);
        }

        // The called syscall number is loaded.
        let mut accumulator = Vec::with_capacity(1);
        let mut filter_len = 1;
        accumulator.push(EXAMINE_SYSCALL());

        // Orders syscalls by priority, the highest number represents the highest priority.
        let mut iter = self.rules.into_iter();

        // For each syscall adds its rule chain to the filter.
        let default_action = u32::from(self.default_action);
        iter.try_for_each(|(syscall_number, chain)| {
            SeccompFilter::append_syscall_chain(
                syscall_number,
                chain,
                default_action,
                &mut accumulator,
                &mut filter_len,
            )
        })?;

        // The default action is once again appended, it is reached if all syscall number
        // comparisons fail.
        filter_len += 1;
        accumulator.push(vec![BPF_STMT(BPF_RET + BPF_K, default_action)]);

        // Finally, builds the translated filter by consuming the accumulator.
        result.reserve(filter_len);
        accumulator
            .into_iter()
            .for_each(|mut instructions| result.append(&mut instructions));

        if result.len() >= usize::from(BPF_MAX_LEN) {
            return Err(FilterError::FilterTooLarge);
        }

        Ok(result)
    }
}

/// Builds a `jump` BPF instruction.
///
/// # Arguments
///
/// * `code` - The operation code.
/// * `jt` - The jump offset in case the operation returns `true`.
/// * `jf` - The jump offset in case the operation returns `false`.
/// * `k` - The operand.
#[allow(non_snake_case)]
#[inline(always)]
fn BPF_JUMP(code: u16, k: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter { code, jt, jf, k }
}

/// Builds a "statement" BPF instruction.
///
/// # Arguments
///
/// * `code` - The operation code.
/// * `k` - The operand.
#[allow(non_snake_case)]
#[inline(always)]
fn BPF_STMT(code: u16, k: u32) -> sock_filter {
    sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

/// Builds a sequence of BPF instructions that validate the underlying architecture.
#[allow(non_snake_case)]
#[inline(always)]
fn VALIDATE_ARCHITECTURE(target_arch: TargetArch) -> Vec<sock_filter> {
    let audit_arch_value = target_arch.get_audit_value();
    vec![
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 4),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, audit_arch_value, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL_PROCESS),
    ]
}

/// Builds a sequence of BPF instructions that are followed by syscall examination.
#[allow(non_snake_case)]
#[inline(always)]
fn EXAMINE_SYSCALL() -> Vec<sock_filter> {
    vec![BPF_STMT(
        BPF_LD + BPF_W + BPF_ABS,
        u32::from(SECCOMP_DATA_NR_OFFSET),
    )]
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
    use std::env::consts::ARCH;
    use std::thread;

    use super::SeccompCmpOp::*;
    use super::{SeccompCmpArgLen as ArgLen, SeccompCondition as Cond, *};

    // BPF structure definition for filter array.
    // See /usr/include/linux/filter.h .
    #[repr(C)]
    struct sock_fprog {
        pub len: ::std::os::raw::c_ushort,
        pub filter: *const sock_filter,
    }

    // Builds the (syscall, rules) tuple for allowing a syscall with certain arguments.
    fn allow_syscall_if(syscall_number: i64, rules: Vec<SeccompRule>) -> (i64, Vec<SeccompRule>) {
        (syscall_number, rules)
    }

    impl SeccompCondition {
        // Creates a new `SeccompCondition`.
        pub fn new(
            arg_number: u8,
            arg_len: SeccompCmpArgLen,
            operator: SeccompCmpOp,
            value: u64,
        ) -> Result<Self, FilterError> {
            let instance = Self {
                arg_number,
                arg_len,
                operator,
                value,
                comment: None,
            };

            instance.validate().map(|_| Ok(instance))?
        }
    }

    // The type of the `req` parameter is different for the `musl` library. This will enable
    // successful build for other non-musl libraries.
    #[cfg(target_env = "musl")]
    type IoctlRequest = i32;
    #[cfg(not(target_env = "musl"))]
    type IoctlRequest = u64;

    // We use KVM_GET_PIT2 as the second parameter for ioctl syscalls in some unit tests
    // because it's a corner case. More details
    // [here](https://github.com/firecracker-microvm/firecracker/issues/1206)
    const KVM_GET_PIT2: u64 = 0x8070_ae9f;
    const KVM_GET_PIT2_MSB: u64 = 0x0000_ae9f;
    const KVM_GET_PIT2_LSB: u64 = 0x8070_0000;

    const EXTRA_SYSCALLS: [i64; 6] = [
        libc::SYS_rt_sigprocmask,
        libc::SYS_sigaltstack,
        libc::SYS_munmap,
        libc::SYS_exit,
        libc::SYS_rt_sigreturn,
        libc::SYS_futex,
    ];

    fn install_filter(bpf_filter: BpfProgram) {
        unsafe {
            {
                let rc = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                assert_eq!(rc, 0);
            }
            let bpf_prog = sock_fprog {
                len: u16::try_from(bpf_filter.len()).unwrap(),
                filter: bpf_filter.as_ptr(),
            };
            let bpf_prog_ptr = &bpf_prog as *const sock_fprog;
            {
                let rc = libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER,
                    bpf_prog_ptr,
                );
                assert_eq!(rc, 0);
            }
        }
    }

    fn validate_seccomp_filter(
        rules: Vec<(i64, Vec<SeccompRule>)>,
        validation_fn: fn(),
        should_fail: bool,
    ) {
        let failure_code: i32 = 1000;

        let mut rule_map: SeccompRuleMap = rules.into_iter().collect();

        for syscall in EXTRA_SYSCALLS.iter() {
            rule_map
                .entry(*syscall)
                .or_default()
                .append(&mut vec![SeccompRule::new(vec![], SeccompAction::Allow)]);
        }

        // Build seccomp filter.
        let filter = SeccompFilter::new(
            rule_map,
            SeccompAction::Errno(u32::try_from(failure_code).unwrap()),
            ARCH,
        )
        .unwrap();

        // We need to run the validation inside another thread in order to avoid setting
        // the seccomp filter for the entire unit tests process.
        let errno = thread::spawn(move || {
            // Install the filter.
            install_filter(filter.try_into().unwrap());

            // Call the validation fn.
            validation_fn();

            // Return errno.
            std::io::Error::last_os_error().raw_os_error().unwrap()
        })
        .join()
        .unwrap();

        // In case of a seccomp denial `errno` should be `failure_code`
        if should_fail {
            assert_eq!(errno, failure_code);
        } else {
            assert_ne!(errno, failure_code);
        }
    }

    #[test]
    fn test_eq_operator() {
        // check use cases for SeccompCmpArgLen::DWORD
        let rules = vec![allow_syscall_if(
            libc::SYS_ioctl,
            vec![SeccompRule::new(
                vec![Cond::new(1, SeccompCmpArgLen::Dword, Eq, KVM_GET_PIT2).unwrap()],
                SeccompAction::Allow,
            )],
        )];
        // check syscalls that are supposed to work
        validate_seccomp_filter(
            rules.clone(),
            || unsafe {
                libc::ioctl(0, KVM_GET_PIT2 as IoctlRequest);
            },
            false,
        );
        // check syscalls that are not supposed to work
        validate_seccomp_filter(
            rules,
            || unsafe {
                libc::ioctl(0, 0);
            },
            true,
        );

        // check use cases for SeccompCmpArgLen::QWORD
        let rules = vec![allow_syscall_if(
            libc::SYS_ioctl,
            vec![SeccompRule::new(
                vec![Cond::new(2, SeccompCmpArgLen::Qword, Eq, u64::MAX).unwrap()],
                SeccompAction::Allow,
            )],
        )];
        // check syscalls that are supposed to work
        validate_seccomp_filter(
            rules.clone(),
            || unsafe {
                libc::ioctl(0, 0, u64::MAX);
            },
            false,
        );
        // check syscalls that are not supposed to work
        validate_seccomp_filter(
            rules,
            || unsafe {
                libc::ioctl(0, 0, 0);
            },
            true,
        );
    }

    #[test]
    fn test_ge_operator() {
        // check use case for SeccompCmpArgLen::DWORD
        let rules = vec![allow_syscall_if(
            libc::SYS_ioctl,
            vec![SeccompRule::new(
                vec![Cond::new(1, SeccompCmpArgLen::Dword, Ge, KVM_GET_PIT2).unwrap()],
                SeccompAction::Allow,
            )],
        )];
        // check syscalls that are supposed to work
        validate_seccomp_filter(
            rules.clone(),
            || unsafe {
                libc::ioctl(0, KVM_GET_PIT2 as IoctlRequest);
                libc::ioctl(0, (KVM_GET_PIT2 + 1) as IoctlRequest);
            },
            false,
        );
        // check syscalls that are not supposed to work
        validate_seccomp_filter(
            rules,
            || unsafe {
                libc::ioctl(0, (KVM_GET_PIT2 - 1) as IoctlRequest);
            },
            true,
        );

        // check use case for SeccompCmpArgLen::QWORD
        let rules = vec![allow_syscall_if(
            libc::SYS_ioctl,
            vec![SeccompRule::new(
                vec![Cond::new(2, SeccompCmpArgLen::Qword, Ge, u64::from(u32::MAX)).unwrap()],
                SeccompAction::Allow,
            )],
        )];
        // check syscalls that are supposed to work
        validate_seccomp_filter(
            rules.clone(),
            || unsafe {
                libc::ioctl(0, 0, u64::from(u32::MAX));
                libc::ioctl(0, 0, u64::from(u32::MAX) + 1);
            },
            false,
        );
        // check syscalls that are not supposed to work
        validate_seccomp_filter(
            rules,
            || unsafe {
                libc::ioctl(0, 0, 1);
            },
            true,
        );
    }

    #[test]
    fn test_gt_operator() {
        // check use case for SeccompCmpArgLen::DWORD
        let rules = vec![allow_syscall_if(
            libc::SYS_ioctl,
            vec![SeccompRule::new(
                vec![Cond::new(1, SeccompCmpArgLen::Dword, Gt, KVM_GET_PIT2).unwrap()],
                SeccompAction::Allow,
            )],
        )];
        // check syscalls that are supposed to work
        validate_seccomp_filter(
            rules.clone(),
            || unsafe {
                libc::ioctl(0, (KVM_GET_PIT2 + 1) as IoctlRequest);
            },
            false,
        );
        // check syscalls that are not supposed to work
        validate_seccomp_filter(
            rules,
            || unsafe {
                libc::ioctl(0, KVM_GET_PIT2 as IoctlRequest);
            },
            true,
        );

        // check use case for SeccompCmpArgLen::QWORD
        let rules = vec![allow_syscall_if(
            libc::SYS_ioctl,
            vec![SeccompRule::new(
                vec![Cond::new(2, SeccompCmpArgLen::Qword, Gt, u64::from(u32::MAX) + 10).unwrap()],
                SeccompAction::Allow,
            )],
        )];
        // check syscalls that are supposed to work
        validate_seccomp_filter(
            rules.clone(),
            || unsafe {
                libc::ioctl(0, 0, u64::from(u32::MAX) + 11);
            },
            false,
        );
        // check syscalls that are not supposed to work
        validate_seccomp_filter(
            rules,
            || unsafe {
                libc::ioctl(0, 0, u64::from(u32::MAX) + 10);
            },
            true,
        );
    }

    #[test]
    fn test_le_operator() {
        // check use case for SeccompCmpArgLen::DWORD
        let rules = vec![allow_syscall_if(
            libc::SYS_ioctl,
            vec![SeccompRule::new(
                vec![Cond::new(1, SeccompCmpArgLen::Dword, Le, KVM_GET_PIT2).unwrap()],
                SeccompAction::Allow,
            )],
        )];
        // check syscalls that are supposed to work
        validate_seccomp_filter(
            rules.clone(),
            || unsafe {
                libc::ioctl(0, KVM_GET_PIT2 as IoctlRequest);
                libc::ioctl(0, (KVM_GET_PIT2 - 1) as IoctlRequest);
            },
            false,
        );
        // check syscalls that are not supposed to work
        validate_seccomp_filter(
            rules,
            || unsafe {
                libc::ioctl(0, (KVM_GET_PIT2 + 1) as IoctlRequest);
            },
            true,
        );

        // check use case for SeccompCmpArgLen::QWORD
        let rules = vec![allow_syscall_if(
            libc::SYS_ioctl,
            vec![SeccompRule::new(
                vec![Cond::new(2, SeccompCmpArgLen::Qword, Le, u64::from(u32::MAX) + 10).unwrap()],
                SeccompAction::Allow,
            )],
        )];
        // check syscalls that are supposed to work
        validate_seccomp_filter(
            rules.clone(),
            || unsafe {
                libc::ioctl(0, 0, u64::from(u32::MAX) + 10);
                libc::ioctl(0, 0, u64::from(u32::MAX) + 9);
            },
            false,
        );
        // check syscalls that are not supposed to work
        validate_seccomp_filter(
            rules,
            || unsafe {
                libc::ioctl(0, 0, u64::from(u32::MAX) + 11);
            },
            true,
        );
    }

    #[test]
    fn test_lt_operator() {
        // check use case for SeccompCmpArgLen::DWORD
        let rules = vec![allow_syscall_if(
            libc::SYS_ioctl,
            vec![SeccompRule::new(
                vec![Cond::new(1, SeccompCmpArgLen::Dword, Lt, KVM_GET_PIT2).unwrap()],
                SeccompAction::Allow,
            )],
        )];
        // check syscalls that are supposed to work
        validate_seccomp_filter(
            rules.clone(),
            || unsafe {
                libc::ioctl(0, (KVM_GET_PIT2 - 1) as IoctlRequest);
            },
            false,
        );
        // check syscalls that are not supposed to work
        validate_seccomp_filter(
            rules,
            || unsafe {
                libc::ioctl(0, KVM_GET_PIT2 as IoctlRequest);
            },
            true,
        );

        // check use case for SeccompCmpArgLen::QWORD
        let rules = vec![allow_syscall_if(
            libc::SYS_ioctl,
            vec![SeccompRule::new(
                vec![Cond::new(2, SeccompCmpArgLen::Qword, Lt, u64::from(u32::MAX) + 10).unwrap()],
                SeccompAction::Allow,
            )],
        )];
        // check syscalls that are supposed to work
        validate_seccomp_filter(
            rules.clone(),
            || unsafe {
                libc::ioctl(0, 0, u64::from(u32::MAX) + 9);
            },
            false,
        );
        // check syscalls that are not supposed to work
        validate_seccomp_filter(
            rules,
            || unsafe {
                libc::ioctl(0, 0, u64::from(u32::MAX) + 10);
            },
            true,
        );
    }

    #[test]
    fn test_masked_eq_operator() {
        // check use case for SeccompCmpArgLen::DWORD
        let rules = vec![allow_syscall_if(
            libc::SYS_ioctl,
            vec![SeccompRule::new(
                vec![Cond::new(
                    1,
                    SeccompCmpArgLen::Dword,
                    MaskedEq(KVM_GET_PIT2_MSB),
                    KVM_GET_PIT2,
                )
                .unwrap()],
                SeccompAction::Allow,
            )],
        )];
        // check syscalls that are supposed to work
        validate_seccomp_filter(
            rules.clone(),
            || unsafe {
                libc::ioctl(0, KVM_GET_PIT2 as IoctlRequest);
                libc::ioctl(0, KVM_GET_PIT2_MSB as IoctlRequest);
            },
            false,
        );
        // check syscalls that are not supposed to work
        validate_seccomp_filter(
            rules,
            || unsafe {
                libc::ioctl(0, KVM_GET_PIT2_LSB as IoctlRequest);
            },
            true,
        );

        // check use case for SeccompCmpArgLen::QWORD
        let rules = vec![allow_syscall_if(
            libc::SYS_ioctl,
            vec![SeccompRule::new(
                vec![Cond::new(
                    2,
                    SeccompCmpArgLen::Qword,
                    MaskedEq(u64::from(u32::MAX)),
                    u64::MAX,
                )
                .unwrap()],
                SeccompAction::Allow,
            )],
        )];
        // check syscalls that are supposed to work
        validate_seccomp_filter(
            rules.clone(),
            || unsafe {
                libc::ioctl(0, 0, u64::from(u32::MAX));
                libc::ioctl(0, 0, u64::MAX);
            },
            false,
        );
        // check syscalls that are not supposed to work
        validate_seccomp_filter(
            rules,
            || unsafe {
                libc::ioctl(0, 0, 0);
            },
            true,
        );
    }

    #[test]
    fn test_ne_operator() {
        // check use case for SeccompCmpArgLen::DWORD
        let rules = vec![allow_syscall_if(
            libc::SYS_ioctl,
            vec![SeccompRule::new(
                vec![Cond::new(1, SeccompCmpArgLen::Dword, Ne, KVM_GET_PIT2).unwrap()],
                SeccompAction::Allow,
            )],
        )];
        // check syscalls that are supposed to work
        validate_seccomp_filter(
            rules.clone(),
            || unsafe {
                libc::ioctl(0, 0);
            },
            false,
        );
        // check syscalls that are not supposed to work
        validate_seccomp_filter(
            rules,
            || unsafe {
                libc::ioctl(0, KVM_GET_PIT2 as IoctlRequest);
            },
            true,
        );

        // check use case for SeccompCmpArgLen::QWORD
        let rules = vec![allow_syscall_if(
            libc::SYS_ioctl,
            vec![SeccompRule::new(
                vec![Cond::new(2, SeccompCmpArgLen::Qword, Ne, u64::MAX).unwrap()],
                SeccompAction::Allow,
            )],
        )];
        // check syscalls that are supposed to work
        validate_seccomp_filter(
            rules.clone(),
            || unsafe {
                libc::ioctl(0, 0, 0);
            },
            false,
        );
        // check syscalls that are not supposed to work
        validate_seccomp_filter(
            rules,
            || unsafe {
                libc::ioctl(0, 0, u64::MAX);
            },
            true,
        );
    }

    // Checks that rule gets translated correctly into BPF statements.
    #[test]
    fn test_rule_bpf_output() {
        Cond::new(6, ArgLen::Qword, Eq, 1).unwrap_err();

        // Builds rule.
        let rule = SeccompRule::new(
            vec![
                Cond::new(0, ArgLen::Dword, Eq, 1).unwrap(),
                Cond::new(2, ArgLen::Qword, MaskedEq(0b1010), 14).unwrap(),
            ],
            SeccompAction::Allow,
        );

        let (msb_offset, lsb_offset) = { (4, 0) };

        // Builds hardcoded BPF instructions.
        let instructions = vec![
            BPF_STMT(0x05, 1),
            BPF_STMT(0x05, 10),
            BPF_STMT(0x20, 32 + msb_offset),
            BPF_STMT(0x54, 0),
            BPF_JUMP(0x15, 0, 0, 6),
            BPF_STMT(0x20, 32 + lsb_offset),
            BPF_STMT(0x54, 0b1010),
            BPF_JUMP(0x15, 14 & 0b1010, 0, 3),
            BPF_STMT(0x20, 16 + lsb_offset),
            BPF_JUMP(0x15, 1, 0, 1),
            BPF_STMT(0x06, 0x7fff_0000),
        ];

        // Compares translated rule with hardcoded BPF instructions.
        let bpfprog: BpfProgram = rule.into();
        assert_eq!(bpfprog, instructions);
    }

    // Checks that rule with too many conditions gets translated correctly into BPF statements
    // using three helper jumps.
    #[test]
    fn test_rule_many_conditions_bpf_output() {
        // Builds rule.
        let mut conditions = Vec::with_capacity(43);
        for _ in 0..42 {
            conditions.push(Cond::new(0, ArgLen::Qword, MaskedEq(0), 0).unwrap());
        }
        conditions.push(Cond::new(0, ArgLen::Qword, Eq, 0).unwrap());
        let rule = SeccompRule::new(conditions, SeccompAction::Allow);

        let (msb_offset, lsb_offset) = { (4, 0) };

        // Builds hardcoded BPF instructions.
        let mut instructions = vec![
            BPF_STMT(0x05, 1),
            BPF_STMT(0x05, 6),
            BPF_STMT(0x20, 16 + msb_offset),
            BPF_JUMP(0x15, 0, 0, 3),
            BPF_STMT(0x20, 16 + lsb_offset),
            BPF_JUMP(0x15, 0, 0, 1),
            BPF_STMT(0x05, 2),
            BPF_STMT(0x05, 254),
            BPF_STMT(0x05, 254),
        ];
        let mut offset = 253;
        for _ in 0..42 {
            offset -= 6;
            instructions.append(&mut vec![
                BPF_STMT(0x20, 16 + msb_offset),
                BPF_STMT(0x54, 0),
                BPF_JUMP(0x15, 0, 0, offset + 3),
                BPF_STMT(0x20, 16 + lsb_offset),
                BPF_STMT(0x54, 0),
                BPF_JUMP(0x15, 0, 0, offset),
            ]);
        }
        instructions.push(BPF_STMT(0x06, 0x7fff_0000));

        // Compares translated rule with hardcoded BPF instructions.
        let bpfprog: BpfProgram = rule.into();
        assert_eq!(bpfprog, instructions);
    }

    fn create_test_bpf_filter(arg_len: ArgLen) -> SeccompFilter {
        SeccompFilter::new(
            vec![
                allow_syscall_if(
                    1,
                    vec![
                        SeccompRule::new(
                            vec![
                                Cond::new(2, arg_len.clone(), Le, 14).unwrap(),
                                Cond::new(2, arg_len.clone(), Ne, 10).unwrap(),
                            ],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![
                                Cond::new(2, arg_len.clone(), Gt, 20).unwrap(),
                                Cond::new(2, arg_len.clone(), Lt, 30).unwrap(),
                            ],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![Cond::new(2, arg_len.clone(), Ge, 42).unwrap()],
                            SeccompAction::Allow,
                        ),
                    ],
                ),
                allow_syscall_if(
                    9,
                    vec![SeccompRule::new(
                        vec![Cond::new(1, arg_len, MaskedEq(0b100), 36).unwrap()],
                        SeccompAction::Allow,
                    )],
                ),
            ]
            .into_iter()
            .collect(),
            SeccompAction::Trap,
            ARCH,
        )
        .unwrap()
    }

    #[test]
    fn test_filter_bpf_output_dword() {
        // Compares translated filter with hardcoded BPF program.
        {
            let mut empty_rule_map = BTreeMap::new();
            empty_rule_map.insert(1, vec![]);
            SeccompFilter::new(empty_rule_map, SeccompAction::Allow, ARCH).unwrap_err();
        }

        let filter = create_test_bpf_filter(ArgLen::Dword);

        let mut instructions = Vec::new();
        instructions.extend(VALIDATE_ARCHITECTURE(ARCH.try_into().unwrap()));
        instructions.extend(vec![
            BPF_STMT(0x20, 0),
            BPF_JUMP(0x15, 1, 0, 1),
            BPF_STMT(0x05, 1),
            BPF_STMT(0x05, 6),
            BPF_STMT(0x20, 32),
            BPF_JUMP(0x15, 10, 3, 0),
            BPF_STMT(0x20, 32),
            BPF_JUMP(0x25, 14, 1, 0),
            BPF_STMT(0x06, 0x7fff_0000),
            BPF_STMT(0x05, 1),
            BPF_STMT(0x05, 6),
            BPF_STMT(0x20, 32),
            BPF_JUMP(0x35, 30, 3, 0),
            BPF_STMT(0x20, 32),
            BPF_JUMP(0x25, 20, 0, 1),
            BPF_STMT(0x06, 0x7fff_0000),
            BPF_STMT(0x05, 1),
            BPF_STMT(0x05, 4),
            BPF_STMT(0x20, 32),
            BPF_JUMP(0x35, 42, 0, 1),
            BPF_STMT(0x06, 0x7fff_0000),
            BPF_STMT(0x06, 0x0003_0000),
            BPF_JUMP(0x15, 9, 0, 1),
            BPF_STMT(0x05, 1),
            BPF_STMT(0x05, 5),
            BPF_STMT(0x20, 24),
            BPF_STMT(0x54, 0b100),
            BPF_JUMP(0x15, 36 & 0b100, 0, 1),
            BPF_STMT(0x06, 0x7fff_0000),
            BPF_STMT(0x06, 0x0003_0000),
            BPF_STMT(0x06, 0x0003_0000),
        ]);

        let bpfprog: BpfProgram = filter.try_into().unwrap();
        assert_eq!(bpfprog, instructions);
    }

    #[test]
    fn test_filter_bpf_output_qword() {
        // Compares translated filter with hardcoded BPF program.
        {
            let mut empty_rule_map = BTreeMap::new();
            empty_rule_map.insert(1, vec![]);
            SeccompFilter::new(empty_rule_map, SeccompAction::Allow, ARCH).unwrap_err();
        }

        let filter = create_test_bpf_filter(ArgLen::Qword);

        let mut instructions = Vec::new();
        instructions.extend(VALIDATE_ARCHITECTURE(ARCH.try_into().unwrap()));
        instructions.extend(vec![
            BPF_STMT(0x20, 0),
            BPF_JUMP(0x15, 1, 0, 1),
            BPF_STMT(0x05, 1),
            BPF_STMT(0x05, 11),
            BPF_STMT(0x20, 36),
            BPF_JUMP(0x15, 0, 0, 2),
            BPF_STMT(0x20, 32),
            BPF_JUMP(0x15, 10, 6, 0),
            BPF_STMT(0x20, 36),
            BPF_JUMP(0x25, 0, 4, 0),
            BPF_JUMP(0x15, 0, 0, 2),
            BPF_STMT(0x20, 32),
            BPF_JUMP(0x25, 14, 1, 0),
            BPF_STMT(0x06, 0x7fff_0000),
            BPF_STMT(0x05, 1),
            BPF_STMT(0x05, 12),
            BPF_STMT(0x20, 36),
            BPF_JUMP(0x25, 0, 9, 0),
            BPF_JUMP(0x15, 0, 0, 2),
            BPF_STMT(0x20, 32),
            BPF_JUMP(0x35, 30, 6, 0),
            BPF_STMT(0x20, 36),
            BPF_JUMP(0x25, 0, 3, 0),
            BPF_JUMP(0x15, 0, 0, 3),
            BPF_STMT(0x20, 32),
            BPF_JUMP(0x25, 20, 0, 1),
            BPF_STMT(0x06, 0x7fff_0000),
            BPF_STMT(0x05, 1),
            BPF_STMT(0x05, 7),
            BPF_STMT(0x20, 36),
            BPF_JUMP(0x25, 0, 3, 0),
            BPF_JUMP(0x15, 0, 0, 3),
            BPF_STMT(0x20, 32),
            BPF_JUMP(0x35, 42, 0, 1),
            BPF_STMT(0x06, 0x7fff_0000),
            BPF_STMT(0x06, 0x0003_0000),
            BPF_JUMP(0x15, 9, 0, 1),
            BPF_STMT(0x05, 1),
            BPF_STMT(0x05, 8),
            BPF_STMT(0x20, 28),
            BPF_STMT(0x54, 0),
            BPF_JUMP(0x15, 0, 0, 4),
            BPF_STMT(0x20, 24),
            BPF_STMT(0x54, 0b100),
            BPF_JUMP(0x15, 36 & 0b100, 0, 1),
            BPF_STMT(0x06, 0x7fff_0000),
            BPF_STMT(0x06, 0x0003_0000),
            BPF_STMT(0x06, 0x0003_0000),
        ]);

        let bpfprog: BpfProgram = filter.try_into().unwrap();
        assert_eq!(bpfprog, instructions);
    }

    #[test]
    fn test_bpf_expanding_functions() {
        // Compares the output of the BPF instruction generating functions to hardcoded
        // instructions.
        assert_eq!(
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 16),
            sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 16,
            }
        );
        assert_eq!(
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 10, 2, 5),
            sock_filter {
                code: 0x15,
                jt: 2,
                jf: 5,
                k: 10,
            }
        );
    }

    #[test]
    fn test_bpf_functions() {
        {
            let ret = VALIDATE_ARCHITECTURE(ARCH.try_into().unwrap());
            let instructions = vec![
                sock_filter {
                    code: 32,
                    jt: 0,
                    jf: 0,
                    k: 4,
                },
                sock_filter {
                    code: 21,
                    jt: 1,
                    jf: 0,
                    #[cfg(target_arch = "x86_64")]
                    k: AUDIT_ARCH_X86_64,
                    #[cfg(target_arch = "aarch64")]
                    k: AUDIT_ARCH_AARCH64,
                },
                sock_filter {
                    code: 6,
                    jt: 0,
                    jf: 0,
                    k: SECCOMP_RET_KILL_PROCESS,
                },
            ];
            assert_eq!(ret, instructions);
        }

        {
            let ret = EXAMINE_SYSCALL();
            let instructions = vec![sock_filter {
                code: 32,
                jt: 0,
                jf: 0,
                k: 0,
            }];
            assert_eq!(ret, instructions);
        }
    }

    #[test]
    fn test_empty_filter() {
        // An empty filter should always return the default action.
        // For example, for an empty allowlist, it should always trap/kill,
        // for an empty denylist, it should allow allow all system calls.

        let mut expected_program = Vec::new();
        expected_program.extend(VALIDATE_ARCHITECTURE(ARCH.try_into().unwrap()));
        expected_program.extend(vec![BPF_STMT(0x06, 0x7fff_0000)]);

        let empty_rule_map = BTreeMap::new();
        let filter = SeccompFilter::new(empty_rule_map, SeccompAction::Allow, ARCH).unwrap();
        let prog: BpfProgram = filter.try_into().unwrap();

        assert_eq!(expected_program, prog);

        // This should allow any system calls.
        let pid = thread::spawn(move || {
            // Install the filter.
            install_filter(prog);

            unsafe { libc::getpid() }
        })
        .join()
        .unwrap();

        // Check that the getpid syscall returned successfully.
        assert!(pid > 0);
    }

    #[test]
    fn test_error_messages() {
        assert_eq!(
            format!("{}", FilterError::EmptyRulesVector),
            "The seccomp rules vector is empty."
        );
        assert_eq!(
            format!("{}", FilterError::FilterTooLarge),
            "The seccomp filter contains too many BPF instructions."
        );
        assert_eq!(
            format!("{}", FilterError::InvalidArgumentNumber),
            "The seccomp rule contains an invalid argument number."
        );
        assert_eq!(
            format!(
                "{}",
                FilterError::Arch(TargetArchError::InvalidString("lala".to_string()))
            ),
            format!("{0}", TargetArchError::InvalidString("lala".to_string()))
        );
    }

    #[test]
    fn test_from_seccomp_action() {
        assert_eq!(0x7fff_0000, u32::from(SeccompAction::Allow));
        assert_eq!(0x0005_002a, u32::from(SeccompAction::Errno(42)));
        assert_eq!(0x0000_0000, u32::from(SeccompAction::KillThread));
        assert_eq!(0x8000_0000, u32::from(SeccompAction::KillProcess));
        assert_eq!(0x7ffc_0000, u32::from(SeccompAction::Log));
        assert_eq!(0x7ff0_002a, u32::from(SeccompAction::Trace(42)));
        assert_eq!(0x0003_0000, u32::from(SeccompAction::Trap));
    }

    #[test]
    fn test_validate_condition() {
        // Invalid argument number
        assert_eq!(
            Cond::new(90, ArgLen::Dword, Eq, 65),
            Err(FilterError::InvalidArgumentNumber)
        );

        // Valid argument number
        Cond::new(0, ArgLen::Dword, Eq, 65).unwrap();
    }

    #[test]
    fn test_seccomp_filter_validate() {
        // Failure cases.
        {
            // Syscall has no rules.
            assert_eq!(
                SeccompFilter::new(
                    vec![(1, vec![]),].into_iter().collect(),
                    SeccompAction::Trap,
                    ARCH,
                )
                .unwrap_err(),
                FilterError::EmptyRulesVector
            );
            // Syscall has multiple empty rules.
            assert_eq!(
                SeccompFilter::new(
                    vec![(
                        1,
                        vec![
                            SeccompRule::new(vec![], SeccompAction::Allow),
                            SeccompRule::new(vec![], SeccompAction::Allow)
                        ]
                    ),]
                    .into_iter()
                    .collect(),
                    SeccompAction::Trap,
                    ARCH,
                )
                .unwrap_err(),
                FilterError::ConflictingRules(1)
            );

            // Syscall has both empty rules condition-based rules.
            assert_eq!(
                SeccompFilter::new(
                    vec![(
                        1,
                        vec![
                            SeccompRule::new(vec![], SeccompAction::Allow),
                            SeccompRule::new(
                                vec![
                                    Cond::new(2, ArgLen::Dword, Le, 14).unwrap(),
                                    Cond::new(1, ArgLen::Dword, Ne, 10).unwrap(),
                                ],
                                SeccompAction::Allow,
                            ),
                        ]
                    ),]
                    .into_iter()
                    .collect(),
                    SeccompAction::Trap,
                    ARCH,
                )
                .unwrap_err(),
                FilterError::ConflictingRules(1)
            );
        }
    }
}
