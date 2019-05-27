// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![deny(missing_docs)]
//! This crate implements a high level wrapper over BPF instructions for seccomp filtering.
//!
//! # Seccomp Filtering Levels
//!
//! [Seccomp filtering](https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt) is used
//! to limit the set of syscalls that a process can make. This crate exposes 2 levels of filtering:
//! 1. Simple filtering: all syscalls are denied, except for a subset that are explicitly let
//!    through. The latter are identified solely through the syscall number.
//! 1. Advanced filtering: all syscalls are denied, except for a subset that are explicitly let
//!    through. The latter are identified via the syscall number and the allowed values for the
//!    syscall's arguments. Arguments whose values do not match the filtering rule will cause the
//!    syscall to be denied.
//!
//! The desired filtering level is passed to the [`apply`] function.
//!
//! ## Example with Filtering Disabled
//!
//! ```
//! extern crate libc;
//!
//! fn main() {
//!     let buf = "Hello, world!";
//!     assert_eq!(
//!         unsafe {
//!             libc::syscall(
//!                 libc::SYS_write,
//!                 libc::STDOUT_FILENO,
//!                 buf.as_bytes(),
//!                 buf.len(),
//!             );
//!         },
//!         ()
//!     );
//! }
//! ```
//!
//! The code snippet above will print "Hello, world!" to stdout.
//! The exit code will be 0.
//!
//! ## Example with Simple Filtering
//!
//! In this example, the process will allow a subset of syscalls. All the others will fall under
//! the `Trap` action: cause the kernel to send `SIGSYS` (signal number 31) to the process.
//! Without a signal handler in place, the process will die with exit code 159 (128 + `SIGSYS`).
//!
//! ```should_panic
//! extern crate libc;
//! extern crate seccomp;
//!
//! use seccomp::*;
//!
//! fn main() {
//!     let buf = "Hello, world!";
//!     let filter = SeccompFilter::new(
//!         vec![
//!             allow_syscall(libc::SYS_close),
//!             allow_syscall(libc::SYS_execve),
//!             allow_syscall(libc::SYS_exit_group),
//!             #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
//!             allow_syscall(libc::SYS_open),
//!             #[cfg(target_arch = "aarch64")]
//!             allow_syscall(libc::SYS_openat),
//!             allow_syscall(libc::SYS_read),
//!         ]
//!         .into_iter()
//!         .collect(),
//!         SeccompAction::Trap,
//!     )
//!     .unwrap();
//!     filter.apply().unwrap();
//!     unsafe {
//!         libc::syscall(
//!             libc::SYS_write,
//!             libc::STDOUT_FILENO,
//!             buf.as_bytes(),
//!             buf.len(),
//!         );
//!     };
//! }
//! ```
//!
//! The code snippet above will print "Hello, world!" to stdout and "Bad system call" to stderr.
//! The exit code will be 159.
//!
//! ## Advanced Filtering: Conditions, Rules and Filters
//!
//! A system call is matched if it verifies a set of [`SeccompCondition`]s. Namely, the syscall
//! number must match the one in the [`SeccompCondition`], and each of its arguments (in case of
//! advanced filtering) must match a set of [`SeccompCondition`]s that identify the argument by its
//! index and its respective value either by exact value match, or by bounds to be compared to.
//!
//! A [`SeccompRule`] is composed of a set of [`SeccompCondition`]s the syscall must match and the
//! [`SeccompAction`] to be taken in case of a match.
//!
//! A [`SeccompFilter`] applies only to advanced filtering and is composed of a set of
//! [`SeccompRule`]s and a default [`SeccompAction`]. The default action will be taken for the
//! syscalls that do not match any of the rules.
//!
//! ### Denying Syscalls
//!
//! The [`SeccompRule`] struct specifies which action to be taken when a syscall is attempted
//! through its [`action`]. To deny a syscall, [`action`] must take one of the following values:
//! 1. `Errno(num)`: the syscall will not be executed. `errno` will be set to `num`.
//! 1. `Kill`: the kernel will kill the process.
//! 1. `Trap`: the kernel will send `SIGSYS` to the process. Handling is up to the process. If no
//!    signal handler is set for `SIGSYS`, the process will die.
//!
//! ### Example with Advanced Filtering
//!
//! In this example, the process will allow a subset of syscalls with any arguments and the syscall
//! `SYS_write` with the first argument `0` and the third argument `13`. The default action is to
//! cause the kernel to send `SIGSYS` (signal number 31) to the process.
//! A signal handler will catch `SIGSYS` and exit with code 159 on any other syscall.
//!
//! ```should_panic
//! extern crate libc;
//! extern crate seccomp;
//!
//! use seccomp::*;
//! use std::mem;
//! use std::process::exit;
//!
//! const SI_OFF_SYSCALL: isize = 6;
//! static mut SIGNAL_HANDLER_CALLED: i32 = 0;
//!
//! fn fail() {
//!     exit(159);
//! }
//!
//! extern "C" fn sigsys_handler(
//!     _num: libc::c_int,
//!     info: *mut libc::siginfo_t,
//!     _unused: *mut libc::c_void,
//! ) {
//!     let syscall = unsafe { *(info as *const i32).offset(SI_OFF_SYSCALL) };
//!     if syscall as i64 != libc::SYS_write {
//!         fail();
//!     }
//!     unsafe {
//!         SIGNAL_HANDLER_CALLED = SIGNAL_HANDLER_CALLED + 1;
//!     }
//! }
//!
//! fn gen_rules() -> Vec<SyscallRuleSet> {
//!     vec![
//!         allow_syscall(libc::SYS_close),
//!         allow_syscall(libc::SYS_execve),
//!         allow_syscall(libc::SYS_exit_group),
//!         allow_syscall(libc::SYS_munmap),
//!         #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
//!         allow_syscall(libc::SYS_open),
//!         #[cfg(target_arch = "aarch64")]
//!         allow_syscall(libc::SYS_openat),
//!         allow_syscall(libc::SYS_rt_sigreturn),
//!         allow_syscall(libc::SYS_sigaltstack),
//!     ]
//! }
//!
//! fn main() {
//!     let buf = "Hello, world!";
//!
//!     let mut act: libc::sigaction = unsafe { mem::zeroed() };
//!     act.sa_flags = libc::SA_SIGINFO;
//!     act.sa_sigaction = sigsys_handler as *const () as usize;
//!
//!     unsafe { libc::sigaction(libc::SIGSYS, &act, ::std::ptr::null_mut()) };
//!
//!     let mut filter =
//!         SeccompFilter::new(vec![].into_iter().collect(), SeccompAction::Trap).unwrap();
//!
//!     gen_rules()
//!         .into_iter()
//!         .try_for_each(|(syscall_number, rules)| filter.add_rules(syscall_number, rules))
//!         .unwrap();
//!
//!     filter
//!         .add_rules(
//!             libc::SYS_write,
//!             vec![SeccompRule::new(
//!                 vec![
//!                     SeccompCondition::new(0, SeccompCmpOp::Eq, libc::STDOUT_FILENO as u64).unwrap(),
//!                     SeccompCondition::new(2, SeccompCmpOp::Eq, 13).unwrap(),
//!                 ],
//!                 SeccompAction::Allow,
//!             )],
//!         )
//!         .unwrap();
//!
//!     filter.apply().unwrap();
//!
//!     unsafe {
//!         libc::syscall(
//!             libc::SYS_write,
//!             libc::STDOUT_FILENO,
//!             buf.as_bytes(),
//!             buf.len(),
//!         );
//!     };
//!
//!     if unsafe { SIGNAL_HANDLER_CALLED } != 0 {
//!         fail();
//!     }
//!
//!     let buf = "Goodbye!";
//!     unsafe {
//!         libc::syscall(
//!             libc::SYS_write,
//!             libc::STDOUT_FILENO,
//!             buf.as_bytes(),
//!             buf.len(),
//!         );
//!     };
//!     if unsafe { SIGNAL_HANDLER_CALLED } != 1 {
//!         fail();
//!     }
//!
//!     unsafe {
//!         libc::syscall(libc::SYS_getpid);
//!     };
//! }
//! ```
//! The code snippet above will print "Hello, world!" to stdout.
//! The exit code will be 159.
//!
//! [`apply`]: struct.SeccompFilter.html#apply
//! [`SeccompCondition`]: struct.SeccompCondition.html
//! [`SeccompRule`]: struct.SeccompRule.html
//! [`SeccompAction`]: enum.SeccompAction.html
//! [`SeccompFilter`]: struct.SeccompFilter.html
//! [`action`]: struct.SeccompRule.html#action
//!

extern crate libc;

use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};

/// Level of filtering that causes syscall numbers and parameters to be examined.
pub const SECCOMP_LEVEL_ADVANCED: u32 = 2;
/// Level of filtering that causes only syscall numbers to be examined.
pub const SECCOMP_LEVEL_BASIC: u32 = 1;
/// Seccomp filtering disabled.
pub const SECCOMP_LEVEL_NONE: u32 = 0;

/// Maximum number of instructions that a BPF program can have.
const BPF_MAX_LEN: usize = 4096;

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
const SECCOMP_RET_KILL: u32 = 0x0000_0000;
const SECCOMP_RET_LOG: u32 = 0x7ffc_0000;
const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
const SECCOMP_RET_MASK: u32 = 0x0000_ffff;

// Architecture identifier.
// See /usr/include/linux/audit.h .

#[cfg(target_arch = "x86_64")]
// Defined as:
// `#define AUDIT_ARCH_X86_64	(EM_X86_64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)`
const AUDIT_ARCH_X86_64: u32 = 62 | 0x8000_0000 | 0x4000_0000;

#[cfg(target_arch = "aarch64")]
// Defined as:
// `#define AUDIT_ARCH_AARCH64	(EM_AARCH64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)`
const AUDIT_ARCH_AARCH64: u32 = 183 | 0x8000_0000 | 0x4000_0000;

// The maximum number of a syscall argument.
// A syscall can have at most 6 arguments.
// Arguments are numbered from 0 to 5.
const ARG_NUMBER_MAX: u8 = 5;

// The maximum number of BPF statements that a condition will be translated into.
const CONDITION_MAX_LEN: u16 = 6;

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

/// Seccomp errors.
#[derive(Debug)]
pub enum Error {
    /// Attempting to add an empty vector of rules to the rule chain of a syscall.
    EmptyRulesVector,
    /// Filter exceeds the maximum number of instructions that a BPF program can have.
    FilterTooLarge,
    /// Failed to translate rules into BPF.
    IntoBpf,
    /// Argument number that exceeds the maximum value.
    InvalidArgumentNumber,
    /// Invalid Seccomp level requested.
    InvalidLevel,
    /// Failed to load seccomp rules into the kernel.
    Load(i32),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::Error::*;

        match *self {
            EmptyRulesVector => write!(f, "The seccomp rules vector is empty."),
            FilterTooLarge => write!(f, "The seccomp filter contains too many BPF instructions."),
            IntoBpf => write!(f, "Failed to translate the seccomp rules into BPF."),
            InvalidArgumentNumber => {
                write!(f, "The seccomp rule contains an invalid argument number.")
            }
            InvalidLevel => write!(f, "The requested seccomp level is invalid."),
            Load(err) => write!(
                f,
                "Failed to load seccomp rules into the kernel with error {}.",
                err
            ),
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

/// Comparison to perform when matching a condition.
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

/// Condition that syscall must match in order to satisfy a rule.
pub struct SeccompCondition {
    /// Number of the argument value that is to be compared.
    arg_number: u8,
    /// Comparison to perform.
    operator: SeccompCmpOp,
    /// The value that will be compared with the argument value.
    value: u64,
}

/// Actions that `seccomp` can apply to process calling a syscall.
pub enum SeccompAction {
    /// Allows syscall.
    Allow,
    /// Returns from syscall with specified error number.
    Errno(u32),
    /// Kills calling process.
    Kill,
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
pub struct SeccompRule {
    /// Conditions of rule that need to match in order for the rule to get matched.
    conditions: Vec<SeccompCondition>,
    /// Action applied to calling process if rule gets matched.
    action: SeccompAction,
}

/// Type that encapsulates a tuple (syscall number, rule set).
///
pub type SyscallRuleSet = (i64, Vec<SeccompRule>);

/// Builds the (syscall, rules) tuple for allowing a syscall regardless of arguments.
///
#[inline(always)]
pub fn allow_syscall(syscall_number: i64) -> SyscallRuleSet {
    (
        syscall_number,
        vec![SeccompRule::new(vec![], SeccompAction::Allow)],
    )
}

/// Builds the (syscall, rules) tuple for allowing a syscall with certain arguments.
///
#[inline(always)]
pub fn allow_syscall_if(syscall_number: i64, rules: Vec<SeccompRule>) -> SyscallRuleSet {
    (syscall_number, rules)
}

/// Filter containing rules assigned to syscall numbers.
///
pub struct SeccompFilter {
    /// Map of syscall numbers and corresponding rule chains.
    rules: BTreeMap<i64, Vec<SeccompRule>>,
    /// Default action to apply to syscall numbers that do not exist in the hash map.
    default_action: SeccompAction,
}

// BPF instruction structure definition.
// See /usr/include/linux/filter.h .
#[repr(C)]
#[derive(Debug, PartialEq)]
struct sock_filter {
    pub code: ::std::os::raw::c_ushort,
    pub jt: ::std::os::raw::c_uchar,
    pub jf: ::std::os::raw::c_uchar,
    pub k: ::std::os::raw::c_uint,
}

// BPF structure definition for filter array.
// See /usr/include/linux/filter.h .
#[repr(C)]
struct sock_fprog {
    pub len: ::std::os::raw::c_ushort,
    pub filter: *const sock_filter,
}

impl SeccompCondition {
    /// Creates a new [`SeccompCondition`].
    ///
    /// # Arguments
    ///
    /// * `arg_number` - The index of the argument in the system call.
    /// * `operator` - The comparison operator. See `SeccompCmpOp`.
    /// * `value` - The value against which the argument will be compared with `operator`.
    ///
    /// [`SeccompCondition`]: struct.SeccompCondition.html
    ///
    pub fn new(arg_number: u8, operator: SeccompCmpOp, value: u64) -> Result<Self> {
        // Checks that the given argument number is valid.
        if arg_number > ARG_NUMBER_MAX {
            return Err(Error::InvalidArgumentNumber);
        }

        Ok(Self {
            arg_number,
            operator,
            value,
        })
    }

    /// Splits the [`SeccompCondition`] into 32 bit chunks and offsets.
    ///
    /// Returns most significant half, least significant half of the `value` field of
    /// [`SeccompCondition`], as well as the offsets of the most significant and least significant
    /// half of the argument specified by `arg_number` relative to `struct seccomp_data` passed to
    /// the BPF program by the kernel.
    ///
    /// [`SeccompCondition`]: struct.SeccompCondition.html
    ///
    fn value_segments(&self) -> (u32, u32, u8, u8) {
        // Splits the specified value into its most significant and least significant halves.
        let (msb, lsb) = ((self.value >> 32) as u32, self.value as u32);

        // Offset to the argument specified by `arg_number`.
        let arg_offset = SECCOMP_DATA_ARGS_OFFSET + self.arg_number * SECCOMP_DATA_ARG_SIZE;

        // Extracts offsets of most significant and least significant halves of argument.
        let (msb_offset, lsb_offset) = {
            #[cfg(target_endian = "big")]
            {
                (arg_offset, arg_offset + SECCOMP_DATA_ARG_SIZE / 2)
            }
            #[cfg(target_endian = "little")]
            {
                (arg_offset + SECCOMP_DATA_ARG_SIZE / 2, arg_offset)
            }
        };

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
    ///
    fn into_eq_bpf(self, offset: u8) -> Vec<sock_filter> {
        let (msb, lsb, msb_offset, lsb_offset) = self.value_segments();
        vec![
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, u32::from(msb_offset)),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, msb, 0, offset + 2),
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, u32::from(lsb_offset)),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, lsb, 0, offset),
        ]
    }

    /// Translates the `ge` (greater than or equal) condition into BPF statements.
    ///
    /// # Arguments
    ///
    /// * `offset` - The given jump offset to the start of the next rule.
    ///
    fn into_ge_bpf(self, offset: u8) -> Vec<sock_filter> {
        let (msb, lsb, msb_offset, lsb_offset) = self.value_segments();
        vec![
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, u32::from(msb_offset)),
            BPF_JUMP(BPF_JMP + BPF_JGT + BPF_K, msb, 3, 0),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, msb, 0, offset + 2),
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, u32::from(lsb_offset)),
            BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, lsb, 0, offset),
        ]
    }

    /// Translates the `gt` (greater than) condition into BPF statements.
    ///
    /// # Arguments
    ///
    /// * `offset` - The given jump offset to the start of the next rule.
    ///
    fn into_gt_bpf(self, offset: u8) -> Vec<sock_filter> {
        let (msb, lsb, msb_offset, lsb_offset) = self.value_segments();
        vec![
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, u32::from(msb_offset)),
            BPF_JUMP(BPF_JMP + BPF_JGT + BPF_K, msb, 3, 0),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, msb, 0, offset + 2),
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, u32::from(lsb_offset)),
            BPF_JUMP(BPF_JMP + BPF_JGT + BPF_K, lsb, 0, offset),
        ]
    }

    /// Translates the `le` (less than or equal) condition into BPF statements.
    ///
    /// # Arguments
    ///
    /// * `offset` - The given jump offset to the start of the next rule.
    ///
    fn into_le_bpf(self, offset: u8) -> Vec<sock_filter> {
        let (msb, lsb, msb_offset, lsb_offset) = self.value_segments();
        vec![
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, u32::from(msb_offset)),
            BPF_JUMP(BPF_JMP + BPF_JGT + BPF_K, msb, offset + 3, 0),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, msb, 0, 2),
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, u32::from(lsb_offset)),
            BPF_JUMP(BPF_JMP + BPF_JGT + BPF_K, lsb, offset, 0),
        ]
    }

    /// Translates the `lt` (less than) condition into BPF statements.
    ///
    /// # Arguments
    ///
    /// * `offset` - The given jump offset to the start of the next rule.
    ///
    fn into_lt_bpf(self, offset: u8) -> Vec<sock_filter> {
        let (msb, lsb, msb_offset, lsb_offset) = self.value_segments();
        vec![
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, u32::from(msb_offset)),
            BPF_JUMP(BPF_JMP + BPF_JGT + BPF_K, msb, offset + 3, 0),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, msb, 0, 2),
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, u32::from(lsb_offset)),
            BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K, lsb, offset, 0),
        ]
    }

    /// Translates the `masked_eq` (masked equal) condition into BPF statements.
    ///
    /// The `masked_eq` condition is `true` if the result of logical `AND` between the given value
    /// and the mask is the value being compared against.
    ///
    /// # Arguments
    ///
    /// * `offset` - The given jump offset to the start of the next rule.
    ///
    fn into_masked_eq_bpf(self, offset: u8, mask: u64) -> Vec<sock_filter> {
        let (_, _, msb_offset, lsb_offset) = self.value_segments();
        let masked_value = self.value & mask;
        let (msb, lsb) = ((masked_value >> 32) as u32, masked_value as u32);
        let (mask_msb, mask_lsb) = ((mask >> 32) as u32, mask as u32);

        vec![
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, u32::from(msb_offset)),
            BPF_STMT(BPF_ALU + BPF_AND + BPF_K, mask_msb),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, msb, 0, offset + 3),
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, u32::from(lsb_offset)),
            BPF_STMT(BPF_ALU + BPF_AND + BPF_K, mask_lsb),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, lsb, 0, offset),
        ]
    }

    /// Translates the `ne` (not equal) condition into BPF statements.
    ///
    /// # Arguments
    ///
    /// * `offset` - The given jump offset to the start of the next rule.
    ///
    fn into_ne_bpf(self, offset: u8) -> Vec<sock_filter> {
        let (msb, lsb, msb_offset, lsb_offset) = self.value_segments();
        vec![
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, u32::from(msb_offset)),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, msb, 0, 2),
            BPF_STMT(BPF_LD + BPF_W + BPF_ABS, u32::from(lsb_offset)),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, lsb, offset, 0),
        ]
    }

    /// Translates the [`SeccompCondition`] into BPF statements.
    ///
    /// # Arguments
    ///
    /// * `offset` - The given jump offset to the start of the next rule.
    ///
    /// [`SeccompCondition`]: struct.SeccompCondition.html
    ///
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
    ///
    fn from(action: SeccompAction) -> Self {
        match action {
            SeccompAction::Allow => SECCOMP_RET_ALLOW,
            SeccompAction::Errno(x) => SECCOMP_RET_ERRNO | (x & SECCOMP_RET_MASK),
            SeccompAction::Kill => SECCOMP_RET_KILL,
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
    ///
    pub fn new(conditions: Vec<SeccompCondition>, action: SeccompAction) -> Self {
        Self { conditions, action }
    }

    /// Translates a rule into BPF statements.
    ///
    /// Each rule starts with 2 jump statements:
    /// * The first jump enters the rule, attempting a match.
    /// * The second jump points to the end of the rule chain for one syscall, into the rule chain
    ///   for the next syscall or the default action if the current syscall is the last one. It
    ///   essentially jumps out of the current rule chain.
    ///
    fn into_bpf(self) -> Vec<sock_filter> {
        // Rule is built backwards, last statement is the action of the rule.
        // The offset to the next rule is 1.
        let mut accumulator = Vec::with_capacity(
            self.conditions.len()
                + ((self.conditions.len() * CONDITION_MAX_LEN as usize) / ::std::u8::MAX as usize)
                + 1,
        );
        let mut rule_len = 1;
        let mut offset = 1;
        accumulator.push(vec![BPF_STMT(BPF_RET + BPF_K, u32::from(self.action))]);

        // Conditions are translated into BPF statements and prepended to the rule.
        self.conditions.into_iter().for_each(|condition| {
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
    ///
    fn append_condition(
        condition: SeccompCondition,
        accumulator: &mut Vec<Vec<sock_filter>>,
        rule_len: &mut usize,
        offset: &mut u8,
    ) {
        // Tries to detect whether prepending the current condition will produce an unjumpable
        // offset (since BPF jumps are a maximum of 255 instructions).
        if u16::from(*offset) + CONDITION_MAX_LEN + 1 > u16::from(::std::u8::MAX) {
            // If that is the case, three additional helper jumps are prepended and the offset
            // is reset to 1.
            //
            // - The first jump continues the evaluation of the condition chain by jumping to
            //   the next condition or the action of the rule if the last condition was matched.
            // - The second, jumps out of the rule, to the next rule or the default action of
            //   the filter in case of the last rule in the rule chain of a syscall.
            // - The third jumps out of the rule chain of the syscall, to the rule chain of the
            //   next syscall number to be checked or the default action of the filter in the
            //   case of the last rule chain.
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
        *offset += condition.len() as u8;
        accumulator.push(condition);
    }
}

impl SeccompFilter {
    /// Creates a new filter with a set of rules and a default action.
    ///
    /// # Arguments
    ///
    /// * `rules` - Map of syscall numbers and the rules that will be applied to each of them.
    /// * `default_action` - Action taken for all syscalls that do not match any rule.
    ///
    pub fn new(
        rules: BTreeMap<i64, Vec<SeccompRule>>,
        default_action: SeccompAction,
    ) -> Result<Self> {
        // All inserted syscalls must have at least one rule, otherwise BPF code will break.
        for (_, value) in rules.iter() {
            if value.is_empty() {
                return Err(Error::EmptyRulesVector);
            }
        }

        Ok(Self {
            rules,
            default_action,
        })
    }

    /// Adds rules for the specified syscall in the filter.
    ///
    /// # Arguments
    ///
    /// * `syscall_number` - Syscall identifier.
    /// * `rules` - Rules to be applied to the syscall.
    ///
    pub fn add_rules(&mut self, syscall_number: i64, mut rules: Vec<SeccompRule>) -> Result<()> {
        // All inserted syscalls must have at least one rule, otherwise BPF code will break.
        if rules.is_empty() {
            return Err(Error::EmptyRulesVector);
        }

        self.rules
            .entry(syscall_number)
            .or_insert_with(|| vec![])
            .append(&mut rules);

        Ok(())
    }

    /// Builds the array of filter instructions and sends them to the kernel.
    ///
    /// # Arguments
    ///
    /// * `level` - Filtering level.
    ///
    pub fn apply(self) -> Result<()> {
        let mut bpf_filter = Vec::new();
        bpf_filter.extend(VALIDATE_ARCHITECTURE());
        bpf_filter.extend(self.into_bpf().map_err(|_| Error::Load(libc::EINVAL))?);

        unsafe {
            {
                let rc = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                if rc != 0 {
                    return Err(Error::Load(*libc::__errno_location()));
                }
            }

            let bpf_prog = sock_fprog {
                len: bpf_filter.len() as u16,
                filter: bpf_filter.as_ptr(),
            };
            let bpf_prog_ptr = &bpf_prog as *const sock_fprog;

            {
                let rc = libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER,
                    bpf_prog_ptr,
                );
                if rc != 0 {
                    return Err(Error::Load(*libc::__errno_location()));
                }
            }
        }

        Ok(())
    }

    /// Translates filter into BPF instructions.
    ///
    fn into_bpf(self) -> Result<Vec<sock_filter>> {
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
        let mut result = Vec::with_capacity(filter_len);
        accumulator
            .into_iter()
            .for_each(|mut instructions| result.append(&mut instructions));

        Ok(result)
    }

    /// Appends a chain of rules to an accumulator, updating the length of the filter.
    ///
    /// # Arguments
    ///
    /// * `syscall_number` - The syscall to which the rules apply.
    /// * `chain` - The chain of rules for the specified syscall.
    /// * `default_action` - The action to be taken in none of the rules apply.
    /// * `accumulator` - The expanding BPF program.
    /// * `filter_len` - The size (in number of BPF statements) of the BPF program. This is
    ///                  limited to 4096. If the limit is exceeded, the filter is invalidated.
    ///
    fn append_syscall_chain(
        syscall_number: i64,
        chain: Vec<SeccompRule>,
        default_action: u32,
        accumulator: &mut Vec<Vec<sock_filter>>,
        filter_len: &mut usize,
    ) -> Result<()> {
        // The rules of the chain are translated into BPF statements.
        let chain: Vec<_> = chain.into_iter().map(|rule| rule.into_bpf()).collect();
        let chain_len: usize = chain.iter().map(|rule| rule.len()).sum();

        // The chain starts with a comparison checking the loaded syscall number against the
        // syscall number of the chain.
        let mut built_syscall = Vec::with_capacity(1 + chain_len + 1);
        built_syscall.push(BPF_JUMP(
            BPF_JMP + BPF_JEQ + BPF_K,
            syscall_number as u32,
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
        if *filter_len >= BPF_MAX_LEN {
            return Err(Error::FilterTooLarge);
        }

        Ok(())
    }

    /// Replaces the seccomp rules so as to allow every syscall contained in the rule set.
    ///
    pub fn allow_all(mut self) -> SeccompFilter {
        // Pre-collect the keys to avoid the double borrow.
        let syscalls: Vec<i64> = self.rules.keys().cloned().collect();
        for syscall in syscalls {
            self.rules.insert(
                syscall,
                vec![SeccompRule::new(vec![], SeccompAction::Allow)],
            );
        }
        self
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
///
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
///
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
///
#[allow(non_snake_case)]
#[inline(always)]
fn VALIDATE_ARCHITECTURE() -> Vec<sock_filter> {
    vec![
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 4),
        #[cfg(target_arch = "x86_64")]
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        #[cfg(target_arch = "aarch64")]
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
    ]
}

/// Builds a sequence of BPF instructions that are followed by syscall examination.
///
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
    use super::*;
    use SeccompCmpOp::*;
    use SeccompCondition as Cond;

    // Checks that rule gets translated correctly into BPF statements.
    #[test]
    fn test_rule_bpf_output() {
        assert!(Cond::new(6, Eq, 1).is_err());

        // Builds rule.
        let rule = SeccompRule::new(
            vec![
                Cond::new(0, Eq, 1).unwrap(),
                Cond::new(2, MaskedEq(0b1010), 14).unwrap(),
            ],
            SeccompAction::Allow,
        );

        // Calculates architecture dependent argument value offsets.
        let (msb_offset, lsb_offset) = {
            #[cfg(target_endian = "big")]
            {
                (0, 4)
            }
            #[cfg(target_endian = "little")]
            {
                (4, 0)
            }
        };

        // Builds hardcoded BPF instructions.
        let instructions = vec![
            BPF_STMT(0x05, 1),
            BPF_STMT(0x05, 12),
            BPF_STMT(0x20, 32 + msb_offset),
            BPF_STMT(0x54, 0),
            BPF_JUMP(0x15, 0, 0, 8),
            BPF_STMT(0x20, 32 + lsb_offset),
            BPF_STMT(0x54, 0b1010),
            BPF_JUMP(0x15, 14 & 0b1010, 0, 5),
            BPF_STMT(0x20, 16 + msb_offset),
            BPF_JUMP(0x15, 0, 0, 3),
            BPF_STMT(0x20, 16 + lsb_offset),
            BPF_JUMP(0x15, 1, 0, 1),
            BPF_STMT(0x06, 0x7fff_0000),
        ];

        // Compares translated rule with hardcoded BPF instructions.
        assert_eq!(rule.into_bpf(), instructions);
    }

    // Checks that rule with too many conditions gets translated correctly into BPF statements
    // using three helper jumps.
    #[test]
    fn test_rule_many_conditions_bpf_output() {
        // Builds rule.
        let mut conditions = Vec::with_capacity(43);
        for _ in 0..42 {
            conditions.push(Cond::new(0, MaskedEq(0), 0).unwrap());
        }
        conditions.push(Cond::new(0, Eq, 0).unwrap());
        let rule = SeccompRule::new(conditions, SeccompAction::Allow);

        // Calculates architecture dependent argument value offsets.
        let (msb_offset, lsb_offset) = {
            #[cfg(target_endian = "big")]
            {
                (0, 4)
            }
            #[cfg(target_endian = "little")]
            {
                (4, 0)
            }
        };

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
        assert_eq!(rule.into_bpf(), instructions);
    }

    #[test]
    fn test_filter_bpf_output() {
        // Compares translated filter with hardcoded BPF program.
        {
            let mut empty_rule_map = BTreeMap::new();
            empty_rule_map.insert(1, vec![]);
            assert!(SeccompFilter::new(empty_rule_map, SeccompAction::Allow).is_err());
        }

        let filter = SeccompFilter::new(
            vec![
                allow_syscall_if(
                    1,
                    vec![
                        SeccompRule::new(
                            vec![Cond::new(2, Le, 14).unwrap(), Cond::new(2, Ne, 10).unwrap()],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![Cond::new(2, Gt, 20).unwrap(), Cond::new(2, Lt, 30).unwrap()],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(vec![Cond::new(2, Ge, 42).unwrap()], SeccompAction::Allow),
                    ],
                ),
                allow_syscall_if(
                    9,
                    vec![SeccompRule::new(
                        vec![Cond::new(1, MaskedEq(0b100), 36).unwrap()],
                        SeccompAction::Allow,
                    )],
                ),
            ]
            .into_iter()
            .collect(),
            SeccompAction::Trap,
        )
        .unwrap();
        let instructions = vec![
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
            BPF_STMT(0x06, 0x7fff0000),
            BPF_STMT(0x05, 1),
            BPF_STMT(0x05, 7),
            BPF_STMT(0x20, 36),
            BPF_JUMP(0x25, 0, 3, 0),
            BPF_JUMP(0x15, 0, 0, 3),
            BPF_STMT(0x20, 32),
            BPF_JUMP(0x35, 42, 0, 1),
            BPF_STMT(0x06, 0x7fff0000),
            BPF_STMT(0x06, 0x00030000),
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
        ];

        assert_eq!(filter.into_bpf().unwrap(), instructions);
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
            let ret = VALIDATE_ARCHITECTURE();
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
                    k: 0,
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
    fn test_error_messages() {
        assert_eq!(
            format!("{}", Error::EmptyRulesVector),
            "The seccomp rules vector is empty."
        );
        assert_eq!(
            format!("{}", Error::FilterTooLarge),
            "The seccomp filter contains too many BPF instructions."
        );
        assert_eq!(
            format!("{}", Error::IntoBpf),
            "Failed to translate the seccomp rules into BPF."
        );
        assert_eq!(
            format!("{}", Error::InvalidArgumentNumber),
            "The seccomp rule contains an invalid argument number."
        );
        assert_eq!(
            format!("{}", Error::InvalidLevel),
            "The requested seccomp level is invalid."
        );
        assert_eq!(
            format!("{}", Error::Load(42)),
            "Failed to load seccomp rules into the kernel with error 42."
        );
    }

    #[test]
    fn test_from_seccomp_action() {
        assert_eq!(0x7fff0000, u32::from(SeccompAction::Allow));
        assert_eq!(0x0005002a, u32::from(SeccompAction::Errno(42)));
        assert_eq!(0x00000000, u32::from(SeccompAction::Kill));
        assert_eq!(0x7ffc0000, u32::from(SeccompAction::Log));
        assert_eq!(0x7ff0002a, u32::from(SeccompAction::Trace(42)));
        assert_eq!(0x00030000, u32::from(SeccompAction::Trap));
    }
}
