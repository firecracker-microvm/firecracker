// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright 2021 Sony Group Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

//! Raw FFI bindings for libseccomp library

use std::os::raw::*;

pub const MINUS_EEXIST: i32 = -libc::EEXIST;

/// Filter context/handle (`*mut`)
pub type scmp_filter_ctx = *mut c_void;
/// Filter context/handle (`*const`)
pub type const_scmp_filter_ctx = *const c_void;

/// Comparison operators
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub enum scmp_compare {
    _SCMP_CMP_MIN = 0,
    /// not equal
    SCMP_CMP_NE = 1,
    /// less than
    SCMP_CMP_LT = 2,
    /// less than or equal
    SCMP_CMP_LE = 3,
    /// equal
    SCMP_CMP_EQ = 4,
    /// greater than or equal
    SCMP_CMP_GE = 5,
    /// greater than
    SCMP_CMP_GT = 6,
    /// masked equality
    SCMP_CMP_MASKED_EQ = 7,
    _SCMP_CMP_MAX,
}

/// Argument datum
pub type scmp_datum_t = u64;

/// Argument / Value comparison definition
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct scmp_arg_cmp {
    /// argument number, starting at 0
    pub arg: c_uint,
    /// the comparison op, e.g. `SCMP_CMP_*`
    pub op: scmp_compare,
    pub datum_a: scmp_datum_t,
    pub datum_b: scmp_datum_t,
}

pub const SCMP_ARCH_X86_64: u32 = 0xc000003e;
pub const SCMP_ARCH_AARCH64: u32 = 0xc00000b7;
pub const SCMP_ARCH_RISCV64: u32 = 0xc00000f3;
/// Kill the process
pub const SCMP_ACT_KILL_PROCESS: u32 = 0x80000000;
/// Kill the thread
pub const SCMP_ACT_KILL_THREAD: u32 = 0x00000000;
/// Throw a `SIGSYS` signal
pub const SCMP_ACT_TRAP: u32 = 0x00030000;
/// Notifies userspace
pub const SCMP_ACT_ERRNO_MASK: u32 = 0x00050000;
/// Return the specified error code
#[must_use]
pub const fn SCMP_ACT_ERRNO(x: u16) -> u32 {
    SCMP_ACT_ERRNO_MASK | x as u32
}
pub const SCMP_ACT_TRACE_MASK: u32 = 0x7ff00000;
/// Notify a tracing process with the specified value
#[must_use]
pub const fn SCMP_ACT_TRACE(x: u16) -> u32 {
    SCMP_ACT_TRACE_MASK | x as u32
}
/// Allow the syscall to be executed after the action has been logged
pub const SCMP_ACT_LOG: u32 = 0x7ffc0000;
/// Allow the syscall to be executed
pub const SCMP_ACT_ALLOW: u32 = 0x7fff0000;

#[link(name = "seccomp")]
unsafe extern "C" {
    /// Initialize the filter state
    ///
    /// - `def_action`: the default filter action
    ///
    /// This function initializes the internal seccomp filter state and should
    /// be called before any other functions in this library to ensure the filter
    /// state is initialized.  Returns a filter context on success, `ptr::null()` on failure.
    pub safe fn seccomp_init(def_action: u32) -> scmp_filter_ctx;

    /// Adds an architecture to the filter
    ///
    /// - `ctx`: the filter context
    /// - `arch_token`: the architecture token, e.g. `SCMP_ARCH_*`
    ///
    /// This function adds a new architecture to the given seccomp filter context.
    /// Any new rules added after this function successfully returns will be added
    /// to this architecture but existing rules will not be added to this
    /// architecture.  If the architecture token is [`SCMP_ARCH_NATIVE`] then the native
    /// architecture will be assumed.  Returns zero on success, `-libc::EEXIST` if
    /// specified architecture is already present, other negative values on failure.
    pub fn seccomp_arch_add(ctx: scmp_filter_ctx, arch_token: u32) -> c_int;

    /// Resolve a syscall name to a number
    ///
    /// - `name`: the syscall name
    ///
    /// Resolve the given syscall name to the syscall number.  Returns the syscall
    /// number on success, including negative pseudo syscall numbers (e.g. `__PNR_*`);
    /// returns [`__NR_SCMP_ERROR`] on failure.
    pub fn seccomp_syscall_resolve_name(name: *const c_char) -> c_int;

    /// Add a new rule to the filter
    ///
    /// - `ctx`: the filter context
    /// - `action`: the filter action
    /// - `syscall`: the syscall number
    /// - `arg_cnt`: the number of argument filters in the argument filter chain
    /// - `...`: [`scmp_arg_cmp`] structs
    ///
    /// This function adds a series of new argument/value checks to the seccomp
    /// filter for the given syscall; multiple argument/value checks can be
    /// specified and they will be chained together (AND'd together) in the filter.
    /// If the specified rule needs to be adjusted due to architecture specifics it
    /// will be adjusted without notification.  Returns zero on success, negative
    /// values on failure.
    pub fn seccomp_rule_add(
        ctx: scmp_filter_ctx,
        action: u32,
        syscall: c_int,
        arg_cnt: c_uint,
        ...
    ) -> c_int;

    /// Add a new rule to the filter
    ///
    /// - `ctx`: the filter context
    /// - `action`: the filter action
    /// - `syscall`: the syscall number
    /// - `arg_cnt`: the number of elements in the arg_array parameter
    /// - `arg_array`: array of [`scmp_arg_cmp`] structs
    ///
    /// This function adds a series of new argument/value checks to the seccomp
    /// filter for the given syscall; multiple argument/value checks can be
    /// specified and they will be chained together (AND'd together) in the filter.
    /// If the specified rule needs to be adjusted due to architecture specifics it
    /// will be adjusted without notification.  Returns zero on success, negative
    /// values on failure.
    pub fn seccomp_rule_add_array(
        ctx: scmp_filter_ctx,
        action: u32,
        syscall: c_int,
        arg_cnt: c_uint,
        arg_array: *const scmp_arg_cmp,
    ) -> c_int;

    /// Generate seccomp Berkeley Packet Filter (BPF) code and export it to a file
    ///
    /// - `ctx`: the filter context
    /// - `fd`: the destination fd
    ///
    /// This function generates seccomp Berkeley Packer Filter (BPF) code and writes
    /// it to the given fd.  Returns zero on success, negative values on failure.
    pub fn seccomp_export_bpf(ctx: const_scmp_filter_ctx, fd: c_int) -> c_int;
}

/// Negative pseudo syscall number returned by some functions in case of an error
pub const __NR_SCMP_ERROR: c_int = -1;
