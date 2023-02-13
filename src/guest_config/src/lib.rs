// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![warn(clippy::pedantic, clippy::restriction)]
#![allow(
    clippy::blanket_clippy_restriction_lints,
    clippy::implicit_return,
    clippy::pattern_type_mismatch,
    clippy::std_instead_of_alloc,
    clippy::std_instead_of_core,
    clippy::pub_use,
    clippy::non_ascii_literal,
    clippy::single_char_lifetime_names,
    clippy::exhaustive_enums,
    clippy::exhaustive_structs,
    clippy::unseparated_literal_suffix,
    clippy::mod_module_files,
    clippy::missing_trait_methods,
    clippy::unsafe_derive_deserialize,
    clippy::unreadable_literal,
    clippy::similar_names,
    clippy::same_name_method,
    clippy::doc_markdown,
    clippy::module_name_repetitions
)]

//! Crate defined to encapsulate configuration of the
//! Firecracker guest/microvm.
//!
//! Initial purpose is for CPU configuration but can be considered for extension
//! into other aspects.

#[cfg(target_arch = "x86_64")]
/// AMD CPUID specification handling.
pub mod amd;

#[cfg(target_arch = "x86_64")]
/// Functionality to support CPUID management.
pub mod cpuid;

#[cfg(target_arch = "x86_64")]
/// Intel CPUID specification handling.
pub mod intel;
