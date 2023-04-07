// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Follows a C3 template in setting up the CPUID.
pub mod c3;
/// Follows a T2 template in setting up the CPUID.
pub mod t2;
/// Follows a T2 template in setting up the CPUID.
/// Also explicitly configures IA32_ARCH_CAPABILITIES MSR.
pub mod t2cl;
/// Follows a T2 template for setting up the CPUID with additional MSRs
/// that are speciffic to an Intel Skylake CPU.
pub mod t2s;
