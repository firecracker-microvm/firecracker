// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub mod bootparam;
#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
pub mod mpspec;
#[allow(non_upper_case_globals)]
pub mod msr_index;

// `boot_params` is just a series of ints, it is safe to initialize it.
unsafe impl memory_model::DataInit for bootparam::boot_params {}
// These `mpspec` types are only data, reading them from data is a safe initialization.
unsafe impl memory_model::DataInit for mpspec::mpc_bus {}
unsafe impl memory_model::DataInit for mpspec::mpc_cpu {}
unsafe impl memory_model::DataInit for mpspec::mpc_intsrc {}
unsafe impl memory_model::DataInit for mpspec::mpc_ioapic {}
unsafe impl memory_model::DataInit for mpspec::mpc_table {}
unsafe impl memory_model::DataInit for mpspec::mpc_lintsrc {}
unsafe impl memory_model::DataInit for mpspec::mpf_intel {}
