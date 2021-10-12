// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use utils::fam::{FamStruct, FamStructWrapper};
use utils::generate_fam_struct_impl;

use crate::bindings::{io_uring_probe, io_uring_probe_op};

// There is no max for the number of operations returned by probing. So we fallback to using the
// number of values representable in a u8;
pub const PROBE_LEN: usize = u8::MAX as usize + 1;

generate_fam_struct_impl!(
    io_uring_probe,
    io_uring_probe_op,
    ops,
    u8,
    ops_len,
    PROBE_LEN
);

pub type ProbeWrapper = FamStructWrapper<io_uring_probe>;
