// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate memory_model;

#[allow(clippy::all)]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod x86;
