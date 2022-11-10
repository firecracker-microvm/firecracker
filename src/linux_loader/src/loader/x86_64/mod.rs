// Copyright (c) 2019 Intel Corporation. All rights reserved.
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! Traits and structs for loading `x86_64` kernels into guest memory.

#![cfg(any(target_arch = "x86", target_arch = "x86_64"))]

#[cfg(feature = "elf")]
pub mod elf;

#[cfg(feature = "bzimage")]
pub mod bzimage;
