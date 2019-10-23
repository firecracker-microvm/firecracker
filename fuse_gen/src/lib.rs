// Copyright 2019 UCloud.cn, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::all)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

extern crate memory_model;

// bindgen  --with-derive-default  ./include/uapi/linux/fuse.h
pub mod fuse;

mod wrapper;
