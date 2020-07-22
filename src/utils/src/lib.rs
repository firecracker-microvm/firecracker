// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate vmm_sys_util;

// We use `utils` as a wrapper over `vmm_sys_util` to control the latter
// dependency easier (i.e. update only in one place `vmm_sys_util` version).
// More specifically, we are re-exporting modules from `vmm_sys_util` as part
// of the `utils` crate.
pub use vmm_sys_util::{
    epoll, errno, eventfd, fam, ioctl, rand, syscall, tempdir, tempfile, terminal,
};
pub use vmm_sys_util::{ioctl_expr, ioctl_ioc_nr, ioctl_iow_nr};

pub mod arg_parser;
pub mod byte_order;
pub mod net;
pub mod signal;
pub mod sm;
pub mod structs;
pub mod time;
pub mod validators;
