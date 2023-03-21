// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// We use `utils` as a wrapper over `vmm_sys_util` to control the latter
// dependency easier (i.e. update only in one place `vmm_sys_util` version).
// More specifically, we are re-exporting modules from `vmm_sys_util` as part
// of the `utils` crate.
pub use vmm_sys_util::ioctl::ioctl_expr;
pub use vmm_sys_util::{
    epoll, errno, eventfd, fam, generate_fam_struct_impl, ioctl, ioctl_ioc_nr, ioctl_iow_nr, rand,
    seek_hole, sock_ctrl_msg, syscall, tempdir, tempfile, terminal,
};

pub mod arg_parser;
pub mod byte_order;
pub mod kernel_version;
pub mod net;
pub mod signal;
pub mod sm;
pub mod time;
pub mod validators;
pub mod vm_memory;

use std::result::Result;

/// Return the default page size of the platform, in bytes.
pub fn get_page_size() -> Result<usize, errno::Error> {
    // SAFETY: Safe because the parameters are valid.
    match unsafe { libc::sysconf(libc::_SC_PAGESIZE) } {
        -1 => Err(errno::Error::last()),
        ps => Ok(usize::try_from(ps).unwrap()),
    }
}
