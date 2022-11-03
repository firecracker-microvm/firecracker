// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![warn(clippy::ptr_as_ptr)]
#![warn(clippy::cast_precision_loss)]

// We use `utils` as a wrapper over `vmm_sys_util` to control the latter
// dependency easier (i.e. update only in one place `vmm_sys_util` version).
// More specifically, we are re-exporting modules from `vmm_sys_util` as part
// of the `utils` crate.
pub use vmm_sys_util::{
    epoll, errno, eventfd, fam, generate_fam_struct_impl, ioctl, ioctl_expr, ioctl_ioc_nr,
    ioctl_iow_nr, rand, seek_hole, sock_ctrl_msg, syscall, tempdir, tempfile, terminal,
};

pub mod arg_parser;
pub mod byte_order;
pub mod kernel_version;
pub mod net;
pub mod signal;
pub mod sm;
pub mod time;
pub mod validators;

use std::result::Result;

/// Return the default page size of the platform, in bytes.
pub fn get_page_size() -> Result<usize, errno::Error> {
    match unsafe { libc::sysconf(libc::_SC_PAGESIZE) } {
        -1 => Err(errno::Error::last()),
        ps => Ok(ps as usize),
    }
}

// The below fucntions will get merged in rust-vmm function once we will upstream it there
fn xor_pseudo_rng_u8_bytes(rand_fn: &dyn Fn() -> u32) -> Vec<u8> {
    let mut r = vec![];

    for n in &rand_fn().to_ne_bytes() {
        r.push(*n);
    }
    r
}

fn rand_bytes_impl(rand_fn: &dyn Fn() -> u32, len: usize) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let mut done = 0;
    loop {
        for n in xor_pseudo_rng_u8_bytes(rand_fn) {
            done += 1;
            buf.push(n);
            if done >= len {
                return buf;
            }
        }
    }
}

/// Get a pseudo random vector of length `len` with bytes.
pub fn rand_bytes(len: usize) -> Vec<u8> {
    rand_bytes_impl(&rand::xor_psuedo_rng_u32, len)
}
