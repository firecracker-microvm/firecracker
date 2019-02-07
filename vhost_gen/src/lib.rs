// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

#![allow(clippy::all)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#[macro_use]
extern crate sys_util;

pub mod vhost;
pub use vhost::*;

pub const VHOST: ::std::os::raw::c_uint = 0xaf;

ioctl_ior_nr!(VHOST_GET_FEATURES, VHOST, 0x00, ::std::os::raw::c_ulonglong);
ioctl_iow_nr!(VHOST_SET_FEATURES, VHOST, 0x00, ::std::os::raw::c_ulonglong);
ioctl_io_nr!(VHOST_SET_OWNER, VHOST, 0x01);
ioctl_iow_nr!(VHOST_SET_MEM_TABLE, VHOST, 0x03, vhost_memory);
ioctl_iow_nr!(VHOST_SET_VRING_NUM, VHOST, 0x10, vhost_vring_state);
ioctl_iow_nr!(VHOST_SET_VRING_ADDR, VHOST, 0x11, vhost_vring_addr);
ioctl_iow_nr!(VHOST_SET_VRING_BASE, VHOST, 0x12, vhost_vring_state);
ioctl_iowr_nr!(VHOST_GET_VRING_BASE, VHOST, 0x12, vhost_vring_state);
ioctl_iow_nr!(VHOST_SET_VRING_KICK, VHOST, 0x20, vhost_vring_file);
ioctl_iow_nr!(VHOST_SET_VRING_CALL, VHOST, 0x21, vhost_vring_file);
ioctl_iow_nr!(
    VHOST_VSOCK_SET_GUEST_CID,
    VHOST,
    0x60,
    ::std::os::raw::c_ulonglong
);
ioctl_iow_nr!(VHOST_VSOCK_SET_RUNNING, VHOST, 0x61, ::std::os::raw::c_int);
