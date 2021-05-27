// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_arch = "aarch64")]
use libc::{c_char, c_int, c_void};

// This links to libfdt which handles the creation of the binary blob
// flattened device tree (fdt) that is passed to the kernel and indicates
// the hardware configuration of the machine.
#[cfg(target_arch = "aarch64")]
extern "C" {
    pub fn fdt_create(buf: *mut c_void, bufsize: c_int) -> c_int;
    pub fn fdt_finish_reservemap(fdt: *mut c_void) -> c_int;
    pub fn fdt_begin_node(fdt: *mut c_void, name: *const c_char) -> c_int;
    pub fn fdt_property(
        fdt: *mut c_void,
        name: *const c_char,
        val: *const c_void,
        len: c_int,
    ) -> c_int;
    pub fn fdt_end_node(fdt: *mut c_void) -> c_int;
    pub fn fdt_open_into(fdt: *const c_void, buf: *mut c_void, bufsize: c_int) -> c_int;
    pub fn fdt_finish(fdt: *const c_void) -> c_int;
    pub fn fdt_pack(fdt: *mut c_void) -> c_int;
}
