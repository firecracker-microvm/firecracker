// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

extern crate kvm_sys;
extern crate libc;
extern crate sys_util;

use kvm_sys::*;
use libc::{c_char, open, O_RDWR};
use std::fs::File;
use std::os::unix::io::FromRawFd;
use sys_util::{ioctl, ioctl_with_val};

const KVM_PATH: &'static str = "/dev/kvm\0";

#[test]
fn get_version() {
    let sys_fd = unsafe { open(KVM_PATH.as_ptr() as *const c_char, O_RDWR) };
    assert!(sys_fd >= 0);

    let ret = unsafe { ioctl(&File::from_raw_fd(sys_fd), KVM_GET_API_VERSION()) };
    assert_eq!(ret as u32, KVM_API_VERSION);
}

#[test]
fn create_vm_fd() {
    let sys_fd = unsafe { open(KVM_PATH.as_ptr() as *const c_char, O_RDWR) };
    assert!(sys_fd >= 0);

    let vm_fd = unsafe { ioctl(&File::from_raw_fd(sys_fd), KVM_CREATE_VM()) };
    assert!(vm_fd >= 0);
}

#[test]
fn check_vm_extension() {
    let sys_fd = unsafe { open(KVM_PATH.as_ptr() as *const c_char, O_RDWR) };
    assert!(sys_fd >= 0);

    let has_user_memory = unsafe {
        ioctl_with_val(
            &File::from_raw_fd(sys_fd),
            KVM_CHECK_EXTENSION(),
            KVM_CAP_USER_MEMORY.into(),
        )
    };
    assert_eq!(has_user_memory, 1);
}
