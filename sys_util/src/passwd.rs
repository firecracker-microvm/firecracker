// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Wrappers for passwd and group file access.

use std::ffi::CStr;
use std::mem;
use std::ptr;

use libc;
use libc::{c_char, getgrnam_r, getpwnam_r, gid_t, uid_t};

use {errno_result, Result};

/// Safe wrapper for getting a uid from a user name with `getpwnam_r(3)`.
#[inline(always)]
pub fn get_user_id(user_name: &CStr) -> Result<uid_t> {
    // libc::passwd is a C struct and can be safely initialized with zeroed memory.
    let mut passwd: libc::passwd = unsafe { mem::zeroed() };
    let mut passwd_result: *mut libc::passwd = ptr::null_mut();
    let mut buf = [0 as c_char; 256];

    // For thread-safety, use the reentrant version of this function. This allows us to give it a
    // buffer on the stack (instead of a global buffer). Unlike most libc functions, the return
    // value of this doesn't really need to be checked, since the extra result pointer that is
    // passed in indicates whether or not the function succeeded.
    //
    // This call is safe as long as it behaves as described in the man page. We pass in valid
    // pointers to stack-allocated buffers, and the length check for the scratch buffer is correct.
    unsafe {
        handle_eintr!(getpwnam_r(
            user_name.as_ptr(),
            &mut passwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut passwd_result,
        ))
    };

    if passwd_result.is_null() {
        errno_result()
    } else {
        Ok(passwd.pw_uid)
    }
}

/// Safe wrapper for getting a gid from a group name with `getgrnam_r(3)`.
#[inline(always)]
pub fn get_group_id(group_name: &CStr) -> Result<gid_t> {
    // libc::group is a C struct and can be safely initialized with zeroed memory.
    let mut group: libc::group = unsafe { mem::zeroed() };
    let mut group_result: *mut libc::group = ptr::null_mut();
    let mut buf = [0 as c_char; 256];

    // For thread-safety, use the reentrant version of this function. This allows us to give it a
    // buffer on the stack (instead of a global buffer). Unlike most libc functions, the return
    // value of this doesn't really need to be checked, since the extra result pointer that is
    // passed in indicates whether or not the function succeeded.
    //
    // This call is safe as long as it behaves as described in the man page. We pass in valid
    // pointers to stack-allocated buffers, and the length check for the scratch buffer is correct.
    unsafe {
        handle_eintr!(getgrnam_r(
            group_name.as_ptr(),
            &mut group,
            buf.as_mut_ptr(),
            buf.len(),
            &mut group_result,
        ))
    };

    if group_result.is_null() {
        errno_result()
    } else {
        Ok(group.gr_gid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_good_uid() {
        let root_name = CStr::from_bytes_with_nul(b"root\0").unwrap();

        // root's uid should always exist, and should be 0.
        let root_uid = get_user_id(root_name).unwrap();
        assert_eq!(root_uid, 0);
    }

    #[test]
    fn get_bad_uid() {
        let bad_name = CStr::from_bytes_with_nul(b"this better not be a user\0").unwrap();

        // This user should give us an error. As a cruel joke, the getpwnam(3) man page allows
        // ENOENT, ESRCH, EBADF, EPERM, or even 0 to be set in errno if a user isn't found. So
        // instead of checking which error we got, just see that we did get one.
        let bad_uid_result = get_user_id(bad_name);
        assert!(bad_uid_result.is_err());
    }

    #[test]
    fn get_good_gid() {
        let root_name = CStr::from_bytes_with_nul(b"root\0").unwrap();

        // root's gid should always exist, and should be 0.
        let root_gid = get_group_id(root_name).unwrap();
        assert_eq!(root_gid, 0);
    }

    #[test]
    fn get_bad_gid() {
        let bad_name = CStr::from_bytes_with_nul(b"this better not be a group\0").unwrap();

        // This group should give us an error. As a cruel joke, the getgrnam(3) man page allows
        // ENOENT, ESRCH, EBADF, EPERM, or even 0 to be set in errno if a group isn't found. So
        // instead of checking which error we got, just see that we did get one.
        let bad_gid_result = get_group_id(bad_name);
        assert!(bad_gid_result.is_err());
    }
}
