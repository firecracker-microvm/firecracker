// Copyright 2019 UCloud.cn, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use libc::stat as FileStat;
use libc::statvfs as Statvfs;
use libc::{self, c_char, c_int, c_uchar, dev_t, dirent, gid_t, mode_t, uid_t, DIR};

use std::mem::MaybeUninit;
use std::os::unix::io::RawFd;

use std::ffi::{CStr, CString};

use std::fmt::{self, Debug};
use std::{io, mem, ptr, result};

type Result<T> = result::Result<T, io::Error>;

pub struct Dir(*mut DIR);

unsafe impl Send for Dir {}

impl Dir {
    pub fn openat(raw_fd: RawFd, name: Option<&CStr>, flag: c_int) -> Result<Self> {
        let dot_cstr = unsafe { CStr::from_bytes_with_nul_unchecked(b".\0") };
        let name_c = name.unwrap_or(dot_cstr).as_ptr();
        let ret = unsafe { libc::openat(raw_fd, name_c, flag) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Dir::from_fd(ret)
        }
    }

    fn from_fd(fd: RawFd) -> Result<Self> {
        let d = unsafe { libc::fdopendir(fd) };
        if d.is_null() {
            let e = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(e);
        };
        Ok(Dir(d))
    }

    pub fn iter(&mut self) -> Iter {
        Iter(self)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        unsafe { libc::closedir(self.0) };
    }
}

pub struct Iter<'d>(&'d mut Dir);

impl<'d> Iterator for Iter<'d> {
    type Item = Result<Entry>;

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            let mut ret = Entry(mem::zeroed());
            let mut entry_ptr = ptr::null_mut();
            if libc::readdir_r((self.0).0, &mut ret.0, &mut entry_ptr) != 0 {
                return Some(Err(io::Error::last_os_error()));
            }
            if entry_ptr.is_null() {
                return None;
            }
            Some(Ok(ret))
        }
    }
}

impl<'d> Drop for Iter<'d> {
    fn drop(&mut self) {
        unsafe { libc::rewinddir((self.0).0) }
    }
}

pub struct Entry(dirent);

impl Entry {
    pub fn ino(&self) -> u64 {
        self.0.d_ino as u64
    }

    pub fn file_name(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.0.d_name.as_ptr()) }
    }

    pub fn file_type(&self) -> c_uchar {
        self.0.d_type
    }

    pub fn off(&self) -> i64 {
        self.0.d_off
    }
}

impl Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Entry")
            .field("ino", &self.ino())
            .field("type", &self.file_type())
            .field("name", &self.file_name())
            .field("off", &self.off())
            .finish()
    }
}

macro_rules! libc_result {
    ($callback:expr) => {{
        let ret = $callback;
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }};
}

pub fn mknodat(dirfd: RawFd, name: &CStr, mode: mode_t, dev: dev_t) -> Result<()> {
    libc_result!(unsafe { libc::mknodat(dirfd, name.as_ptr(), mode, dev) })
}

pub fn mkdirat(dirfd: RawFd, name: &CStr, mode: mode_t) -> Result<()> {
    libc_result!(unsafe { libc::mkdirat(dirfd, name.as_ptr(), mode) })
}

pub fn fchmod(dirfd: RawFd, mode: mode_t) -> Result<()> {
    libc_result!(unsafe { libc::fchmod(dirfd, mode) })
}

pub fn fchown(dirfd: RawFd, owner: uid_t, group: gid_t) -> Result<()> {
    libc_result!(unsafe { libc::fchown(dirfd, owner, group) })
}

pub fn unlinkat(dirfd: RawFd, name: &CStr, flag: c_int) -> Result<()> {
    libc_result!(unsafe { libc::unlinkat(dirfd, name.as_ptr(), flag) })
}

pub fn symlinkat(dirfd: RawFd, linkpath: &CStr, target: &CStr) -> Result<()> {
    libc_result!(unsafe { libc::symlinkat(target.as_ptr(), dirfd, linkpath.as_ptr()) })
}

pub fn readlinkat(dirfd: RawFd, name: Option<&CStr>) -> Result<CString> {
    let name_c = name.unwrap_or(Default::default()).as_ptr();
    let mut buf = Vec::with_capacity(libc::PATH_MAX as usize);
    let ret = unsafe {
        libc::readlinkat(
            dirfd,
            name_c,
            buf.as_mut_ptr() as *mut c_char,
            buf.capacity(),
        )
    };

    if ret < 0 {
        Err(io::Error::last_os_error())
    } else if ret as c_int >= libc::PATH_MAX {
        Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG))
    } else {
        // It's safe because the size of buf has been checked
        unsafe {
            buf.set_len(ret as usize);
            Ok(CString::from_vec_unchecked(buf))
        }
    }
}

pub fn fstatat(dirfd: RawFd, name: Option<&CStr>, flag: c_int) -> Result<FileStat> {
    let name_c = name.unwrap_or(Default::default()).as_ptr();
    let mut buf = MaybeUninit::<FileStat>::uninit();
    let ret = unsafe { libc::fstatat(dirfd, name_c, buf.as_mut_ptr(), flag) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        // It's safe because buf has been initialiezed.
        unsafe { Ok(buf.assume_init()) }
    }
}

pub fn fstatvfs(dirfd: RawFd) -> Result<Statvfs> {
    let mut buf = MaybeUninit::<Statvfs>::uninit();
    let ret = unsafe { libc::fstatvfs(dirfd, buf.as_mut_ptr()) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        // It's safe because buf has been initialiezed.
        unsafe { Ok(buf.assume_init()) }
    }
}

pub fn openat(dirfd: RawFd, name: Option<&CStr>, flag: c_int) -> Result<RawFd> {
    let name_c = name.unwrap_or(Default::default()).as_ptr();
    let ret = unsafe { libc::openat(dirfd, name_c, flag) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as RawFd)
    }
}

pub fn open(name: &CStr, flag: c_int) -> Result<RawFd> {
    let ret = unsafe { libc::open(name.as_ptr(), flag) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as RawFd)
    }
}

pub fn close(fd: RawFd) -> Result<()> {
    libc_result!(unsafe { libc::close(fd) })
}

struct Cred {
    euid: uid_t,
    egid: gid_t,
}

impl Cred {
    fn change_to(euid: uid_t, egid: gid_t) -> Result<Cred> {
        let saved = unsafe {
            Cred {
                euid: libc::getuid(),
                egid: libc::getgid(),
            }
        };

        let ret = unsafe { libc::setegid(egid) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        let ret = unsafe { libc::seteuid(euid) };
        if ret < 0 {
            let saved_err = io::Error::last_os_error();
            unsafe { libc::setegid(saved.egid) };
            return Err(saved_err);
        }
        Ok(saved)
    }

    fn restore(&self) -> Result<()> {
        libc_result!(unsafe { libc::seteuid(self.euid) })?;
        libc_result!(unsafe { libc::setegid(self.egid) })
    }
}

pub fn with_cred<F>(uid: uid_t, gid: gid_t, f: F) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    let saved_cred = Cred::change_to(uid, gid)?;
    let ret = f();
    saved_cred.restore().unwrap();
    ret
}
