// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::ffi::CString;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::path::Path;
use std::path::PathBuf;

use libc;

use {errno_result, Result};

/// Create and remove a temporary directory.  The directory will be maintained for the lifetime of
/// the `TempDir` object.
pub struct TempDir {
    path: Option<PathBuf>,
}

impl TempDir {
    /// Creates a new temporary directory.
    /// The directory will be removed when the object goes out of scope.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::path::Path;
    /// # use std::path::PathBuf;
    /// # use sys_util::TempDir;
    /// # fn test_create_temp_dir() -> Result<(), ()> {
    ///       let t = TempDir::new("/tmp/testdir").map_err(|_| ())?;
    ///       assert!(t.as_path().unwrap().exists());
    /// #     Ok(())
    /// # }
    /// ```
    pub fn new<P: AsRef<OsStr>>(prefix: P) -> Result<TempDir> {
        let mut dir_string = prefix.as_ref().to_os_string();
        dir_string.push("XXXXXX");
        // unwrap this result as the internal bytes can't have a null with a valid path.
        let dir_name = CString::new(dir_string.into_vec()).unwrap();
        let mut dir_bytes = dir_name.into_bytes_with_nul();
        let ret = unsafe {
            // Creating the directory isn't unsafe.  The fact that it modifies the guts of the path
            // is also OK because it only overwrites the last 6 Xs added above.
            libc::mkdtemp(dir_bytes.as_mut_ptr() as *mut libc::c_char)
        };
        if ret.is_null() {
            return errno_result();
        }
        dir_bytes.pop(); // Remove the null becasue from_vec can't handle it.
        Ok(TempDir {
            path: Some(PathBuf::from(OsString::from_vec(dir_bytes))),
        })
    }

    /// Removes the temporary directory.  Calling this is optional as dropping a `TempDir` object
    /// will also remove the directory.  Calling remove explicitly allows for better error handling.
    pub fn remove(mut self) -> Result<()> {
        let path = self.path.take();
        path.map_or(Ok(()), |ref p| fs::remove_dir_all(p))?;
        Ok(())
    }

    /// Returns the path to the tempdir if it is currently valid
    pub fn as_path(&self) -> Option<&Path> {
        self.path.as_ref().map(|ref p| p.as_path())
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if let Some(ref p) = self.path {
            // Nothing can be done here if this returns an error.
            let _ = fs::remove_dir_all(p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_dir() {
        let t = TempDir::new("/tmp/asdf").unwrap();
        let path = t.as_path().unwrap();
        assert!(path.exists());
        assert!(path.is_dir());
        assert!(path.starts_with("/tmp/"));
    }

    #[test]
    fn remove_dir() {
        let t = TempDir::new("/tmp/asdf").unwrap();
        let path = t.as_path().unwrap().to_owned();
        assert!(t.remove().is_ok());
        assert!(!path.exists());
    }
}
