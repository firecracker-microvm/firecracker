#[macro_use]
extern crate vmm_sys_util;
use std::os::raw::c_int;
pub use vmm_sys_util::{errno, eventfd, ioctl, signal, terminal};

/// Wrapper to interpret syscall exit codes and provide a rustacean `io::Result`
pub struct SyscallReturnCode(pub c_int);
impl SyscallReturnCode {
    /// Returns the last OS error if value is -1 or Ok(value) otherwise.
    pub fn into_result(self) -> std::io::Result<c_int> {
        if self.0 == -1 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(self.0)
        }
    }

    /// Returns the last OS error if value is -1 or Ok(()) otherwise.
    pub fn into_empty_result(self) -> std::io::Result<()> {
        self.into_result().map(|_| ())
    }
}

pub mod net;
pub mod rand;
pub mod structs;
pub mod time;
pub mod validators;
