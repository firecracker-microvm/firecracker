use libc::c_int;
pub use vmm_sys_util::signal::*;

extern "C" {
    fn __libc_current_sigrtmin() -> c_int;
    fn __libc_current_sigrtmax() -> c_int;
}

pub fn sigrtmin() -> c_int {
    unsafe { __libc_current_sigrtmin() }
}

pub fn sigrtmax() -> c_int {
    unsafe { __libc_current_sigrtmax() }
}
