/// Machine configuration specifics

use std::path::PathBuf;
use std::ffi::CString;

pub struct MachineCfg {
    pub kernel_path: PathBuf,
    pub kernel_cmdline: CString,
    pub vcpu_count: u8,
    pub mem_size: usize,
}

impl MachineCfg {
    pub fn new(
        kernel_path: PathBuf,
        kernel_cmdline: CString,
        vcpu_count: u8,
        mem_size: usize,
    ) -> Self {
        MachineCfg {
            kernel_path,
            kernel_cmdline,
            vcpu_count,
            mem_size,
        }
    }
}
