/// Machine configuration specifics

use std::path::Path;
use std::fs::File;
use std::io;
use clap::ArgMatches;

pub struct MachineCfg {
    kernel_fd: Option<File>,
    kernel_cmdline: Option<String>,
}

impl MachineCfg {
    pub fn new() -> Self {
        MachineCfg {
            kernel_fd: None,
            kernel_cmdline: Some(String::from(
                "console=ttyS0,115200n8 init=/init tsc=reliable no_timer_check cryptomgr.notests",
            )),
        }
    }

    pub fn populate(&mut self, matches: ArgMatches) -> Result<(), io::Error> {
        if let Some(value) = matches.value_of("kernel") {
            let path = Path::new(value);
            self.kernel_fd = Some(File::open(&path)?);
        }

        if let Some(value) = matches.value_of("kernel_cmdline") {
            self.kernel_cmdline = Some(String::from(value));
        }

        Ok(())
    }

    pub fn kernel_fd(&self) -> &Option<File> {
        &self.kernel_fd
    }

    pub fn kernel_cmdline(&self) -> &Option<String> {
        &self.kernel_cmdline
    }

}
