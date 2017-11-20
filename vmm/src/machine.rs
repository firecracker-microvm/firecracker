/// Machine configuration specifics

use std::io;
use std::path::PathBuf;

use clap::ArgMatches;

pub struct MachineCfg {
    pub kernel_path: Option<PathBuf>,
    pub kernel_cmdline: Option<String>,
}

impl MachineCfg {
    pub fn new() -> Self {
        MachineCfg {
            kernel_path: None,
            kernel_cmdline: Some(String::from(
                "console=ttyS0 noapic noacpi reboot=k panic=1 pci=off",
            )),
        }
    }

    pub fn populate(&mut self, matches: ArgMatches) -> io::Result<()> {
        if let Some(value) = matches.value_of("kernel_path") {
            self.kernel_path = Some(PathBuf::from(value));
        }

        if let Some(value) = matches.value_of("kernel_cmdline") {
            self.kernel_cmdline = Some(String::from(value));
        }

        Ok(())
    }
}
