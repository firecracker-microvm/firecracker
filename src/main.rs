#[macro_use(crate_version, crate_authors)]
extern crate clap;

extern crate sys_util;
extern crate vmm;

use std::path::PathBuf;

use clap::{App, Arg};

use sys_util::syslog;
use vmm::boot_kernel;
use vmm::machine::MachineCfg;


fn main() {
    if let Err(e) = syslog::init() {
        println!("failed to initialize syslog: {:?}", e);
        return;
    }

    let cmd_arguments = App::new("firecracker")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Launch a microvm.")
        .arg(
            Arg::with_name("kernel_path")
                .short("k")
                .long("kernel-path")
                .help("The kernel's file path (vmlinux.bin)")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("kernel_cmdline")
                .long("kernel-cmdline")
                .help("The kernel's command line")
                .default_value("console=ttyS0 noapic reboot=k panic=1 pci=off")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("mem_size")
                .long("mem-size")
                .default_value("128")
                .help("Virtual Machine Memory Size in MB")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("vcpu_count")
                .long("vcpu-count")
                .default_value("1")
                .help("Number of VCPUs")
                .takes_value(true),
        )
        .get_matches();

    let kernel_path : Option<PathBuf> = cmd_arguments.value_of("kernel_path").map(|s| PathBuf::from(s));

    let kernel_cmdline = String::from(cmd_arguments.value_of("kernel_cmdline").unwrap());

    let vcpu_count = match cmd_arguments
        .value_of("vcpu_count")
        .unwrap()
        .to_string()
        .parse::<u8>() {
        Ok(value) => value,
        Err(error) => {
            panic!("Invalid value for vcpu_count! {:?}", error);
        }
    };

    let mem_size = match cmd_arguments
        .value_of("mem_size")
        .unwrap()
        .to_string()
        .parse::<usize>() {
        Ok(value) => value,
        Err(error) => {
            panic!("Invalid value for mem_size! {:?}", error);
        }
    };

    let cfg = MachineCfg::new(kernel_path, kernel_cmdline, vcpu_count, mem_size,
                              None , None, "255.255.255.0".parse().unwrap());

    boot_kernel(&cfg).expect("cannot boot kernel");
}
