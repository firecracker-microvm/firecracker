#[macro_use(crate_version, crate_authors)]
extern crate clap;
extern crate vmm;

use clap::{App, Arg};
use vmm::boot_kernel;
use vmm::machine::MachineCfg;


fn main() {
    let matches = App::new("firecracker")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Launch a microvm.")
        .arg(Arg::with_name("kernel_path")
            .short("k")
            .long("kernel-path")
            .help("The kernel's file path (vmlinux.bin)")
            .required(true)
            .takes_value(true))
        .arg(Arg::with_name("kernel_cmdline")
            .long("kernel-cmdline")
            .help("The kernel's command line")
            .takes_value(true))
        .get_matches();

    let mut cfg = MachineCfg::new();
    cfg.populate(matches).expect("parsing arguments failed");

    boot_kernel(&cfg).ok().expect("cannot boot kernel");
}
