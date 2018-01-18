#[macro_use(crate_version, crate_authors)]
extern crate clap;

extern crate api_server;
extern crate devices;
extern crate sys_util;
extern crate vmm;

use clap::{App, Arg};

use sys_util::syslog;

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
            Arg::with_name("kill_api")
                .long("kill-api")
                .help("Kill the REST API server on vmm exit")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("api_port")
                .short("p")
                .long("api-port")
                .help("The TCP listen port for the REST API")
                .required(true)
                .takes_value(true),
        )
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
                .default_value("console=ttyS0 noapic reboot=k panic=1 pci=off nomodules")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("mem_size")
                .long("mem-size")
                .default_value("128")
                .help("Virtual Machine Memory Size in MiB")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("vcpu_count")
                .long("vcpu-count")
                .default_value("1")
                .help("Number of VCPUs")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("root_blk_file")
                .short("r")
                .long("root-blk")
                .help("File to serve as root block device")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("host_ip")
                .long("host-ip")
                .help("IPv4 address of the host interface")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("subnet_mask")
                .long("subnet-mask")
                .default_value("255.255.255.0")
                .help("Subnet mask for the IP address of host interface")
                .takes_value(true)
        )
        /*
        The mac address option is not currently implemented; the L2 addresses for both the
        host interface and the guest interface take some implicit (possibly random) values
        .arg(
            Arg::with_name("mac_address")
                .long("mac-addr")
                .help("MAC address for the VM")
                .takes_value(true)
        )*/
        .get_matches();

    api_server::start_api_server(&cmd_arguments).expect("cannot start api server");
}
