#[macro_use(crate_version, crate_authors)]
extern crate clap;

extern crate api_server;
extern crate devices;
extern crate sys_util;
extern crate vmm;

use clap::{App, Arg, SubCommand};
use std::fs::File;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::sync::mpsc::Receiver;

use api_server::{ApiRequest, ApiServer};
use sys_util::{syslog, EventFd, GuestAddress};
use vmm::{CMDLINE_MAX_SIZE, CMDLINE_OFFSET, KERNEL_START_OFFSET};
use vmm::{kernel_cmdline, KernelConfig};
use vmm::machine::{MachineCfg, DEFAULT_SUBNET_MASK};
use vmm::device_config::BlockDeviceConfig;

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
            Arg::with_name("api_sock")
                .long("api-sock")
                .help("Path to unix domain socket used by the API")
                .default_value("/tmp/firecracker.socket")
                .takes_value(true),
        )
        .subcommand(
            SubCommand::with_name("vmm-no-api")
                .about("Start vmm without an API thread")
                .arg(
                    Arg::with_name("kernel_path")
                        .short("k")
                        .long("kernel-path")
                        .help("The kernel's file path (vmlinux.bin)")
                        .takes_value(true)
                        .required(true),
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
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("tap_dev_name")
                        .long("tap-dev-name")
                        .help("Name of existing TAP interface to use for guest Virtio net device")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("subnet_mask")
                        .long("subnet-mask")
                        .default_value(DEFAULT_SUBNET_MASK)
                        .help("Subnet mask for the IP address of host interface")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("vsock_guest_cid")
                        .long("vsock-guest-cid")
                        .help("The guest CID for the virtio-vhost-vsock device")
                        .takes_value(true),
                ),
        )
        .get_matches();

    let (to_vmm, from_api) = channel();

    // TODO: vmm_no_api is for integration testing, need to find a more pretty solution
    match cmd_arguments.subcommand {
        Some(_) => {
            vmm_no_api_handler(
                cmd_arguments.subcommand_matches("vmm-no-api").unwrap(),
                from_api,
            );
        }
        None => {
            // safe to unwrap since api_sock has a default value
            let bind_path = cmd_arguments
                .value_of("api_sock")
                .map(|s| PathBuf::from(s))
                .unwrap();

            let server = ApiServer::new(to_vmm, 100).unwrap();
            let api_event_fd = server
                .get_event_fd_clone()
                .expect("cannot clone API eventFD");
            // vmm thread should not need a MachineCfg, will give the default for the moment
            // and remove it later on
            let _vmm_thread_handle =
                vmm::start_vmm_thread(MachineCfg::default(), api_event_fd, from_api);
            server.bind_and_run(bind_path).unwrap();
        }
    }
}

fn vmm_no_api_handler(cmd_arguments: &clap::ArgMatches, from_api: Receiver<Box<ApiRequest>>) {
    let cfg = parse_args(&cmd_arguments);

    let mut vmm = vmm::Vmm::new(
        cfg,
        EventFd::new().expect("cannot create eventFD"),
        from_api,
    ).expect("cannot create VMM");

    // configure virtual machine from command line
    if cmd_arguments.is_present("vcpu_count") {
        match cmd_arguments
            .value_of("vcpu_count")
            .unwrap()
            .to_string()
            .parse::<u8>()
        {
            Ok(vcpu_count) => {
                vmm.put_virtual_machine_configuration(Some(vcpu_count), None)
                    .expect("Invalid value for vcpu_count");
            }
            Err(error) => {
                panic!("Invalid value for vcpu_count! {:?}", error);
            }
        };
    }
    if cmd_arguments.is_present("mem_size") {
        match cmd_arguments
            .value_of("mem_size")
            .unwrap()
            .to_string()
            .parse::<usize>()
        {
            Ok(mem_size_mib) => {
                vmm.put_virtual_machine_configuration(None, Some(mem_size_mib))
                    .expect("Invalid value for mem_size!");
            }
            Err(error) => {
                panic!("Invalid value for mem_size! {:?}", error);
            }
        }
    }

    // This is a temporary fix. Block devices should be added via http requests.
    // With the command line, we can only add one device, with default to root block device.
    if cmd_arguments.is_present("root_blk_file") {
        let root_block_device = BlockDeviceConfig {
            path_on_host: PathBuf::from(cmd_arguments.value_of("root_blk_file").unwrap()),
            is_root_device: true,
            drive_id: String::from("1"),
        };
        vmm.put_block_device(root_block_device)
            .expect("cannot add root block device.");
    }

    if let Some(value) = cmd_arguments.value_of("tap_dev_name") {
        let host_dev_name = String::from(value);

        use api_server::request::sync::DeviceState;
        use api_server::request::sync::NetworkInterfaceBody;

        let body = NetworkInterfaceBody {
            iface_id: String::from("0"),
            state: DeviceState::Attached,
            host_dev_name,
            guest_mac: None,
        };

        vmm.put_net_device(body).expect("failed adding net device.");
    }

    // configure kernel from command line
    //we're using unwrap here because the kernel_path is mandatory for now
    let kernel_file = File::open(cmd_arguments.value_of("kernel_path").unwrap_or_default())
        .expect("Cannot open kernel file");

    let mut cmdline = kernel_cmdline::Cmdline::new(CMDLINE_MAX_SIZE);
    cmdline
        .insert_str(cmd_arguments.value_of("kernel_cmdline").unwrap())
        .expect("could not use the specified kernel cmdline");
    let kernel_config = KernelConfig {
        cmdline,
        kernel_file,
        kernel_start_addr: GuestAddress(KERNEL_START_OFFSET),
        cmdline_addr: GuestAddress(CMDLINE_OFFSET),
    };
    vmm.configure_kernel(kernel_config);
    vmm.boot_kernel().expect("cannot boot kernel");
    vmm.run_control().expect("VMM loop error!");
}

fn parse_args(cmd_arguments: &clap::ArgMatches) -> MachineCfg {
    let root_blk_file = cmd_arguments
        .value_of("root_blk_file")
        .map(|s| PathBuf::from(s));

    let vsock_guest_cid = match cmd_arguments.value_of("vsock_guest_cid") {
        Some(cid) => match cid.parse::<u64>() {
            Ok(value) => Some(value),
            Err(error) => {
                panic!(
                    "Invalid parameter value for the vsock's guest CID! {:?}",
                    error
                );
            }
        },
        None => None,
    };

    // host_ip; no longer used; remove when refactoring MachineCfg
    let host_ip: Option<Ipv4Addr> = Some("1.2.3.4".parse().unwrap());
    // subnet_mask; no longer used; remove when refactoring MachineCfg
    let subnet_mask: Ipv4Addr = "255.255.255.0".parse().unwrap();

    MachineCfg::new(root_blk_file, host_ip, subnet_mask, vsock_guest_cid)
}
