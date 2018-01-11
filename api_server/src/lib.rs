extern crate clap;
extern crate futures;
extern crate iron;

extern crate api;
extern crate vmm;

use futures::Future;

use api::*;

#[derive(Copy, Clone)]
pub struct Server;

impl Api for Server {
    /// Applies limiter 'limiter_id' to drive 'drive_id'
    fn apply_limiter_to_drive(
        &self,
        drive_id: String,
        limiter_id: String,
        context: &Context,
    ) -> Box<Future<Item = ApplyLimiterToDriveResponse, Error = ApiError> + Send> {
        let context = context.clone();
        println!(
            "apply_limiter_to_drive(\"{}\", \"{}\") - X-Span-ID: {:?}",
            drive_id,
            limiter_id,
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Applies limiter 'limiter_id' to network interface 'iface_id'
    fn apply_limiter_to_network_interface(
        &self,
        iface_id: String,
        limiter_id: String,
        context: &Context,
    ) -> Box<Future<Item = ApplyLimiterToNetworkInterfaceResponse, Error = ApiError> + Send> {
        let context = context.clone();
        println!(
            "apply_limiter_to_network_interface(\"{}\", \"{}\") - X-Span-ID: {:?}",
            iface_id,
            limiter_id,
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Applies limiter 'limiter_id' to vsock 'vsock_id'
    fn apply_limiter_to_vsock(
        &self,
        vsock_id: String,
        limiter_id: String,
        context: &Context,
    ) -> Box<Future<Item = ApplyLimiterToVsockResponse, Error = ApiError> + Send> {
        let context = context.clone();
        println!(
            "apply_limiter_to_vsock(\"{}\", \"{}\") - X-Span-ID: {:?}",
            vsock_id,
            limiter_id,
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Create an instance action.
    fn create_instance_action(
        &self,
        action_id: String,
        info: models::InstanceActionInfo,
        context: &Context,
    ) -> Box<Future<Item = CreateInstanceActionResponse, Error = ApiError> + Send> {
        let context = context.clone();
        println!(
            "create_instance_action(\"{}\", {:?}) - X-Span-ID: {:?}",
            action_id,
            info,
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Deletes drive with ID specified by 'drive_id' path parameter.
    /// Will clean up any resources associated with this drive.
    fn delete_guest_drive_by_id(
        &self,
        drive_id: String,
        context: &Context,
    ) -> Box<Future<Item = DeleteGuestDriveByIDResponse, Error = ApiError> + Send> {
        let context = context.clone();
        println!(
            "delete_guest_drive_by_id(\"{}\") - X-Span-ID: {:?}",
            drive_id,
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Deletes network interface with ID specified by 'iface_id' path parameter.
    /// Will clean up any resources associated with this network interface.
    fn delete_guest_network_interface_by_id(
        &self,
        iface_id: String,
        context: &Context,
    ) -> Box<Future<Item = DeleteGuestNetworkInterfaceByIDResponse, Error = ApiError> + Send> {
        let context = context.clone();
        println!(
            "delete_guest_network_interface_by_id(\"{}\") - X-Span-ID: {:?}",
            iface_id,
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Deletes vsock with ID specified by 'vsock_id' path parameter.
    /// Will clean up any resources associated with this vsock.
    fn delete_guest_vsock_by_id(
        &self,
        vsock_id: String,
        context: &Context,
    ) -> Box<Future<Item = DeleteGuestVsockByIDResponse, Error = ApiError> + Send> {
        let context = context.clone();
        println!(
            "delete_guest_vsock_by_id(\"{}\") - X-Span-ID: {:?}",
            vsock_id,
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Deletes limiter with ID specified by 'limiter_id' path parameter.
    /// Will clean up any resources associated with this limiter.
    fn delete_limiter(
        &self,
        limiter_id: String,
        context: &Context,
    ) -> Box<Future<Item = DeleteLimiterResponse, Error = ApiError> + Send> {
        let context = context.clone();
        println!(
            "delete_limiter(\"{}\") - X-Span-ID: {:?}",
            limiter_id,
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Return general information about an instance.
    fn describe_instance(
        &self,
        context: &Context,
    ) -> Box<Future<Item = DescribeInstanceResponse, Error = ApiError> + Send> {
        let context = context.clone();
        println!(
            "describe_instance() - X-Span-ID: {:?}",
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Return detailed information about an action.
    fn describe_instance_action(
        &self,
        action_id: String,
        context: &Context,
    ) -> Box<Future<Item = DescribeInstanceActionResponse, Error = ApiError> + Send> {
        let context = context.clone();
        println!(
            "describe_instance_action(\"{}\") - X-Span-ID: {:?}",
            action_id,
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Retrieves limiter specified by 'limiter_id' path parameter.
    fn describe_limiter(
        &self,
        limiter_id: String,
        context: &Context,
    ) -> Box<Future<Item = DescribeLimiterResponse, Error = ApiError> + Send> {
        let context = context.clone();
        println!(
            "describe_limiter(\"{}\") - X-Span-ID: {:?}",
            limiter_id,
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Get configured boot source.
    fn get_guest_boot_source(
        &self,
        context: &Context,
    ) -> Box<Future<Item = GetGuestBootSourceResponse, Error = ApiError> + Send> {
        let context = context.clone();
        println!(
            "get_guest_boot_source() - X-Span-ID: {:?}",
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Get guest drive by 'drive_id' path parameter.
    fn get_guest_drive_by_id(
        &self,
        drive_id: String,
        context: &Context,
    ) -> Box<Future<Item = GetGuestDriveByIDResponse, Error = ApiError> + Send> {
        let context = context.clone();
        println!(
            "get_guest_drive_by_id(\"{}\") - X-Span-ID: {:?}",
            drive_id,
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// All guest drives
    fn get_guest_drives(
        &self,
        context: &Context,
    ) -> Box<Future<Item = GetGuestDrivesResponse, Error = ApiError> + Send> {
        let context = context.clone();
        println!(
            "get_guest_drives() - X-Span-ID: {:?}",
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Get guest network interface by 'iface_id' path parameter.
    fn get_guest_network_interface_by_id(
        &self,
        iface_id: String,
        context: &Context,
    ) -> Box<Future<Item = GetGuestNetworkInterfaceByIDResponse, Error = ApiError> + Send> {
        let context = context.clone();
        println!(
            "get_guest_network_interface_by_id(\"{}\") - X-Span-ID: {:?}",
            iface_id,
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// All guest network interfaces
    fn get_guest_network_interfaces(
        &self,
        context: &Context,
    ) -> Box<Future<Item = GetGuestNetworkInterfacesResponse, Error = ApiError> + Send> {
        let context = context.clone();
        println!(
            "get_guest_network_interfaces() - X-Span-ID: {:?}",
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Get guest vsock by 'vsock_id' path parameter.
    fn get_guest_vsock_by_id(
        &self,
        vsock_id: String,
        context: &Context,
    ) -> Box<Future<Item = GetGuestVsockByIDResponse, Error = ApiError> + Send> {
        let context = context.clone();
        println!(
            "get_guest_vsock_by_id(\"{}\") - X-Span-ID: {:?}",
            vsock_id,
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// All guest vsocks
    fn get_guest_vsocks(
        &self,
        context: &Context,
    ) -> Box<Future<Item = GetGuestVsocksResponse, Error = ApiError> + Send> {
        let context = context.clone();
        println!(
            "get_guest_vsocks() - X-Span-ID: {:?}",
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Retrieves list of limiters IDs currently applied to the drive with 'drive_id'.
    fn get_limiters_for_guest_drive(
        &self,
        drive_id: String,
        context: &Context,
    ) -> Box<Future<Item = GetLimitersForGuestDriveResponse, Error = ApiError> + Send> {
        let context = context.clone();
        println!(
            "get_limiters_for_guest_drive(\"{}\") - X-Span-ID: {:?}",
            drive_id,
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Retrieves list of limiters IDs currently applied
    /// to the network interface with 'iface_id'.
    fn get_limiters_for_guest_network_interface(
        &self,
        iface_id: String,
        context: &Context,
    ) -> Box<Future<Item = GetLimitersForGuestNetworkInterfaceResponse, Error = ApiError> + Send>
    {
        let context = context.clone();
        println!(
            "get_limiters_for_guest_network_interface(\"{}\") - X-Span-ID: {:?}",
            iface_id,
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Retrieves list of limiters IDs currently applied to the vsock with 'vsock_id'.
    fn get_limiters_for_guest_vsock(
        &self,
        vsock_id: String,
        context: &Context,
    ) -> Box<Future<Item = GetLimitersForGuestVsockResponse, Error = ApiError> + Send> {
        let context = context.clone();
        println!(
            "get_limiters_for_guest_vsock(\"{}\") - X-Span-ID: {:?}",
            vsock_id,
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Return metadata about an instance.
    fn get_metadata(
        &self,
        context: &Context,
    ) -> Box<Future<Item = GetMetadataResponse, Error = ApiError> + Send> {
        let context = context.clone();
        println!(
            "get_metadata() - X-Span-ID: {:?}",
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Return the list of (most recent) actions for an instance.
    fn list_instance_actions(
        &self,
        context: &Context,
    ) -> Box<Future<Item = ListInstanceActionsResponse, Error = ApiError> + Send> {
        let context = context.clone();
        println!(
            "list_instance_actions() - X-Span-ID: {:?}",
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Retrieves list of currently created limiters.
    fn list_limiters(
        &self,
        next_token: Option<String>,
        context: &Context,
    ) -> Box<Future<Item = ListLimitersResponse, Error = ApiError> + Send> {
        let context = context.clone();
        println!(
            "list_limiters({:?}) - X-Span-ID: {:?}",
            next_token,
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Creates new boot source. If boot source already exists,
    /// updates its state based on new input. May fail if update is not possible.
    fn put_guest_boot_source(
        &self,
        body: models::BootSource,
        context: &Context,
    ) -> Box<Future<Item = PutGuestBootSourceResponse, Error = ApiError> + Send> {
        let context = context.clone();
        println!(
            "put_guest_boot_source({:?}) - X-Span-ID: {:?}",
            body,
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Creates new drive with ID specified by 'drive_id' path parameter.
    /// If drive with specified ID already exists, updates its state based on new input.
    /// May fail if update is not possible.
    fn put_guest_drive_by_id(
        &self,
        drive_id: String,
        body: models::Drive,
        context: &Context,
    ) -> Box<Future<Item = PutGuestDriveByIDResponse, Error = ApiError> + Send> {
        let context = context.clone();
        println!(
            "put_guest_drive_by_id(\"{}\", {:?}) - X-Span-ID: {:?}",
            drive_id,
            body,
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Creates new network interface with ID specified by 'iface_id' path parameter.
    /// If network interface with specified ID already exists,
    /// updates its state based on new input. May fail if update is not possible.
    fn put_guest_network_interface_by_id(
        &self,
        iface_id: String,
        body: models::NetworkInterface,
        context: &Context,
    ) -> Box<Future<Item = PutGuestNetworkInterfaceByIDResponse, Error = ApiError> + Send> {
        let context = context.clone();
        println!(
            "put_guest_network_interface_by_id(\"{}\", {:?}) - X-Span-ID: {:?}",
            iface_id,
            body,
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Creates new vsock with ID specified by 'vsock_id' path parameter.
    /// If vsock with specified ID already exists, updates its state based on new input.
    /// May fail if update is not possible.
    fn put_guest_vsock_by_id(
        &self,
        vsock_id: String,
        body: models::Vsock,
        context: &Context,
    ) -> Box<Future<Item = PutGuestVsockByIDResponse, Error = ApiError> + Send> {
        let context = context.clone();
        println!(
            "put_guest_vsock_by_id(\"{}\", {:?}) - X-Span-ID: {:?}",
            vsock_id,
            body,
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Creates new limiter with ID specified by 'limiter_id' path parameter.
    /// If limiter with specified ID already exists, updates its state based on new input.
    /// May fail if update is not possible.
    fn update_limiter(
        &self,
        limiter_id: String,
        limiter: models::Limiter,
        context: &Context,
    ) -> Box<Future<Item = UpdateLimiterResponse, Error = ApiError> + Send> {
        let context = context.clone();
        println!(
            "update_limiter(\"{}\", {:?}) - X-Span-ID: {:?}",
            limiter_id,
            limiter,
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }
}

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::thread;

use iron::{Chain, Iron};

use vmm::machine::MachineCfg;

pub fn start_api_server(cmd_arguments: &clap::ArgMatches) {
    let api_port = match cmd_arguments
        .value_of("api_port")
        .unwrap()
        .to_string()
        .parse::<u16>()
    {
        Ok(value) => value,
        Err(error) => {
            panic!("Invalid value for api TCP listen port! {:?}", error);
        }
    };
    let kernel_path: Option<PathBuf> = cmd_arguments
        .value_of("kernel_path")
        .map(|s| PathBuf::from(s));

    //unwrap should not panic because kernel_cmdline has a default value
    let kernel_cmdline = String::from(cmd_arguments.value_of("kernel_cmdline").unwrap());

    let vcpu_count = match cmd_arguments
        .value_of("vcpu_count")
        .unwrap()
        .to_string()
        .parse::<u8>()
    {
        Ok(value) => value,
        Err(error) => {
            panic!("Invalid value for vcpu_count! {:?}", error);
        }
    };

    let mem_size = match cmd_arguments
        .value_of("mem_size")
        .unwrap()
        .to_string()
        .parse::<usize>()
    {
        Ok(value) => value,
        Err(error) => {
            panic!("Invalid value for mem_size! {:?}", error);
        }
    };

    let root_blk_file = cmd_arguments
        .value_of("root_blk_file")
        .map(|s| PathBuf::from(s));

    //fixme print some message when the Ipv4Addrs cannot be parsed
    let host_ip = cmd_arguments
        .value_of("host_ip")
        .map(|x| x.parse().unwrap());

    let subnet_mask = cmd_arguments
        .value_of("subnet_mask")
        .unwrap()
        .parse()
        .unwrap();

    let cfg = MachineCfg::new(
        kernel_path,
        kernel_cmdline,
        vcpu_count,
        mem_size,
        root_blk_file,
        host_ip,
        subnet_mask,
    );
    let kill_on_vmm_exit = cmd_arguments.is_present("kill_api");

    thread::spawn(move || {
        vmm::boot_kernel(cfg, kill_on_vmm_exit).expect("cannot boot kernel");
    });

    let server = Server {};
    let router = api::router(server);

    let chain = Chain::new(router);
    let sock_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), api_port);

    let mut iron = Iron::new(chain);
    // By default Iron uses 8 * num_cpus threads.
    iron.threads = 1;
    iron.http(sock_addr).expect("Failed to start HTTP server");
}
