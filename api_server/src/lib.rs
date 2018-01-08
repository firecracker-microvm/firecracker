extern crate clap;
extern crate futures;
extern crate iron;

extern crate api;
extern crate vmm;

use futures::Future;

use api::*;

use std::sync::{Arc, Mutex};
use std::collections::LinkedList;

type FutureResponse<T> = Box<Future<Item = T, Error = ApiError> + Send>;

type ResponseResult<T> = std::result::Result<FutureResponse<T>, FutureResponse<T>>;

macro_rules! ErrorResponseWithMessage {
    ($err:path, $msg:expr) => (Box::new(futures::future::ok($err(
                               models::Error {fault_message: Some($msg.to_string())}))));
}

macro_rules! ret_on_fail {
    ($expr:expr) => (match $expr {
        Ok(ret) => ret,
        Err(ret) => {
            return ret
        }
    })
}

#[derive(Clone)]
pub struct Server {
    actions: Arc<Mutex<LinkedList<models::InstanceActionInfo>>>,
}

impl Server {
    pub fn new() -> Server {
        Server {
            actions: Arc::new(Mutex::new(LinkedList::new())),
        }
    }

    fn add_instance_action(
        &self,
        action_id: String,
        info: models::InstanceActionInfo,
    ) -> ResponseResult<CreateInstanceActionResponse> {
        let mut actions = self.actions.lock().unwrap();

        match actions.iter().position(|ref n| **n == info) {
            Some(pos) => {
                if actions.iter().nth(pos).unwrap().timestamp.is_none() {
                    return Err(ErrorResponseWithMessage!(
                        CreateInstanceActionResponse::UnexpectedError,
                        format!(
                            "action_id '{}' is already used by a pending action.",
                            action_id
                        )
                    ));
                }

                let mut the_rest = actions.split_off(pos);
                let the_one = the_rest.pop_front().unwrap();
                actions.push_front(the_one);
                actions.append(&mut the_rest);

                Ok(Box::new(futures::future::ok(
                    CreateInstanceActionResponse::ActionUpdated,
                )))
            }
            None => {
                actions.push_back(info);
                Ok(Box::new(futures::future::ok(
                    CreateInstanceActionResponse::NoPreviousActionExistedSoANewOneWasCreated,
                )))
            }
        }
    }
}

impl Api for Server {
    /// Applies limiter 'limiter_id' to drive 'drive_id'
    fn apply_limiter_to_drive(
        &self,
        drive_id: String,
        limiter_id: String,
        context: &Context,
    ) -> FutureResponse<ApplyLimiterToDriveResponse> {
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
    ) -> FutureResponse<ApplyLimiterToNetworkInterfaceResponse> {
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
    ) -> FutureResponse<ApplyLimiterToVsockResponse> {
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
        _context: &Context,
    ) -> FutureResponse<CreateInstanceActionResponse> {
        if info.timestamp.is_some() {
            return ErrorResponseWithMessage!(
                CreateInstanceActionResponse::UnexpectedError,
                "Timestamp field is read-only! Do not attempt to modify."
            );
        }
        if info.action_id != action_id {
            return ErrorResponseWithMessage!(
                CreateInstanceActionResponse::UnexpectedError,
                "'action_id' from url does not match the one in body."
            );
        }
        if let Some(ref action_type) = info.action_type {
            match &action_type[..] {
                "InstanceStart" | "InstanceDeviceDetach" | "InstanceReset" | "InstanceHalt" => (),
                _ => {
                    return ErrorResponseWithMessage!(
                        CreateInstanceActionResponse::UnexpectedError,
                        "Invalid 'action_type'"
                    )
                }
            }
        } else {
            return ErrorResponseWithMessage!(
                CreateInstanceActionResponse::UnexpectedError,
                "Invalid 'action_type'"
            );
        }

        let response = ret_on_fail!(self.add_instance_action(action_id, info));

        /* TODO: initiate the actual action here in a separate (async req) thread. */

        response
    }

    /// Deletes drive with ID specified by 'drive_id' path parameter.
    /// Will clean up any resources associated with this drive.
    fn delete_guest_drive_by_id(
        &self,
        drive_id: String,
        context: &Context,
    ) -> FutureResponse<DeleteGuestDriveByIDResponse> {
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
    ) -> FutureResponse<DeleteGuestNetworkInterfaceByIDResponse> {
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
    ) -> FutureResponse<DeleteGuestVsockByIDResponse> {
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
    ) -> FutureResponse<DeleteLimiterResponse> {
        let context = context.clone();
        println!(
            "delete_limiter(\"{}\") - X-Span-ID: {:?}",
            limiter_id,
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Return general information about an instance.
    fn describe_instance(&self, context: &Context) -> FutureResponse<DescribeInstanceResponse> {
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
    ) -> FutureResponse<DescribeInstanceActionResponse> {
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
    ) -> FutureResponse<DescribeLimiterResponse> {
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
    ) -> FutureResponse<GetGuestBootSourceResponse> {
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
    ) -> FutureResponse<GetGuestDriveByIDResponse> {
        let context = context.clone();
        println!(
            "get_guest_drive_by_id(\"{}\") - X-Span-ID: {:?}",
            drive_id,
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// All guest drives
    fn get_guest_drives(&self, context: &Context) -> FutureResponse<GetGuestDrivesResponse> {
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
    ) -> FutureResponse<GetGuestNetworkInterfaceByIDResponse> {
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
    ) -> FutureResponse<GetGuestNetworkInterfacesResponse> {
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
    ) -> FutureResponse<GetGuestVsockByIDResponse> {
        let context = context.clone();
        println!(
            "get_guest_vsock_by_id(\"{}\") - X-Span-ID: {:?}",
            vsock_id,
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// All guest vsocks
    fn get_guest_vsocks(&self, context: &Context) -> FutureResponse<GetGuestVsocksResponse> {
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
    ) -> FutureResponse<GetLimitersForGuestDriveResponse> {
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
    ) -> FutureResponse<GetLimitersForGuestNetworkInterfaceResponse> {
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
    ) -> FutureResponse<GetLimitersForGuestVsockResponse> {
        let context = context.clone();
        println!(
            "get_limiters_for_guest_vsock(\"{}\") - X-Span-ID: {:?}",
            vsock_id,
            context.x_span_id.unwrap_or(String::from("<none>")).clone()
        );
        Box::new(futures::failed("Generic failure".into()))
    }

    /// Return metadata about an instance.
    fn get_metadata(&self, context: &Context) -> FutureResponse<GetMetadataResponse> {
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
    ) -> FutureResponse<ListInstanceActionsResponse> {
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
    ) -> FutureResponse<ListLimitersResponse> {
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
    ) -> FutureResponse<PutGuestBootSourceResponse> {
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
    ) -> FutureResponse<PutGuestDriveByIDResponse> {
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
    ) -> FutureResponse<PutGuestNetworkInterfaceByIDResponse> {
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
    ) -> FutureResponse<PutGuestVsockByIDResponse> {
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
    ) -> FutureResponse<UpdateLimiterResponse> {
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

    let server = Server::new();
    let router = api::router(server);

    let chain = Chain::new(router);
    let sock_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), api_port);

    let mut iron = Iron::new(chain);
    // By default Iron uses 8 * num_cpus threads.
    iron.threads = 1;
    iron.http(sock_addr).expect("Failed to start HTTP server");
}
