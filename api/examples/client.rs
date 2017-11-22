#![allow(missing_docs, unused_variables, trivial_casts)]

extern crate swagger_client;
#[allow(unused_extern_crates)]
extern crate futures;
#[allow(unused_extern_crates)]
extern crate swagger;
#[allow(unused_extern_crates)]
extern crate uuid;
extern crate clap;

#[allow(unused_imports)]
use futures::{Future, future, Stream, stream};
#[allow(unused_imports)]
use swagger_client::{ApiNoContext, ContextWrapperExt,
                      ApiError,
                      ApplyLimiterToDriveResponse,
                      ApplyLimiterToNetworkInterfaceResponse,
                      ApplyLimiterToVsockResponse,
                      CreateInstanceActionResponse,
                      DeleteGuestDriveByIDResponse,
                      DeleteGuestNetworkInterfaceByIDResponse,
                      DeleteGuestVsockByIDResponse,
                      DeleteLimiterResponse,
                      DescribeInstanceResponse,
                      DescribeInstanceActionResponse,
                      DescribeLimiterResponse,
                      GetGuestBootSourceResponse,
                      GetGuestDriveByIDResponse,
                      GetGuestDrivesResponse,
                      GetGuestNetworkInterfaceByIDResponse,
                      GetGuestNetworkInterfacesResponse,
                      GetGuestVsockByIDResponse,
                      GetGuestVsocksResponse,
                      GetLimitersForGuestDriveResponse,
                      GetLimitersForGuestNetworkInterfaceResponse,
                      GetLimitersForGuestVsockResponse,
                      GetMetadataResponse,
                      ListInstanceActionsResponse,
                      ListLimitersResponse,
                      PutGuestBootSourceResponse,
                      PutGuestDriveByIDResponse,
                      PutGuestNetworkInterfaceByIDResponse,
                      PutGuestVsockByIDResponse,
                      UpdateLimiterResponse
                     };
use clap::{App, Arg};

fn main() {
    let matches = App::new("client")
        .arg(Arg::with_name("operation")
            .help("Sets the operation to run")
            .possible_values(&[
    "ApplyLimiterToDrive",
    "ApplyLimiterToNetworkInterface",
    "ApplyLimiterToVsock",
    "DeleteGuestDriveByID",
    "DeleteGuestNetworkInterfaceByID",
    "DeleteGuestVsockByID",
    "DeleteLimiter",
    "DescribeInstance",
    "DescribeInstanceAction",
    "DescribeLimiter",
    "GetGuestBootSource",
    "GetGuestDriveByID",
    "GetGuestDrives",
    "GetGuestNetworkInterfaceByID",
    "GetGuestNetworkInterfaces",
    "GetGuestVsockByID",
    "GetGuestVsocks",
    "GetLimitersForGuestDrive",
    "GetLimitersForGuestNetworkInterface",
    "GetLimitersForGuestVsock",
    "GetMetadata",
    "ListInstanceActions",
    "ListLimiters",
])
            .required(true)
            .index(1))
        .arg(Arg::with_name("https")
            .long("https")
            .help("Whether to use HTTPS or not"))
        .get_matches();

    let client = if matches.is_present("https") {
        // Using Simple HTTPS
        swagger_client::Client::try_new_https("https://localhost:8080", "examples/ca.pem").expect("Failed to create HTTPS client")
    } else {
        // Using HTTP
        swagger_client::Client::try_new_http("http://localhost:8080").expect("Failed to create HTTP client")
    };

    // Using a non-default `Context` is not required; this is just an example!
    let client = client.with_context(swagger_client::Context::new_with_span_id(self::uuid::Uuid::new_v4().to_string()));

    match matches.value_of("operation") {

        Some("ApplyLimiterToDrive") => {
            let result = client.apply_limiter_to_drive("drive_id_example".to_string(), "limiter_id_example".to_string()).wait();
            println!("{:?} (X-Span-ID: {:?})", result, client.context().x_span_id.clone().unwrap_or(String::from("<none>")));
         },

        Some("ApplyLimiterToNetworkInterface") => {
            let result = client.apply_limiter_to_network_interface("iface_id_example".to_string(), "limiter_id_example".to_string()).wait();
            println!("{:?} (X-Span-ID: {:?})", result, client.context().x_span_id.clone().unwrap_or(String::from("<none>")));
         },

        Some("ApplyLimiterToVsock") => {
            let result = client.apply_limiter_to_vsock("vsock_id_example".to_string(), "limiter_id_example".to_string()).wait();
            println!("{:?} (X-Span-ID: {:?})", result, client.context().x_span_id.clone().unwrap_or(String::from("<none>")));
         },

        // Disabled because there's no example.
        // Some("CreateInstanceAction") => {
        //     let result = client.create_instance_action("action_id_example".to_string(), ???).wait();
        //     println!("{:?} (X-Span-ID: {:?})", result, client.context().x_span_id.clone().unwrap_or(String::from("<none>")));
        //  },

        Some("DeleteGuestDriveByID") => {
            let result = client.delete_guest_drive_by_id("drive_id_example".to_string()).wait();
            println!("{:?} (X-Span-ID: {:?})", result, client.context().x_span_id.clone().unwrap_or(String::from("<none>")));
         },

        Some("DeleteGuestNetworkInterfaceByID") => {
            let result = client.delete_guest_network_interface_by_id("iface_id_example".to_string()).wait();
            println!("{:?} (X-Span-ID: {:?})", result, client.context().x_span_id.clone().unwrap_or(String::from("<none>")));
         },

        Some("DeleteGuestVsockByID") => {
            let result = client.delete_guest_vsock_by_id("vsock_id_example".to_string()).wait();
            println!("{:?} (X-Span-ID: {:?})", result, client.context().x_span_id.clone().unwrap_or(String::from("<none>")));
         },

        Some("DeleteLimiter") => {
            let result = client.delete_limiter("limiter_id_example".to_string()).wait();
            println!("{:?} (X-Span-ID: {:?})", result, client.context().x_span_id.clone().unwrap_or(String::from("<none>")));
         },

        Some("DescribeInstance") => {
            let result = client.describe_instance().wait();
            println!("{:?} (X-Span-ID: {:?})", result, client.context().x_span_id.clone().unwrap_or(String::from("<none>")));
         },

        Some("DescribeInstanceAction") => {
            let result = client.describe_instance_action("action_id_example".to_string()).wait();
            println!("{:?} (X-Span-ID: {:?})", result, client.context().x_span_id.clone().unwrap_or(String::from("<none>")));
         },

        Some("DescribeLimiter") => {
            let result = client.describe_limiter("limiter_id_example".to_string()).wait();
            println!("{:?} (X-Span-ID: {:?})", result, client.context().x_span_id.clone().unwrap_or(String::from("<none>")));
         },

        Some("GetGuestBootSource") => {
            let result = client.get_guest_boot_source().wait();
            println!("{:?} (X-Span-ID: {:?})", result, client.context().x_span_id.clone().unwrap_or(String::from("<none>")));
         },

        Some("GetGuestDriveByID") => {
            let result = client.get_guest_drive_by_id("drive_id_example".to_string()).wait();
            println!("{:?} (X-Span-ID: {:?})", result, client.context().x_span_id.clone().unwrap_or(String::from("<none>")));
         },

        Some("GetGuestDrives") => {
            let result = client.get_guest_drives().wait();
            println!("{:?} (X-Span-ID: {:?})", result, client.context().x_span_id.clone().unwrap_or(String::from("<none>")));
         },

        Some("GetGuestNetworkInterfaceByID") => {
            let result = client.get_guest_network_interface_by_id("iface_id_example".to_string()).wait();
            println!("{:?} (X-Span-ID: {:?})", result, client.context().x_span_id.clone().unwrap_or(String::from("<none>")));
         },

        Some("GetGuestNetworkInterfaces") => {
            let result = client.get_guest_network_interfaces().wait();
            println!("{:?} (X-Span-ID: {:?})", result, client.context().x_span_id.clone().unwrap_or(String::from("<none>")));
         },

        Some("GetGuestVsockByID") => {
            let result = client.get_guest_vsock_by_id("vsock_id_example".to_string()).wait();
            println!("{:?} (X-Span-ID: {:?})", result, client.context().x_span_id.clone().unwrap_or(String::from("<none>")));
         },

        Some("GetGuestVsocks") => {
            let result = client.get_guest_vsocks().wait();
            println!("{:?} (X-Span-ID: {:?})", result, client.context().x_span_id.clone().unwrap_or(String::from("<none>")));
         },

        Some("GetLimitersForGuestDrive") => {
            let result = client.get_limiters_for_guest_drive("drive_id_example".to_string()).wait();
            println!("{:?} (X-Span-ID: {:?})", result, client.context().x_span_id.clone().unwrap_or(String::from("<none>")));
         },

        Some("GetLimitersForGuestNetworkInterface") => {
            let result = client.get_limiters_for_guest_network_interface("iface_id_example".to_string()).wait();
            println!("{:?} (X-Span-ID: {:?})", result, client.context().x_span_id.clone().unwrap_or(String::from("<none>")));
         },

        Some("GetLimitersForGuestVsock") => {
            let result = client.get_limiters_for_guest_vsock("vsock_id_example".to_string()).wait();
            println!("{:?} (X-Span-ID: {:?})", result, client.context().x_span_id.clone().unwrap_or(String::from("<none>")));
         },

        Some("GetMetadata") => {
            let result = client.get_metadata().wait();
            println!("{:?} (X-Span-ID: {:?})", result, client.context().x_span_id.clone().unwrap_or(String::from("<none>")));
         },

        Some("ListInstanceActions") => {
            let result = client.list_instance_actions().wait();
            println!("{:?} (X-Span-ID: {:?})", result, client.context().x_span_id.clone().unwrap_or(String::from("<none>")));
         },

        Some("ListLimiters") => {
            let result = client.list_limiters(Some("next_token_example".to_string())).wait();
            println!("{:?} (X-Span-ID: {:?})", result, client.context().x_span_id.clone().unwrap_or(String::from("<none>")));
         },

        // Disabled because there's no example.
        // Some("PutGuestBootSource") => {
        //     let result = client.put_guest_boot_source(???).wait();
        //     println!("{:?} (X-Span-ID: {:?})", result, client.context().x_span_id.clone().unwrap_or(String::from("<none>")));
        //  },

        // Disabled because there's no example.
        // Some("PutGuestDriveByID") => {
        //     let result = client.put_guest_drive_by_id("drive_id_example".to_string(), ???).wait();
        //     println!("{:?} (X-Span-ID: {:?})", result, client.context().x_span_id.clone().unwrap_or(String::from("<none>")));
        //  },

        // Disabled because there's no example.
        // Some("PutGuestNetworkInterfaceByID") => {
        //     let result = client.put_guest_network_interface_by_id("iface_id_example".to_string(), ???).wait();
        //     println!("{:?} (X-Span-ID: {:?})", result, client.context().x_span_id.clone().unwrap_or(String::from("<none>")));
        //  },

        // Disabled because there's no example.
        // Some("PutGuestVsockByID") => {
        //     let result = client.put_guest_vsock_by_id("vsock_id_example".to_string(), ???).wait();
        //     println!("{:?} (X-Span-ID: {:?})", result, client.context().x_span_id.clone().unwrap_or(String::from("<none>")));
        //  },

        // Disabled because there's no example.
        // Some("UpdateLimiter") => {
        //     let result = client.update_limiter("limiter_id_example".to_string(), ???).wait();
        //     println!("{:?} (X-Span-ID: {:?})", result, client.context().x_span_id.clone().unwrap_or(String::from("<none>")));
        //  },

        _ => {
            panic!("Invalid operation provided")
        }
    }
}

