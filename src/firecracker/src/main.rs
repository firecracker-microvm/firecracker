// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate backtrace;
extern crate libc;

extern crate api_server;
#[macro_use]
extern crate logger;
extern crate mmds;
extern crate seccomp;
extern crate utils;
extern crate vmm;

use backtrace::Backtrace;

use std::fs;
use std::io;
use std::panic;
use std::path::PathBuf;
use std::process;
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::{Arc, RwLock};
use std::thread;

use api_server::{ApiServer, Error, VmmRequest, VmmResponse};
use logger::{Metric, LOGGER, METRICS};
use mmds::MMDS;
use seccomp::{BpfInstructionSlice, BpfProgram, SeccompLevel};
use utils::arg_parser::{App, ArgInfo};
use utils::eventfd::EventFd;
use utils::terminal::Terminal;
use utils::validators::validate_instance_id;
use vmm::default_syscalls::get_seccomp_filter;
use vmm::signal_handler::register_signal_handlers;
use vmm::vmm_config::instance_info::{InstanceInfo, InstanceState};
use vmm::{EventLoopExitReason, Vmm};

const DEFAULT_API_SOCK_PATH: &str = "/tmp/firecracker.socket";
const DEFAULT_INSTANCE_ID: &str = "anonymous-instance";
const FIRECRACKER_VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    LOGGER
        .preinit(Some(DEFAULT_INSTANCE_ID.to_string()))
        .expect("Failed to register logger");

    if let Err(e) = register_signal_handlers() {
        error!("Failed to register signal handlers: {}", e);
        process::exit(i32::from(vmm::FC_EXIT_CODE_GENERIC_ERROR));
    }

    // We need this so that we can reset terminal to canonical mode if panic occurs.
    let stdin = io::stdin();

    // Start firecracker by setting up a panic hook, which will be called before
    // terminating as we're building with panic = "abort".
    // It's worth noting that the abort is caused by sending a SIG_ABORT signal to the process.
    panic::set_hook(Box::new(move |info| {
        // We're currently using the closure parameter, which is a &PanicInfo, for printing the
        // origin of the panic, including the payload passed to panic! and the source code location
        // from which the panic originated.
        error!("Firecracker {}", info);
        if let Err(e) = stdin.lock().set_canon_mode() {
            error!(
                "Failure while trying to reset stdin to canonical mode: {}",
                e
            );
        }

        METRICS.vmm.panic_count.inc();
        let bt = Backtrace::new();
        error!("{:?}", bt);

        // Log the metrics before aborting.
        if let Err(e) = LOGGER.log_metrics() {
            error!("Failed to log metrics while panicking: {}", e);
        }
    }));

    let mut app = App::new()
        .name("Firecracker")
        .version(FIRECRACKER_VERSION)
        .header("Launch a microVM.")
        .arg(
            ArgInfo::new("api-sock")
                .takes_value(true)
                .default_value(DEFAULT_API_SOCK_PATH)
                .help("Path to unix domain socket used by the API"),
        )
        .arg(
            ArgInfo::new("id")
                .takes_value(true)
                .default_value(DEFAULT_INSTANCE_ID)
                .help("MicroVM unique identifier"),
        )
        .arg(
            ArgInfo::new("seccomp-level")
                .takes_value(true)
                .default_value("2")
                .help(
                    "Level of seccomp filtering that will be passed to executed path as \
                    argument.\n
                        - Level 0: No filtering.\n
                        - Level 1: Seccomp filtering by syscall number.\n
                        - Level 2: Seccomp filtering by syscall number and argument values.\n
                    ",
                ),
        )
        .arg(
            ArgInfo::new("start-time-us")
                .takes_value(true),
        )
        .arg(
            ArgInfo::new("start-time-cpu-us")
                .takes_value(true),
        )
        .arg(
            ArgInfo::new("config-file")
                .takes_value(true)
                .help("Path to a file that contains the microVM configuration in JSON format."),
        )
        .arg(
            ArgInfo::new("no-api")
                .takes_value(false)
                .requires("config-file")
                .help("Optional parameter which allows starting and using a microVM without an active API socket.")
        );

    let arguments = match app.parse_cmdline_args() {
        Err(err) => {
            error!(
                "Arguments parsing error: {} \n\n\
                 For more information try --help.",
                err
            );
            process::exit(i32::from(vmm::FC_EXIT_CODE_ARG_PARSING));
        }
        _ => {
            if let Some(help) = app.arguments().value_as_bool("help") {
                if help {
                    println!("{}", app.format_help());
                    process::exit(i32::from(vmm::FC_EXIT_CODE_OK));
                }
            }
            app.arguments()
        }
    };

    let bind_path = arguments
        .value_as_string("api-sock")
        .map(PathBuf::from)
        .expect("Missing argument: api_sock");

    // It's safe to unwrap here because the field's been provided with a default value.
    let instance_id = arguments.value_as_string("id").unwrap();
    validate_instance_id(instance_id.as_str()).expect("Invalid instance ID");

    // It's safe to unwrap here because the field's been provided with a default value.
    let seccomp_level = arguments.value_as_string("seccomp-level").unwrap();
    let seccomp_filter = get_seccomp_filter(
        SeccompLevel::from_string(seccomp_level).unwrap_or_else(|err| {
            panic!("Invalid value for seccomp-level: {}", err);
        }),
    )
    .unwrap_or_else(|err| {
        panic!("Could not create seccomp filter: {}", err);
    });

    let start_time_us = arguments.value_as_string("start-time-us").map(|s| {
        s.parse::<u64>()
            .expect("'start-time-us' parameter expected to be of 'u64' type.")
    });

    let start_time_cpu_us = arguments.value_as_string("start-time-cpu-us").map(|s| {
        s.parse::<u64>()
            .expect("'start-time-cpu_us' parameter expected to be of 'u64' type.")
    });

    let vmm_config_json = arguments
        .value_as_string("config-file")
        .map(fs::read_to_string)
        .map(|x| x.expect("Unable to open or read from the configuration file"));

    let no_api = arguments.value_as_bool("no-api").unwrap_or(false);

    let api_shared_info = Arc::new(RwLock::new(InstanceInfo {
        state: InstanceState::Uninitialized,
        id: instance_id.clone(),
        vmm_version: FIRECRACKER_VERSION.to_string(),
    }));

    let request_event_fd = EventFd::new(libc::EFD_NONBLOCK)
        .map_err(Error::Eventfd)
        .expect("Cannot create API Eventfd.");
    let (to_vmm, from_api) = channel();
    let (to_api, from_vmm) = channel();

    // Api enabled.
    if !no_api {
        // MMDS only supported with API.
        let mmds_info = MMDS.clone();
        let vmm_shared_info = api_shared_info.clone();
        let to_vmm_event_fd = request_event_fd.try_clone().unwrap();
        let api_server_filter = seccomp_filter.clone();

        thread::Builder::new()
            .name("fc_api".to_owned())
            .spawn(move || {
                match ApiServer::new(
                    mmds_info,
                    vmm_shared_info,
                    to_vmm,
                    from_vmm,
                    to_vmm_event_fd,
                )
                .expect("Cannot create API server")
                .bind_and_run(
                    bind_path,
                    start_time_us,
                    start_time_cpu_us,
                    api_server_filter,
                ) {
                    Ok(_) => (),
                    Err(Error::Io(inner)) => match inner.kind() {
                        io::ErrorKind::AddrInUse => {
                            panic!("Failed to open the API socket: {:?}", Error::Io(inner))
                        }
                        _ => panic!(
                            "Failed to communicate with the API socket: {:?}",
                            Error::Io(inner)
                        ),
                    },
                    Err(eventfd_err @ Error::Eventfd(_)) => {
                        panic!("Failed to open the API socket: {:?}", eventfd_err)
                    }
                }
            })
            .expect("API thread spawn failed.");
    }

    start_vmm(
        api_shared_info,
        request_event_fd,
        from_api,
        to_api,
        seccomp_filter,
        vmm_config_json,
    );
}

/// Creates and starts a vmm.
///
/// # Arguments
///
/// * `api_shared_info` - A parameter for storing information on the VMM (e.g the current state).
/// * `api_event_fd` - An event fd used for receiving API associated events.
/// * `from_api` - The receiver end point of the communication channel.
/// * `seccomp_filter` - The seccomp filter used. Filters are loaded before executing
///                     guest code. The caller is responsible for providing a correct filter.
/// * `config_json` - Optional parameter that can be used to configure the guest machine without
///                   using the API socket.
fn start_vmm(
    api_shared_info: Arc<RwLock<InstanceInfo>>,
    api_event_fd: EventFd,
    from_api: Receiver<VmmRequest>,
    to_api: Sender<VmmResponse>,
    seccomp_filter: BpfProgram,
    config_json: Option<String>,
) {
    // If this fails, consider it fatal. Use expect().
    let mut vmm = Vmm::new(api_shared_info, &api_event_fd).expect("Cannot create VMM");
    let vmm_seccomp_filter = seccomp_filter.clone();
    let vcpu_seccomp_filter = seccomp_filter.clone();

    if let Some(json) = config_json {
        vmm.configure_from_json(json).unwrap_or_else(|err| {
            error!(
                "Setting configuration for VMM from one single json failed: {}",
                err
            );
            process::exit(i32::from(vmm::FC_EXIT_CODE_BAD_CONFIGURATION));
        });
        vmm.start_microvm(vmm_seccomp_filter.clone(), vcpu_seccomp_filter.clone())
            .unwrap_or_else(|err| {
                error!(
                    "Starting microvm that was configured from one single json failed: {}",
                    err
                );
                process::exit(i32::from(vmm::FC_EXIT_CODE_UNEXPECTED_ERROR));
            });
        info!("Successfully started microvm that was configured from one single json");
    }

    let exit_code = loop {
        match vmm.run_event_loop() {
            Err(e) => {
                error!("Abruptly exited VMM control loop: {:?}", e);
                break vmm::FC_EXIT_CODE_GENERIC_ERROR;
            }
            Ok(exit_reason) => match exit_reason {
                EventLoopExitReason::Break => {
                    info!("Gracefully terminated VMM control loop");
                    break vmm::FC_EXIT_CODE_OK;
                }
                EventLoopExitReason::ControlAction => {
                    if let Err(exit_code) = vmm_control_event(
                        &mut vmm,
                        &api_event_fd,
                        &from_api,
                        &to_api,
                        &vmm_seccomp_filter[..],
                        &vcpu_seccomp_filter[..],
                    ) {
                        break exit_code;
                    }
                }
            },
        };
    };

    vmm.stop(i32::from(exit_code));
}

/// Handles the control event.
/// Receives and runs the Vmm action and sends back a response.
/// Provides program exit codes on errors.
fn vmm_control_event(
    vmm: &mut Vmm,
    api_event_fd: &EventFd,
    from_api: &Receiver<VmmRequest>,
    to_api: &Sender<VmmResponse>,
    vmm_seccomp_filter: &BpfInstructionSlice,
    vcpu_seccomp_filter: &BpfInstructionSlice,
) -> Result<(), u8> {
    api_event_fd.read().map_err(|e| {
        error!("VMM: Failed to read the API event_fd: {}", e);
        vmm::FC_EXIT_CODE_GENERIC_ERROR
    })?;

    match from_api.try_recv() {
        Ok(vmm_request) => {
            use api_server::VmmAction::*;
            let action_request = *vmm_request;
            let response = match action_request {
                ConfigureBootSource(boot_source_body) => vmm
                    .configure_boot_source(boot_source_body)
                    .map(|_| api_server::VmmData::Empty),
                ConfigureLogger(logger_description) => vmm
                    .init_logger(logger_description)
                    .map(|_| api_server::VmmData::Empty),
                FlushMetrics => vmm.flush_metrics().map(|_| api_server::VmmData::Empty),
                GetVmConfiguration => Ok(api_server::VmmData::MachineConfiguration(
                    vmm.vm_config().clone(),
                )),
                InsertBlockDevice(block_device_config) => vmm
                    .insert_block_device(block_device_config)
                    .map(|_| api_server::VmmData::Empty),
                InsertNetworkDevice(netif_body) => vmm
                    .insert_net_device(netif_body)
                    .map(|_| api_server::VmmData::Empty),
                SetVsockDevice(vsock_cfg) => vmm
                    .set_vsock_device(vsock_cfg)
                    .map(|_| api_server::VmmData::Empty),
                RescanBlockDevice(drive_id) => vmm
                    .rescan_block_device(&drive_id)
                    .map(|_| api_server::VmmData::Empty),
                StartMicroVm => vmm
                    .start_microvm(
                        vmm_seccomp_filter.to_owned(),
                        vcpu_seccomp_filter.to_owned(),
                    )
                    .map(|_| api_server::VmmData::Empty),
                #[cfg(target_arch = "x86_64")]
                SendCtrlAltDel => vmm.send_ctrl_alt_del().map(|_| api_server::VmmData::Empty),
                SetVmConfiguration(machine_config_body) => vmm
                    .set_vm_configuration(machine_config_body)
                    .map(|_| api_server::VmmData::Empty),
                UpdateBlockDevicePath(drive_id, path_on_host) => vmm
                    .set_block_device_path(drive_id, path_on_host)
                    .map(|_| api_server::VmmData::Empty),
                UpdateNetworkInterface(netif_update) => vmm
                    .update_net_device(netif_update)
                    .map(|_| api_server::VmmData::Empty),
            };
            // Run the requested action and send back the result.
            to_api
                .send(Box::new(response))
                .map_err(|_| ())
                .expect("one-shot channel closed");
        }
        Err(TryRecvError::Empty) => {
            warn!("Got a spurious notification from api thread");
        }
        Err(TryRecvError::Disconnected) => {
            panic!("The channel's sending half was disconnected. Cannot receive data.");
        }
    };
    Ok(())
}
