// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate api_server;
extern crate backtrace;
extern crate libc;
#[macro_use]
extern crate logger;
extern crate mmds;
extern crate polly;
extern crate seccomp;
extern crate timerfd;
extern crate utils;
extern crate vmm;

mod api_server_adapter;
mod metrics;

use backtrace::Backtrace;

use std::fs;
use std::io;
use std::panic;
use std::path::PathBuf;
use std::process;
use std::sync::{Arc, Mutex};

use logger::{Metric, LOGGER, METRICS};
use polly::event_manager::EventManager;
use seccomp::{BpfProgram, SeccompLevel};
use utils::arg_parser::{ArgParser, Argument};
use utils::terminal::Terminal;
use utils::validators::validate_instance_id;
use vmm::default_syscalls::get_seccomp_filter;
use vmm::resources::VmResources;
use vmm::signal_handler::register_signal_handlers;
use vmm::vmm_config::instance_info::InstanceInfo;

// The reason we place default API socket under /run is that API socket is a
// runtime file.
// see https://refspecs.linuxfoundation.org/FHS_3.0/fhs/ch03s15.html for more information.
const DEFAULT_API_SOCK_PATH: &str = "/run/firecracker.socket";
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

    let mut arg_parser = ArgParser::new()
        .arg(
            Argument::new("api-sock")
                .takes_value(true)
                .default_value(DEFAULT_API_SOCK_PATH)
                .help("Path to unix domain socket used by the API."),
        )
        .arg(
            Argument::new("id")
                .takes_value(true)
                .default_value(DEFAULT_INSTANCE_ID)
                .help("MicroVM unique identifier."),
        )
        .arg(
            Argument::new("seccomp-level")
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
            Argument::new("start-time-us")
                .takes_value(true),
        )
        .arg(
            Argument::new("start-time-cpu-us")
                .takes_value(true),
        )
        .arg(
            Argument::new("config-file")
                .takes_value(true)
                .help("Path to a file that contains the microVM configuration in JSON format."),
        )
        .arg(
            Argument::new("no-api")
                .takes_value(false)
                .requires("config-file")
                .help("Optional parameter which allows starting and using a microVM without an active API socket.")
        );

    let arguments = match arg_parser.parse_from_cmdline() {
        Err(err) => {
            error!(
                "Arguments parsing error: {} \n\n\
                 For more information try --help.",
                err
            );
            process::exit(i32::from(vmm::FC_EXIT_CODE_ARG_PARSING));
        }
        _ => {
            if let Some(help) = arg_parser.arguments().value_as_bool("help") {
                if help {
                    println!("Firecracker v{}\n", FIRECRACKER_VERSION);
                    println!("{}", arg_parser.formatted_help());
                    process::exit(i32::from(vmm::FC_EXIT_CODE_OK));
                }
            }
            arg_parser.arguments()
        }
    };

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

    let vmm_config_json = arguments
        .value_as_string("config-file")
        .map(fs::read_to_string)
        .map(|x| x.expect("Unable to open or read from the configuration file"));

    let api_enabled = !arguments.value_as_bool("no-api").unwrap_or(false);

    LOGGER.set_instance_id(instance_id.clone());

    if api_enabled {
        let bind_path = arguments
            .value_as_string("api-sock")
            .map(PathBuf::from)
            .expect("Missing argument: api-sock");

        let start_time_us = arguments.value_as_string("start-time-us").map(|s| {
            s.parse::<u64>()
                .expect("'start-time-us' parameter expected to be of 'u64' type.")
        });

        let start_time_cpu_us = arguments.value_as_string("start-time-cpu-us").map(|s| {
            s.parse::<u64>()
                .expect("'start-time-cpu_us' parameter expected to be of 'u64' type.")
        });
        let instance_info = InstanceInfo {
            id: instance_id,
            started: false,
            vmm_version: FIRECRACKER_VERSION.to_string(),
        };
        api_server_adapter::run_with_api(
            seccomp_filter,
            vmm_config_json,
            bind_path,
            instance_info,
            start_time_us,
            start_time_cpu_us,
        );
    } else {
        run_without_api(seccomp_filter, vmm_config_json);
    }
}

// Configure and start a microVM as described by the command-line JSON.
fn build_microvm_from_json(
    seccomp_filter: BpfProgram,
    epoll_context: &mut vmm::EpollContext,
    event_manager: &mut EventManager,
    config_json: String,
) -> (VmResources, Arc<Mutex<vmm::Vmm>>) {
    let vm_resources =
        VmResources::from_json(&config_json, FIRECRACKER_VERSION).unwrap_or_else(|err| {
            error!(
                "Configuration for VMM from one single json failed: {:?}",
                err
            );
            process::exit(i32::from(vmm::FC_EXIT_CODE_BAD_CONFIGURATION));
        });
    let vmm =
        vmm::builder::build_microvm(&vm_resources, epoll_context, event_manager, &seccomp_filter)
            .unwrap_or_else(|err| {
                error!(
                    "Building VMM configured from cmdline json failed: {:?}",
                    err
                );
                process::exit(i32::from(vmm::FC_EXIT_CODE_BAD_CONFIGURATION));
            });
    info!("Successfully started microvm that was configured from one single json");

    (vm_resources, vmm)
}

fn run_without_api(seccomp_filter: BpfProgram, config_json: Option<String>) {
    // The driving epoll engine.
    let mut epoll_context = vmm::EpollContext::new().expect("Cannot create the epoll context.");
    let mut event_manager = EventManager::new().expect("Unable to create EventManager");

    // Create the firecracker metrics object responsible for periodically printing metrics.
    let firecracker_metrics = Arc::new(Mutex::new(metrics::PeriodicMetrics::new()));
    event_manager
        .register(firecracker_metrics.clone())
        .expect("Cannot register the metrics event to the event manager.");

    // Build the microVm. We can ignore the returned values here because:
    // - VmResources is not used without api,
    // - An `Arc` reference of the built `Vmm` is plugged in the `EventManager` by the builder.
    build_microvm_from_json(
        seccomp_filter,
        &mut epoll_context,
        &mut event_manager,
        // Safe to unwrap since '--no-api' requires this to be set.
        config_json.unwrap(),
    );

    // Start the metrics.
    firecracker_metrics
        .lock()
        .expect("Metrics lock poisoned.")
        .start(metrics::WRITE_METRICS_PERIOD_MS);

    // TODO: remove this when last epoll_context user is migrated to EventManager.
    let epoll_context = Arc::new(Mutex::new(epoll_context));
    event_manager.register(epoll_context).unwrap();

    // Run the EventManager that drives everything in the microVM.
    loop {
        event_manager.run().unwrap();
    }
}
