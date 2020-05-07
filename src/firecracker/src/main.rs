// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate api_server;
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
use vmm::vmm_config::logger::{init_logger, LoggerConfig, LoggerLevel};

// The reason we place default API socket under /run is that API socket is a
// runtime file.
// see https://refspecs.linuxfoundation.org/FHS_3.0/fhs/ch03s15.html for more information.
const DEFAULT_API_SOCK_PATH: &str = "/run/firecracker.socket";
const DEFAULT_INSTANCE_ID: &str = "anonymous-instance";
const FIRECRACKER_VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    LOGGER
        .configure(Some(DEFAULT_INSTANCE_ID.to_string()))
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

        // Write the metrics before aborting.
        if let Err(e) = METRICS.write() {
            error!("Failed to write metrics while panicking: {}", e);
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
                    "Level of seccomp filtering (0: no filter | 1: filter by syscall number | 2: filter by syscall \
                     number and argument values) that will be passed to executed path as argument."
                ),
        )
        .arg(
            Argument::new("start-time-us")
                .takes_value(true)
                .help("Process start time (wall clock, microseconds)."),
        )
        .arg(
            Argument::new("start-time-cpu-us")
                .takes_value(true)
                .help("Process start CPU time (wall clock, microseconds)."),
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
        )
        .arg(
            Argument::new("log-path")
                .takes_value(true)
                .help("Path to a fifo or a file used for configuring the logger on startup.")
        )
        .arg(
            Argument::new("level")
                .takes_value(true)
                .requires("log-path")
                .default_value("Warning")
                .help("Set the logger level.")
        )
        .arg(
            Argument::new("show-level")
                .takes_value(false)
                .requires("log-path")
                .help("Whether or not to output the level in the logs.")
        )
        .arg(
            Argument::new("show-log-origin")
                .takes_value(false)
                .requires("log-path")
                .help("Whether or not to include the file path and line number of the log's origin.")
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

            if let Some(version) = arg_parser.arguments().value_as_bool("version") {
                if version {
                    println!("Firecracker v{}\n", FIRECRACKER_VERSION);
                    process::exit(i32::from(vmm::FC_EXIT_CODE_OK));
                }
            }

            arg_parser.arguments()
        }
    };

    // It's safe to unwrap here because the field's been provided with a default value.
    let instance_id = arguments.value_as_string("id").unwrap();
    validate_instance_id(instance_id.as_str()).expect("Invalid instance ID");

    let instance_info = InstanceInfo {
        id: instance_id.clone(),
        started: false,
        vmm_version: FIRECRACKER_VERSION.to_string(),
        app_name: "Firecracker".to_string(),
    };

    LOGGER.set_instance_id(instance_id);

    if let Some(log) = arguments.value_as_string("log-path") {
        // It's safe to unwrap here because the field's been provided with a default value.
        let level = arguments.value_as_string("level").unwrap();
        let logger_level = LoggerLevel::from_string(level).unwrap_or_else(|err| {
            panic!("Invalid value for logger level: {}. Possible values: [Error, Warning, Info, Debug]", err);
        });
        let show_level = arguments.value_as_bool("show-level").unwrap_or(false);
        let show_log_origin = arguments.value_as_bool("show-log-origin").unwrap_or(false);

        let logger_config = LoggerConfig::new(
            PathBuf::from(log),
            logger_level,
            show_level,
            show_log_origin,
        );
        init_logger(logger_config, &instance_info).expect("Could not initialize logger.");
    }

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
                .expect("'start-time-cpu-us' parameter expected to be of 'u64' type.")
        });
        api_server_adapter::run_with_api(
            seccomp_filter,
            vmm_config_json,
            bind_path,
            instance_info,
            start_time_us,
            start_time_cpu_us,
        );
    } else {
        run_without_api(seccomp_filter, vmm_config_json, &instance_info);
    }
}

// Configure and start a microVM as described by the command-line JSON.
fn build_microvm_from_json(
    seccomp_filter: BpfProgram,
    event_manager: &mut EventManager,
    config_json: String,
    instance_info: &InstanceInfo,
) -> (VmResources, Arc<Mutex<vmm::Vmm>>) {
    let vm_resources = VmResources::from_json(&config_json, instance_info).unwrap_or_else(|err| {
        error!(
            "Configuration for VMM from one single json failed: {:?}",
            err
        );
        process::exit(i32::from(vmm::FC_EXIT_CODE_BAD_CONFIGURATION));
    });
    let vmm = vmm::builder::build_microvm_for_boot(&vm_resources, event_manager, &seccomp_filter)
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

fn run_without_api(
    seccomp_filter: BpfProgram,
    config_json: Option<String>,
    instance_info: &InstanceInfo,
) {
    let mut event_manager = EventManager::new().expect("Unable to create EventManager");

    // Create the firecracker metrics object responsible for periodically printing metrics.
    let firecracker_metrics = Arc::new(Mutex::new(metrics::PeriodicMetrics::new()));
    event_manager
        .add_subscriber(firecracker_metrics.clone())
        .expect("Cannot register the metrics event to the event manager.");

    // Build the microVm. We can ignore the returned values here because:
    // - VmResources is not used without api,
    // - An `Arc` reference of the built `Vmm` is plugged in the `EventManager` by the builder.
    build_microvm_from_json(
        seccomp_filter,
        &mut event_manager,
        // Safe to unwrap since '--no-api' requires this to be set.
        config_json.unwrap(),
        instance_info,
    );

    // Start the metrics.
    firecracker_metrics
        .lock()
        .expect("Poisoned lock")
        .start(metrics::WRITE_METRICS_PERIOD_MS);

    // Run the EventManager that drives everything in the microVM.
    loop {
        event_manager
            .run()
            .expect("Failed to start the event manager");
    }
}
