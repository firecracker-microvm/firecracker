// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate api_server;
extern crate backtrace;
#[macro_use(crate_version, crate_authors)]
extern crate clap;
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
use clap::{App, Arg};

use std::fs;
use std::io;
use std::panic;
use std::path::PathBuf;
use std::process;
use std::sync::{Arc, Mutex};

use logger::{Metric, LOGGER, METRICS};
use polly::event_manager::EventManager;
use utils::terminal::Terminal;
use utils::validators::validate_instance_id;
use vmm::resources::VmResources;
use vmm::signal_handler::register_signal_handlers;
use vmm::vmm_config::instance_info::InstanceInfo;

const DEFAULT_API_SOCK_PATH: &str = "/tmp/firecracker.socket";
const DEFAULT_INSTANCE_ID: &str = "anonymous-instance";

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

    let cmd_arguments = App::new("firecracker")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Launch a microvm.")
        .arg(
            Arg::with_name("api_sock")
                .long("api-sock")
                .help("Path to unix domain socket used by the API")
                .takes_value(true)
                .default_value(DEFAULT_API_SOCK_PATH),
        )
        .arg(
            Arg::with_name("id")
                .long("id")
                .help("MicroVM unique identifier")
                .takes_value(true)
                .default_value(DEFAULT_INSTANCE_ID)
                .validator(|s: String| -> Result<(), String> {
                    validate_instance_id(&s).map_err(|e| format!("{}", e))
                }),
        )
        .arg(
            Arg::with_name("seccomp-level")
                .long("seccomp-level")
                .help(
                    "Level of seccomp filtering.\n
                            - Level 0: No filtering.\n
                            - Level 1: Seccomp filtering by syscall number.\n
                            - Level 2: Seccomp filtering by syscall number and argument values.\n
                        ",
                )
                .takes_value(true)
                .default_value("2")
                .possible_values(&["0", "1", "2"]),
        )
        .arg(
            Arg::with_name("start-time-us")
                .long("start-time-us")
                .takes_value(true)
                .hidden(true),
        )
        .arg(
            Arg::with_name("start-time-cpu-us")
                .long("start-time-cpu-us")
                .takes_value(true)
                .hidden(true),
        )
        .arg(
            Arg::with_name("config-file")
                .long("config-file")
                .help("Path to a file that contains the microVM configuration in JSON format.")
                .takes_value(true)
                .required(false),
        )
        .arg(
            Arg::with_name("no-api")
                .long("no-api")
                .help("Optional parameter which allows starting and using a microVM without an active API socket.")
                .takes_value(false)
                .required(false)
                .requires("config-file")
        )
        .get_matches();

    // It's safe to unwrap here because clap's been provided with a default value
    let instance_id = cmd_arguments.value_of("id").unwrap().to_string();

    // It's safe to unwrap here because clap's been provided with a default value,
    // and allowed values are guaranteed to parse to u32.
    let seccomp_level = cmd_arguments
        .value_of("seccomp-level")
        .unwrap()
        .parse::<u32>()
        .unwrap();

    let vmm_config_json = cmd_arguments
        .value_of("config-file")
        .map(fs::read_to_string)
        .map(|x| x.expect("Unable to open or read from the configuration file"));

    let api_enabled = !cmd_arguments.is_present("no-api");

    LOGGER.set_instance_id(instance_id.clone());

    if api_enabled {
        let bind_path = cmd_arguments
            .value_of("api_sock")
            .map(PathBuf::from)
            .expect("Missing argument: api_sock");

        let start_time_us = cmd_arguments.value_of("start-time-us").map(|s| {
            s.parse::<u64>()
                .expect("'start-time-us' parameter expected to be of 'u64' type.")
        });

        let start_time_cpu_us = cmd_arguments.value_of("start-time-cpu-us").map(|s| {
            s.parse::<u64>()
                .expect("'start-time-cpu_us' parameter expected to be of 'u64' type.")
        });
        let instance_info = InstanceInfo {
            id: instance_id,
            started: false,
            vmm_version: crate_version!().to_string(),
        };
        api_server_adapter::run_with_api(
            seccomp_level,
            vmm_config_json,
            bind_path,
            instance_info,
            start_time_us,
            start_time_cpu_us,
        );
    } else {
        run_without_api(seccomp_level, vmm_config_json);
    }
}

// Configure and start a microVM as described by the command-line JSON.
fn build_microvm_from_json(
    seccomp_level: u32,
    epoll_context: &mut vmm::EpollContext,
    event_manager: &mut EventManager,
    firecracker_version: String,
    config_json: String,
) -> (VmResources, Arc<Mutex<vmm::Vmm>>) {
    let vm_resources =
        VmResources::from_json(&config_json, &firecracker_version).unwrap_or_else(|err| {
            error!(
                "Configuration for VMM from one single json failed: {:?}",
                err
            );
            process::exit(i32::from(vmm::FC_EXIT_CODE_BAD_CONFIGURATION));
        });
    let vmm =
        vmm::builder::build_microvm(&vm_resources, epoll_context, event_manager, seccomp_level)
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

fn run_without_api(seccomp_level: u32, config_json: Option<String>) {
    // The driving epoll engine.
    let mut epoll_context = vmm::EpollContext::new().expect("Cannot create the epoll context.");
    let mut event_manager = EventManager::new().expect("Unable to create EventManager");

    // Create the firecracker metrics object responsible for periodically printing metrics.
    let firecracker_metrics = Arc::new(Mutex::new(metrics::PeriodicMetrics::new()));
    event_manager
        .register(firecracker_metrics.clone())
        .expect("Cannot register the metrics event to the event manager.");

    build_microvm_from_json(
        seccomp_level,
        &mut epoll_context,
        &mut event_manager,
        crate_version!().to_string(),
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
