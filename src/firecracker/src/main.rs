// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
mod api_server_adapter;
mod metrics;

use std::fs::{self, File};
use std::io;
use std::panic;
use std::path::PathBuf;
use std::process;
use std::sync::{Arc, Mutex};

use logger::{error, info, warn, IncMetric, ProcessTimeReporter, LOGGER, METRICS};
use polly::event_manager::EventManager;
use seccompiler::BpfThreadMap;
use snapshot::Snapshot;
use utils::arg_parser::{ArgParser, Argument, Arguments};
use utils::terminal::Terminal;
use utils::validators::validate_instance_id;
use vmm::resources::VmResources;
use vmm::seccomp_filters::{get_filters, SeccompConfig};
use vmm::signal_handler::register_signal_handlers;
use vmm::version_map::{FC_VERSION_TO_SNAP_VERSION, VERSION_MAP};
use vmm::vmm_config::instance_info::{InstanceInfo, VmState};
use vmm::vmm_config::logger::{init_logger, LoggerConfig, LoggerLevel};
use vmm::ExitCode;

// The reason we place default API socket under /run is that API socket is a
// runtime file.
// see https://refspecs.linuxfoundation.org/FHS_3.0/fhs/ch03s15.html for more information.
const DEFAULT_API_SOCK_PATH: &str = "/run/firecracker.socket";
const DEFAULT_INSTANCE_ID: &str = "anonymous-instance";
const FIRECRACKER_VERSION: &str = env!("FIRECRACKER_VERSION");

#[cfg(target_arch = "aarch64")]
/// Enable SSBD mitigation through `prctl`.
pub fn enable_ssbd_mitigation() {
    // Parameters for `prctl`
    // TODO: generate bindings for these from the kernel sources.
    // https://elixir.bootlin.com/linux/v4.17/source/include/uapi/linux/prctl.h#L212
    const PR_SET_SPECULATION_CTRL: i32 = 53;
    const PR_SPEC_STORE_BYPASS: u64 = 0;
    const PR_SPEC_FORCE_DISABLE: u64 = 1u64 << 3;

    let ret = unsafe {
        libc::prctl(
            PR_SET_SPECULATION_CTRL,
            PR_SPEC_STORE_BYPASS,
            PR_SPEC_FORCE_DISABLE,
            0,
            0,
        )
    };

    if ret < 0 {
        let last_error = std::io::Error::last_os_error().raw_os_error().unwrap();
        error!(
            "Could not enable SSBD mitigation through prctl, error {}",
            last_error
        );
        if last_error == libc::EINVAL {
            error!("The host does not support SSBD mitigation through prctl.");
        }
    }
}

fn main_exitable() -> ExitCode {
    LOGGER
        .configure(Some(DEFAULT_INSTANCE_ID.to_string()))
        .expect("Failed to register logger");

    if let Err(e) = register_signal_handlers() {
        error!("Failed to register signal handlers: {}", e);
        return vmm::FC_EXIT_CODE_GENERIC_ERROR;
    }

    #[cfg(target_arch = "aarch64")]
    enable_ssbd_mitigation();

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
                .help("Deprecated! Level of seccomp filtering (0: no filter | 1: filter by syscall number | 2: filter by syscall \
                number and argument values.")
        )
        .arg(
            Argument::new("seccomp-filter")
                .takes_value(true)
                .forbids(vec!["seccomp-level", "no-seccomp"])
                .help(
                    "Optional parameter which allows specifying the path to a custom seccomp filter. For advanced users."
                ),
        )
        .arg(
            Argument::new("no-seccomp")
                .takes_value(false)
                .forbids(vec!["seccomp-level"])
                .help("Optional parameter which allows starting and using a microVM without seccomp filtering. \
                    Not recommended.")
        )
        .arg(
            Argument::new("start-time-us")
                .takes_value(true)
                .help("Process start time (wall clock, microseconds). This parameter is optional."),
        )
        .arg(
            Argument::new("start-time-cpu-us")
                .takes_value(true)
                .help("Process start CPU time (wall clock, microseconds). This parameter is optional."),
        )
        .arg(
            Argument::new("parent-cpu-time-us")
                .takes_value(true)
                .help("Parent process CPU time (wall clock, microseconds). This parameter is optional."),
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
        )
        .arg(
            Argument::new("boot-timer")
                .takes_value(false)
                .help("Whether or not to load boot timer device for logging elapsed time since InstanceStart command.")
        )
        .arg(
            Argument::new("version")
                .takes_value(false)
                .help("Print the binary version number and a list of supported snapshot data format versions.")
        )
        .arg(
            Argument::new("describe-snapshot")
                .takes_value(true)
                .help("Print the data format version of the provided snapshot state file.")
        );

    let arguments = match arg_parser.parse_from_cmdline() {
        Err(err) => {
            error!(
                "Arguments parsing error: {} \n\n\
                 For more information try --help.",
                err
            );
            return vmm::FC_EXIT_CODE_ARG_PARSING;
        }
        _ => {
            if arg_parser.arguments().flag_present("help") {
                println!("Firecracker v{}\n", FIRECRACKER_VERSION);
                println!("{}", arg_parser.formatted_help());
                return vmm::FC_EXIT_CODE_OK;
            }

            if arg_parser.arguments().flag_present("version") {
                println!("Firecracker v{}\n", FIRECRACKER_VERSION);
                print_supported_snapshot_versions();
                return vmm::FC_EXIT_CODE_OK;
            }

            if let Some(snapshot_path) = arg_parser.arguments().single_value("describe-snapshot") {
                print_snapshot_data_format(snapshot_path);
                return vmm::FC_EXIT_CODE_OK;
            }

            arg_parser.arguments()
        }
    };

    // Display warnings for any used deprecated parameters.
    warn_deprecated_parameters(&arguments);

    // It's safe to unwrap here because the field's been provided with a default value.
    let instance_id = arguments.single_value("id").unwrap();
    validate_instance_id(instance_id.as_str()).expect("Invalid instance ID");

    let instance_info = InstanceInfo {
        id: instance_id.clone(),
        state: VmState::NotStarted,
        vmm_version: FIRECRACKER_VERSION.to_string(),
        app_name: "Firecracker".to_string(),
    };

    LOGGER.set_instance_id(instance_id.to_owned());

    if let Some(log) = arguments.single_value("log-path") {
        // It's safe to unwrap here because the field's been provided with a default value.
        let level = arguments.single_value("level").unwrap().to_owned();
        let logger_level = match LoggerLevel::from_string(level) {
            Ok(level) => level,
            Err(e) => {
                return generic_error_exit(&format!(
                    "Invalid value for logger level: {}.\
                    Possible values: [Error, Warning, Info, Debug]",
                    e
                ));
            }
        };
        let show_level = arguments.flag_present("show-level");
        let show_log_origin = arguments.flag_present("show-log-origin");

        let logger_config = LoggerConfig::new(
            PathBuf::from(log),
            logger_level,
            show_level,
            show_log_origin,
        );
        if let Err(e) = init_logger(logger_config, &instance_info) {
            return generic_error_exit(&format!("Could not initialize logger:: {}", e));
        };
    }

    let mut seccomp_filters: BpfThreadMap = match SeccompConfig::from_args(
        arguments.single_value("seccomp-level"),
        arguments.flag_present("no-seccomp"),
        arguments.single_value("seccomp-filter"),
    )
    .and_then(get_filters)
    {
        Ok(filters) => filters,
        Err(e) => {
            return generic_error_exit(&format!("Seccomp error: {}", e));
        }
    };

    let vmm_config_json = arguments
        .single_value("config-file")
        .map(fs::read_to_string)
        .map(|x| x.expect("Unable to open or read from the configuration file"));

    let boot_timer_enabled = arguments.flag_present("boot-timer");
    let api_enabled = !arguments.flag_present("no-api");

    if api_enabled {
        let bind_path = arguments
            .single_value("api-sock")
            .map(PathBuf::from)
            .expect("Missing argument: api-sock");

        let start_time_us = arguments.single_value("start-time-us").map(|s| {
            s.parse::<u64>()
                .expect("'start-time-us' parameter expected to be of 'u64' type.")
        });

        let start_time_cpu_us = arguments.single_value("start-time-cpu-us").map(|s| {
            s.parse::<u64>()
                .expect("'start-time-cpu-us' parameter expected to be of 'u64' type.")
        });

        let parent_cpu_time_us = arguments.single_value("parent-cpu-time-us").map(|s| {
            s.parse::<u64>()
                .expect("'parent-cpu-time-us' parameter expected to be of 'u64' type.")
        });

        let process_time_reporter =
            ProcessTimeReporter::new(start_time_us, start_time_cpu_us, parent_cpu_time_us);
        api_server_adapter::run_with_api(
            &mut seccomp_filters,
            vmm_config_json,
            bind_path,
            instance_info,
            process_time_reporter,
            boot_timer_enabled,
        )
    } else {
        let seccomp_filters: BpfThreadMap = seccomp_filters
            .into_iter()
            .filter(|(k, _)| k != "api")
            .collect();
        run_without_api(
            &seccomp_filters,
            vmm_config_json,
            instance_info,
            boot_timer_enabled,
        )
    }
}

fn main() {
    // This idiom is the prescribed way to get a clean shutdown of Rust (that will report
    // no leaks in Valgrind or sanitizers).  Calling `unsafe { libc::exit() }` does no
    // cleanup, and std::process::exit() does more--but does not run destructors.  So the
    // best thing to do is to is bubble up the exit code through the whole stack, and
    // only exit when everything potentially destructible has cleaned itself up.
    //
    // https://doc.rust-lang.org/std/process/fn.exit.html
    //
    // See process_exitable() method of Subscriber trait for what triggers the exit_code.
    //
    let exit_code = main_exitable();
    std::process::exit(i32::from(exit_code));
}

// Exit gracefully with a generic error code.
fn generic_error_exit(msg: &str) -> ExitCode {
    error!("{}", msg);
    vmm::FC_EXIT_CODE_GENERIC_ERROR
}

// Log a warning for any usage of deprecated parameters.
fn warn_deprecated_parameters(arguments: &Arguments) {
    // --seccomp-level is deprecated.
    if let Some(value) = arguments.single_value("seccomp-level") {
        warn!(
            "You are using a deprecated parameter: --seccomp-level {}, that will be removed in a\
            future version.",
            value
        );
    }
}

// Print supported snapshot data format versions.
fn print_supported_snapshot_versions() {
    let mut snapshot_versions_str = "Supported snapshot data format versions:".to_string();
    let mut snapshot_versions: Vec<String> = FC_VERSION_TO_SNAP_VERSION
        .iter()
        .map(|(key, _)| key.clone())
        .collect();
    snapshot_versions.sort();

    snapshot_versions
        .iter()
        .for_each(|v| snapshot_versions_str.push_str(format!(" v{},", v).as_str()));
    snapshot_versions_str.pop();
    println!("{}\n", snapshot_versions_str);
}

// Print data format of provided snapshot state file.
fn print_snapshot_data_format(snapshot_path: &str) {
    let mut snapshot_reader = File::open(snapshot_path).unwrap_or_else(|err| {
        process::exit(i32::from(generic_error_exit(&format!(
            "Unable to open snapshot state file: {:?}",
            err
        ))));
    });
    let data_format_version = Snapshot::get_data_version(&mut snapshot_reader, &VERSION_MAP)
        .unwrap_or_else(|err| {
            process::exit(i32::from(generic_error_exit(&format!(
                "Invalid data format version of snapshot file: {:?}",
                err
            ))));
        });

    let (key, _) = FC_VERSION_TO_SNAP_VERSION
        .iter()
        .find(|(_, &val)| val == data_format_version)
        .unwrap_or_else(|| {
            process::exit(i32::from(generic_error_exit(&format!(
                "Cannot translate snapshot data version {} to Firecracker microVM version",
                data_format_version
            ))));
        });
    println!("v{}", key);
}

// Configure and start a microVM as described by the command-line JSON.
fn build_microvm_from_json(
    seccomp_filters: &BpfThreadMap,
    event_manager: &mut EventManager,
    config_json: String,
    instance_info: InstanceInfo,
    boot_timer_enabled: bool,
) -> std::result::Result<(VmResources, Arc<Mutex<vmm::Vmm>>), ExitCode> {
    let mut vm_resources = VmResources::from_json(&config_json, &instance_info).map_err(|err| {
        error!(
            "Configuration for VMM from one single json failed: {:?}",
            err
        );
        vmm::FC_EXIT_CODE_BAD_CONFIGURATION
    })?;
    vm_resources.boot_timer = boot_timer_enabled;
    let vmm = vmm::builder::build_microvm_for_boot(
        &instance_info,
        &vm_resources,
        event_manager,
        seccomp_filters,
    )
    .map_err(|err| {
        error!(
            "Building VMM configured from cmdline json failed: {:?}",
            err
        );
        vmm::FC_EXIT_CODE_BAD_CONFIGURATION
    })?;
    info!("Successfully started microvm that was configured from one single json");

    Ok((vm_resources, vmm))
}

fn run_without_api(
    seccomp_filters: &BpfThreadMap,
    config_json: Option<String>,
    instance_info: InstanceInfo,
    bool_timer_enabled: bool,
) -> ExitCode {
    let mut event_manager = EventManager::new().expect("Unable to create EventManager");

    // Create the firecracker metrics object responsible for periodically printing metrics.
    let firecracker_metrics = Arc::new(Mutex::new(metrics::PeriodicMetrics::new()));
    event_manager
        .add_subscriber(firecracker_metrics.clone())
        .expect("Cannot register the metrics event to the event manager.");

    // Build the microVm. We can ignore VmResources since it's not used without api.
    let (_, vmm) = match build_microvm_from_json(
        seccomp_filters,
        &mut event_manager,
        // Safe to unwrap since '--no-api' requires this to be set.
        config_json.unwrap(),
        instance_info,
        bool_timer_enabled,
    ) {
        Ok((res, vmm)) => (res, vmm),
        Err(exit_code) => return exit_code,
    };

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

        if let Some(exit_code) = vmm.lock().unwrap().shutdown_exit_code() {
            return exit_code;
        }
    }
}
