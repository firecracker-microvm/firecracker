// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod api_server_adapter;
mod metrics;

use std::fs::{self, File};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::{io, panic, process};

use clap::Parser;
use event_manager::SubscriberOps;
use logger::{error, info, ProcessTimeReporter, StoreMetric, LOGGER, METRICS};
use seccompiler::BpfThreadMap;
use snapshot::Snapshot;
use utils::terminal::Terminal;
use utils::validators::validate_instance_id;
use vmm::resources::VmResources;
use vmm::seccomp_filters::{get_filters, SeccompConfig};
use vmm::signal_handler::register_signal_handlers;
use vmm::version_map::{FC_VERSION_TO_SNAP_VERSION, VERSION_MAP};
use vmm::vmm_config::instance_info::{InstanceInfo, VmState};
use vmm::vmm_config::logger::{init_logger, LoggerConfig, LoggerLevel};
use vmm::vmm_config::metrics::{init_metrics, MetricsConfig};
use vmm::{EventManager, FcExitCode, HTTP_MAX_PAYLOAD_SIZE};

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

    // SAFETY: Parameters are valid since they are copied verbatim
    // from the kernel's UAPI.
    // PR_SET_SPECULATION_CTRL only uses those 2 parameters, so it's ok
    // to leave the latter 2 as zero.
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

fn main_exitable() -> FcExitCode {
    LOGGER
        .configure(Some(DEFAULT_INSTANCE_ID.to_string()))
        .expect("Failed to register logger");

    if let Err(err) = register_signal_handlers() {
        error!("Failed to register signal handlers: {}", err);
        return vmm::FcExitCode::GenericError;
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
        if let Err(err) = stdin.lock().set_canon_mode() {
            error!(
                "Failure while trying to reset stdin to canonical mode: {}",
                err
            );
        }

        METRICS.vmm.panic_count.store(1);

        // Write the metrics before aborting.
        if let Err(err) = METRICS.write() {
            error!("Failed to write metrics while panicking: {}", err);
        }
    }));

    let arguments = match Args::try_parse() {
        Err(err) => {
            error!(
                "Arguments parsing error: {} \n\nFor more information try --help.",
                err
            );
            return vmm::FcExitCode::ArgParsing;
        }
        Ok(args) => {
            if args.version {
                println!("Firecracker v{}\n", FIRECRACKER_VERSION);
                print_supported_snapshot_versions();
                return vmm::FcExitCode::Ok;
            }
            if let Some(snapshot_path) = args.describe_snapshot {
                print_snapshot_data_format(&snapshot_path);
                return vmm::FcExitCode::Ok;
            }

            args
        }
    };

    // Display warnings for any used deprecated parameters.
    // Currently unused since there are no deprecated parameters. Uncomment the line when
    // deprecating one.
    // warn_deprecated_parameters(&arguments);

    let instance_id = arguments.id;
    validate_instance_id(instance_id.as_str()).expect("Invalid instance ID");

    let instance_info = InstanceInfo {
        id: instance_id.clone(),
        state: VmState::NotStarted,
        vmm_version: FIRECRACKER_VERSION.to_string(),
        app_name: "Firecracker".to_string(),
    };

    LOGGER.set_instance_id(instance_id);

    if let Some(log) = arguments.log_path {
        let level = arguments.level;
        let logger_level = match LoggerLevel::from_string(level) {
            Ok(level) => level,
            Err(err) => {
                return generic_error_exit(&format!(
                    "Invalid value for logger level: {}.Possible values: [Error, Warning, Info, \
                     Debug]",
                    err
                ));
            }
        };
        let show_level = arguments.show_level;
        let show_log_origin = arguments.show_log_origin;

        let logger_config = LoggerConfig::new(
            PathBuf::from(log),
            logger_level,
            show_level,
            show_log_origin,
        );
        if let Err(err) = init_logger(logger_config, &instance_info) {
            return generic_error_exit(&format!("Could not initialize logger: {}", err));
        };
    }

    if let Some(metrics_path) = arguments.metrics_path {
        let metrics_config = MetricsConfig {
            metrics_path: PathBuf::from(metrics_path),
        };
        if let Err(err) = init_metrics(metrics_config) {
            return generic_error_exit(&format!("Could not initialize metrics: {}", err));
        };
    }

    let mut seccomp_filters: BpfThreadMap =
        match SeccompConfig::from_args(arguments.no_seccomp, arguments.seccomp_filter.as_ref())
            .and_then(get_filters)
        {
            Ok(filters) => filters,
            Err(err) => {
                return generic_error_exit(&format!("Seccomp error: {}", err));
            }
        };

    let vmm_config_json = arguments
        .config_file
        .map(fs::read_to_string)
        .map(|x| x.expect("Unable to open or read from the configuration file"));

    let metadata_json = arguments
        .metadata
        .map(fs::read_to_string)
        .map(|x| x.expect("Unable to open or read from the mmds content file"));

    let boot_timer_enabled = arguments.boot_timer;
    let api_enabled = !arguments.no_api;
    let api_payload_limit = arguments.http_api_max_payload_size;

    // If the mmds size limit is not explicitly configured, default to using the
    // `http-api-max-payload-size` value.
    let mmds_size_limit = arguments.mmds_size_limit.unwrap_or(api_payload_limit);

    if api_enabled {
        let bind_path = arguments
            .api_sock
            .map(PathBuf::from)
            .expect("Missing argument: api-sock");

        let start_time_us = arguments.start_time_us;
        let start_time_cpu_us = arguments.start_time_cpu_us;
        let parent_cpu_time_us = arguments.parent_cpu_time_us;

        let process_time_reporter =
            ProcessTimeReporter::new(start_time_us, start_time_cpu_us, parent_cpu_time_us);
        api_server_adapter::run_with_api(
            &mut seccomp_filters,
            vmm_config_json,
            bind_path,
            instance_info,
            process_time_reporter,
            boot_timer_enabled,
            api_payload_limit,
            mmds_size_limit,
            metadata_json.as_deref(),
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
            mmds_size_limit,
            metadata_json.as_deref(),
        )
    }
}

#[derive(Debug, Parser)]
struct Args {
    /// Path to unix domain socket used by the API.
    #[arg(long, default_value = Some(DEFAULT_API_SOCK_PATH))]
    api_sock: Option<String>,
    /// MicroVM unique identifier.
    #[arg(long, default_value = DEFAULT_INSTANCE_ID)]
    id: String,

    // TODO `seccomp_filter` and `no_seccomp` are mutally exclusive, these should be replaced with
    // 1 argument `seccomp_filter: SeccompFilter` where
    // `enum SeccompFilter { None, Default, Custom(String) }`.
    /// Optional paramter which allows specifying the path to a custom seccomp filter. For advanced
    /// users.
    #[arg(long, default_value = None)]
    seccomp_filter: Option<String>,
    /// Optional parameter which allows starting and using a microVM without seccomp filtering. Not
    /// recommended.
    #[arg(long, default_value_t = false)]
    no_seccomp: bool,

    /// Process start time (wall clock, microseconds). This parameter is optional.
    #[arg(long, default_value = None)]
    start_time_us: Option<u64>,
    /// Process start CPU time (wall clock, microseconds). This parameter is optional.
    #[arg(long, default_value = None)]
    start_time_cpu_us: Option<u64>,
    /// Parent process CPU time (wall clock, microseconds). This parameter is optional.
    #[arg(long, default_value = None)]
    parent_cpu_time_us: Option<u64>,

    // TODO When `no_api` is true it requires `config_file.is_some()`, when `no_api` is false it
    // requires `api_sock.is_some()`, these arguments should be replaced with 1 argument
    // `config: Config` where
    // `enum Config { FileAndApi(String, String), Api(String), File(String) }`
    /// Path to a file that contains the microVM configuration in JSON format.
    #[arg(long, default_value = None)]
    config_file: Option<String>, // TODO Should this be `Option<std::path::Path>`?
    /// Optional parameter which allows starting and using a microVM without an active API socket.
    #[arg(long, default_value_t = false)]
    no_api: bool,

    /// Path to a file that contains metadata in JSON format to add to the mmds.
    #[arg(long, default_value = None)]
    metadata: Option<String>, // TODO Should this be `Option<std::path::Path>`?

    // TODO Most loggers default to setting up from enviroment variables, could we do this instead
    // of passing the setup via the command line?
    /// Path to a fifo or a file used for configuring the logger on startup.
    #[arg(long, default_value = None)]
    log_path: Option<String>,
    /// Set the logger level.
    #[arg(long, default_value = "Warning")]
    level: String,
    /// Whether or not to output the level in the logs.
    #[arg(long, default_value_t = false)]
    show_level: bool,
    /// Whether or not to include the file path and line number of the log's origin.
    #[arg(long, default_value_t = false)]
    show_log_origin: bool,

    /// Path to a fifo or a file used for configuring the metrics on startup.
    #[arg(long, default_value = None)]
    metrics_path: Option<String>, // TODO Should this be `Option<std::path::Path>`?
    /// Whether or not to load boot timer device for logging elapsed time since InstanceStart
    /// command.
    #[arg(long, default_value_t = false)]
    boot_timer: bool,
    /// Print the binary version number and a list of supported snapshot data format versions.
    #[arg(long, default_value_t = false)]
    version: bool,

    /// Print the data format version of the provided snapshot state file.
    #[arg(long, default_value = None)]
    describe_snapshot: Option<String>,
    /// Http API request payload max size, in bytes.
    #[arg(long, default_value_t = HTTP_MAX_PAYLOAD_SIZE)]
    http_api_max_payload_size: usize,
    /// Mmds data store limit, in bytes.
    mmds_size_limit: Option<usize>,
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
    std::process::exit(exit_code as i32);
}

// Exit gracefully with a generic error code.
fn generic_error_exit(msg: &str) -> FcExitCode {
    error!("{}", msg);
    vmm::FcExitCode::GenericError
}

// Log a warning for any usage of deprecated parameters.
#[allow(unused)]
fn warn_deprecated_parameters() {}

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
        process::exit(
            generic_error_exit(&format!("Unable to open snapshot state file: {:?}", err)) as i32,
        );
    });
    let data_format_version = Snapshot::get_data_version(&mut snapshot_reader, &VERSION_MAP)
        .unwrap_or_else(|err| {
            process::exit(generic_error_exit(&format!(
                "Invalid data format version of snapshot file: {:?}",
                err
            )) as i32);
        });

    let (key, _) = FC_VERSION_TO_SNAP_VERSION
        .iter()
        .find(|(_, &val)| val == data_format_version)
        .unwrap_or_else(|| {
            process::exit(generic_error_exit(&format!(
                "Cannot translate snapshot data version {} to Firecracker microVM version",
                data_format_version
            )) as i32);
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
    mmds_size_limit: usize,
    metadata_json: Option<&str>,
) -> std::result::Result<(VmResources, Arc<Mutex<vmm::Vmm>>), FcExitCode> {
    let mut vm_resources =
        VmResources::from_json(&config_json, &instance_info, mmds_size_limit, metadata_json)
            .map_err(|err| {
                error!("Configuration for VMM from one single json failed: {}", err);
                vmm::FcExitCode::BadConfiguration
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
        vmm::FcExitCode::BadConfiguration
    })?;
    info!("Successfully started microvm that was configured from one single json");

    Ok((vm_resources, vmm))
}

fn run_without_api(
    seccomp_filters: &BpfThreadMap,
    config_json: Option<String>,
    instance_info: InstanceInfo,
    bool_timer_enabled: bool,
    mmds_size_limit: usize,
    metadata_json: Option<&str>,
) -> FcExitCode {
    let mut event_manager = EventManager::new().expect("Unable to create EventManager");

    // Create the firecracker metrics object responsible for periodically printing metrics.
    let firecracker_metrics = Arc::new(Mutex::new(metrics::PeriodicMetrics::new()));
    event_manager.add_subscriber(firecracker_metrics.clone());

    // Build the microVm. We can ignore VmResources since it's not used without api.
    let (_, vmm) = match build_microvm_from_json(
        seccomp_filters,
        &mut event_manager,
        // Safe to unwrap since '--no-api' requires this to be set.
        config_json.unwrap(),
        instance_info,
        bool_timer_enabled,
        mmds_size_limit,
        metadata_json,
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
