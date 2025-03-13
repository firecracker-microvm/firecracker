// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod api_server;
mod api_server_adapter;
mod generated;
mod metrics;
mod seccomp;

use std::fs::{self, File};
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::{io, panic};

use api_server_adapter::ApiServerError;
use event_manager::SubscriberOps;
use seccomp::FilterError;
use utils::arg_parser::{ArgParser, Argument};
use utils::validators::validate_instance_id;
use vmm::arch::host_page_size;
use vmm::builder::StartMicrovmError;
use vmm::logger::{
    LOGGER, LoggerConfig, METRICS, ProcessTimeReporter, StoreMetric, debug, error, info,
};
use vmm::persist::SNAPSHOT_VERSION;
use vmm::resources::VmResources;
use vmm::seccomp::BpfThreadMap;
use vmm::signal_handler::register_signal_handlers;
use vmm::snapshot::{Snapshot, SnapshotError};
use vmm::vmm_config::instance_info::{InstanceInfo, VmState};
use vmm::vmm_config::metrics::{MetricsConfig, MetricsConfigError, init_metrics};
use vmm::{EventManager, FcExitCode, HTTP_MAX_PAYLOAD_SIZE};
use vmm_sys_util::terminal::Terminal;

use crate::seccomp::SeccompConfig;

// The reason we place default API socket under /run is that API socket is a
// runtime file.
// see https://refspecs.linuxfoundation.org/FHS_3.0/fhs/ch03s15.html for more information.
const DEFAULT_API_SOCK_PATH: &str = "/run/firecracker.socket";
const FIRECRACKER_VERSION: &str = env!("CARGO_PKG_VERSION");
const MMDS_CONTENT_ARG: &str = "metadata";

#[derive(Debug, thiserror::Error, displaydoc::Display)]
enum MainError {
    /// Failed to set the logger: {0}
    SetLogger(vmm::logger::LoggerInitError),
    /// Failed to register signal handlers: {0}
    RegisterSignalHandlers(#[source] vmm_sys_util::errno::Error),
    /// Arguments parsing error: {0} \n\nFor more information try --help.
    ParseArguments(#[from] utils::arg_parser::UtilsArgParserError),
    /// When printing Snapshot Data format: {0}
    PrintSnapshotDataFormat(#[from] SnapshotVersionError),
    /// Invalid value for logger level: {0}.Possible values: [Error, Warning, Info, Debug]
    InvalidLogLevel(vmm::logger::LevelFilterFromStrError),
    /// Could not initialize logger: {0}
    LoggerInitialization(vmm::logger::LoggerUpdateError),
    /// Could not initialize metrics: {0}
    MetricsInitialization(MetricsConfigError),
    /// Seccomp error: {0}
    SeccompFilter(FilterError),
    /// Failed to resize fd table: {0}
    ResizeFdtable(ResizeFdTableError),
    /// RunWithApiError error: {0}
    RunWithApi(ApiServerError),
    /// RunWithoutApiError error: {0}
    RunWithoutApiError(RunWithoutApiError),
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
enum ResizeFdTableError {
    /// Failed to get RLIMIT_NOFILE
    GetRlimit,
    /// Failed to call dup2 to resize fdtable
    Dup2(io::Error),
    /// Failed to close dup2'd file descriptor
    Close(io::Error),
}

impl From<MainError> for FcExitCode {
    fn from(value: MainError) -> Self {
        match value {
            MainError::ParseArguments(_) => FcExitCode::ArgParsing,
            MainError::InvalidLogLevel(_) => FcExitCode::BadConfiguration,
            MainError::RunWithApi(ApiServerError::MicroVMStoppedWithError(code)) => code,
            MainError::RunWithoutApiError(RunWithoutApiError::Shutdown(code)) => code,
            _ => FcExitCode::GenericError,
        }
    }
}

fn main() -> ExitCode {
    let result = main_exec();
    if let Err(err) = result {
        error!("{err}");
        eprintln!("Error: {err:?}");
        let exit_code = FcExitCode::from(err) as u8;
        error!("Firecracker exiting with error. exit_code={exit_code}");
        ExitCode::from(exit_code)
    } else {
        info!("Firecracker exiting successfully. exit_code=0");
        ExitCode::SUCCESS
    }
}

fn main_exec() -> Result<(), MainError> {
    // Initialize the logger.
    LOGGER.init().map_err(MainError::SetLogger)?;

    // First call to this function updates the value to current
    // host page size.
    _ = host_page_size();

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

    let http_max_payload_size_str = HTTP_MAX_PAYLOAD_SIZE.to_string();

    let mut arg_parser =
        ArgParser::new()
            .arg(
                Argument::new("api-sock")
                    .takes_value(true)
                    .default_value(DEFAULT_API_SOCK_PATH)
                    .help("Path to unix domain socket used by the API."),
            )
            .arg(
                Argument::new("id")
                    .takes_value(true)
                    .default_value(vmm::logger::DEFAULT_INSTANCE_ID)
                    .help("MicroVM unique identifier."),
            )
            .arg(
                Argument::new("seccomp-filter")
                    .takes_value(true)
                    .forbids(vec!["no-seccomp"])
                    .help(
                        "Optional parameter which allows specifying the path to a custom seccomp \
                         filter. For advanced users.",
                    ),
            )
            .arg(
                Argument::new("no-seccomp")
                    .takes_value(false)
                    .forbids(vec!["seccomp-filter"])
                    .help(
                        "Optional parameter which allows starting and using a microVM without \
                         seccomp filtering. Not recommended.",
                    ),
            )
            .arg(
                Argument::new("start-time-us").takes_value(true).help(
                    "Process start time (wall clock, microseconds). This parameter is optional.",
                ),
            )
            .arg(Argument::new("start-time-cpu-us").takes_value(true).help(
                "Process start CPU time (wall clock, microseconds). This parameter is optional.",
            ))
            .arg(Argument::new("parent-cpu-time-us").takes_value(true).help(
                "Parent process CPU time (wall clock, microseconds). This parameter is optional.",
            ))
            .arg(
                Argument::new("config-file")
                    .takes_value(true)
                    .help("Path to a file that contains the microVM configuration in JSON format."),
            )
            .arg(
                Argument::new(MMDS_CONTENT_ARG).takes_value(true).help(
                    "Path to a file that contains metadata in JSON format to add to the mmds.",
                ),
            )
            .arg(
                Argument::new("no-api")
                    .takes_value(false)
                    .requires("config-file")
                    .help(
                        "Optional parameter which allows starting and using a microVM without an \
                         active API socket.",
                    ),
            )
            .arg(
                Argument::new("log-path")
                    .takes_value(true)
                    .help("Path to a fifo or a file used for configuring the logger on startup."),
            )
            .arg(
                Argument::new("level")
                    .takes_value(true)
                    .help("Set the logger level."),
            )
            .arg(
                Argument::new("module")
                    .takes_value(true)
                    .help("Set the logger module filter."),
            )
            .arg(
                Argument::new("show-level")
                    .takes_value(false)
                    .help("Whether or not to output the level in the logs."),
            )
            .arg(Argument::new("show-log-origin").takes_value(false).help(
                "Whether or not to include the file path and line number of the log's origin.",
            ))
            .arg(
                Argument::new("metrics-path")
                    .takes_value(true)
                    .help("Path to a fifo or a file used for configuring the metrics on startup."),
            )
            .arg(Argument::new("boot-timer").takes_value(false).help(
                "Whether or not to load boot timer device for logging elapsed time since \
                 InstanceStart command.",
            ))
            .arg(
                Argument::new("version")
                    .takes_value(false)
                    .help("Print the binary version number."),
            )
            .arg(
                Argument::new("snapshot-version")
                    .takes_value(false)
                    .help("Print the supported data format version."),
            )
            .arg(
                Argument::new("describe-snapshot")
                    .takes_value(true)
                    .help("Print the data format version of the provided snapshot state file."),
            )
            .arg(
                Argument::new("http-api-max-payload-size")
                    .takes_value(true)
                    .default_value(&http_max_payload_size_str)
                    .help("Http API request payload max size, in bytes."),
            )
            .arg(
                Argument::new("mmds-size-limit")
                    .takes_value(true)
                    .help("Mmds data store limit, in bytes."),
            );

    arg_parser.parse_from_cmdline()?;
    let arguments = arg_parser.arguments();

    if arguments.flag_present("help") {
        println!("Firecracker v{}\n", FIRECRACKER_VERSION);
        println!("{}", arg_parser.formatted_help());
        return Ok(());
    }

    if arguments.flag_present("version") {
        println!("Firecracker v{}\n", FIRECRACKER_VERSION);
        return Ok(());
    }

    if arguments.flag_present("snapshot-version") {
        println!("v{SNAPSHOT_VERSION}");
        return Ok(());
    }

    if let Some(snapshot_path) = arguments.single_value("describe-snapshot") {
        print_snapshot_data_format(snapshot_path)?;
        return Ok(());
    }

    // It's safe to unwrap here because the field's been provided with a default value.
    let instance_id = arguments.single_value("id").unwrap();
    validate_instance_id(instance_id.as_str()).expect("Invalid instance ID");

    // Apply the logger configuration.
    vmm::logger::INSTANCE_ID
        .set(String::from(instance_id))
        .unwrap();
    let log_path = arguments.single_value("log-path").map(PathBuf::from);
    let level = arguments
        .single_value("level")
        .map(|s| vmm::logger::LevelFilter::from_str(s))
        .transpose()
        .map_err(MainError::InvalidLogLevel)?;
    let show_level = arguments.flag_present("show-level").then_some(true);
    let show_log_origin = arguments.flag_present("show-log-origin").then_some(true);
    let module = arguments.single_value("module").cloned();
    LOGGER
        .update(LoggerConfig {
            log_path,
            level,
            show_level,
            show_log_origin,
            module,
        })
        .map_err(MainError::LoggerInitialization)?;
    info!("Running Firecracker v{FIRECRACKER_VERSION}");

    register_signal_handlers().map_err(MainError::RegisterSignalHandlers)?;

    #[cfg(target_arch = "aarch64")]
    enable_ssbd_mitigation();

    if let Err(err) = resize_fdtable() {
        match err {
            // These errors are non-critical: In the worst case we have worse snapshot restore
            // performance.
            ResizeFdTableError::GetRlimit | ResizeFdTableError::Dup2(_) => {
                debug!("Failed to resize fdtable: {err}")
            }
            // This error means that we now have a random file descriptor lying around, abort to be
            // cautious.
            ResizeFdTableError::Close(_) => return Err(MainError::ResizeFdtable(err)),
        }
    }

    // Display warnings for any used deprecated parameters.
    // Currently unused since there are no deprecated parameters. Uncomment the line when
    // deprecating one.
    // warn_deprecated_parameters(&arguments);

    let instance_info = InstanceInfo {
        id: instance_id.clone(),
        state: VmState::NotStarted,
        vmm_version: FIRECRACKER_VERSION.to_string(),
        app_name: "Firecracker".to_string(),
    };

    if let Some(metrics_path) = arguments.single_value("metrics-path") {
        let metrics_config = MetricsConfig {
            metrics_path: PathBuf::from(metrics_path),
        };
        init_metrics(metrics_config).map_err(MainError::MetricsInitialization)?;
    }

    let mut seccomp_filters: BpfThreadMap = SeccompConfig::from_args(
        arguments.flag_present("no-seccomp"),
        arguments.single_value("seccomp-filter"),
    )
    .and_then(seccomp::get_filters)
    .map_err(MainError::SeccompFilter)?;

    let vmm_config_json = arguments
        .single_value("config-file")
        .map(fs::read_to_string)
        .map(|x| x.expect("Unable to open or read from the configuration file"));

    let metadata_json = arguments
        .single_value(MMDS_CONTENT_ARG)
        .map(fs::read_to_string)
        .map(|x| x.expect("Unable to open or read from the mmds content file"));

    let boot_timer_enabled = arguments.flag_present("boot-timer");
    let api_enabled = !arguments.flag_present("no-api");
    let api_payload_limit = arg_parser
        .arguments()
        .single_value("http-api-max-payload-size")
        .map(|lim| {
            lim.parse::<usize>()
                .expect("'http-api-max-payload-size' parameter expected to be of 'usize' type.")
        })
        // Safe to unwrap as we provide a default value.
        .unwrap();

    // If the mmds size limit is not explicitly configured, default to using the
    // `http-api-max-payload-size` value.
    let mmds_size_limit = arg_parser
        .arguments()
        .single_value("mmds-size-limit")
        .map(|lim| {
            lim.parse::<usize>()
                .expect("'mmds-size-limit' parameter expected to be of 'usize' type.")
        })
        .unwrap_or_else(|| api_payload_limit);

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
            api_payload_limit,
            mmds_size_limit,
            metadata_json.as_deref(),
        )
        .map_err(MainError::RunWithApi)
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
        .map_err(MainError::RunWithoutApiError)
    }
}

/// Attempts to resize the processes file descriptor table to match RLIMIT_NOFILE or 2048 if no
/// RLIMIT_NOFILE is set (this can only happen if firecracker is run outside the jailer. 2048 is
/// the default the jailer would set).
///
/// We do this resizing because the kernel default is 64, with a reallocation happening whenever
/// the tabel fills up. This was happening for some larger microVMs, and reallocating the
/// fdtable while a lot of file descriptors are active (due to being eventfds/timerfds registered
/// to epoll) incurs a penalty of 30ms-70ms on the snapshot restore path.
fn resize_fdtable() -> Result<(), ResizeFdTableError> {
    let mut rlimit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };

    // SAFETY: We pass a pointer to a valid area of memory to which we have exclusive mutable access
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlimit as *mut libc::rlimit) } < 0 {
        return Err(ResizeFdTableError::GetRlimit);
    }

    // If no jailer is used, there might not be an NOFILE limit set. In this case, resize
    // the table to the default that the jailer would usually impose (2048)
    let limit: libc::c_int = if rlimit.rlim_cur == libc::RLIM_INFINITY {
        2048
    } else {
        rlimit.rlim_cur.try_into().unwrap_or(2048)
    };

    // Resize the file descriptor table to its maximal possible size, to ensure that
    // firecracker will not need to reallocate it later. If the file descriptor table
    // needs to be reallocated (which by default happens once more than 64 fds exist,
    // something that happens for reasonably complex microvms due to each device using
    // a multitude of eventfds), this can incur a significant performance impact (it
    // was responsible for a 30ms-70ms impact on snapshot restore times).
    if limit > 3 {
        // SAFETY: Duplicating stdin is safe
        if unsafe { libc::dup2(0, limit - 1) } < 0 {
            return Err(ResizeFdTableError::Dup2(io::Error::last_os_error()));
        }

        // SAFETY: Closing the just created duplicate is safe
        if unsafe { libc::close(limit - 1) } < 0 {
            return Err(ResizeFdTableError::Close(io::Error::last_os_error()));
        }
    }

    Ok(())
}

/// Enable SSBD mitigation through `prctl`.
#[cfg(target_arch = "aarch64")]
pub fn enable_ssbd_mitigation() {
    // SAFETY: Parameters are valid since they are copied verbatim
    // from the kernel's UAPI.
    // PR_SET_SPECULATION_CTRL only uses those 2 parameters, so it's ok
    // to leave the latter 2 as zero.
    let ret = unsafe {
        libc::prctl(
            generated::prctl::PR_SET_SPECULATION_CTRL,
            generated::prctl::PR_SPEC_STORE_BYPASS,
            generated::prctl::PR_SPEC_FORCE_DISABLE,
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

// Log a warning for any usage of deprecated parameters.
#[allow(unused)]
fn warn_deprecated_parameters() {}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
enum SnapshotVersionError {
    /// Unable to open snapshot state file: {0}
    OpenSnapshot(io::Error),
    /// Invalid data format version of snapshot file: {0}
    SnapshotVersion(SnapshotError),
}

// Print data format of provided snapshot state file.
fn print_snapshot_data_format(snapshot_path: &str) -> Result<(), SnapshotVersionError> {
    let mut snapshot_reader =
        File::open(snapshot_path).map_err(SnapshotVersionError::OpenSnapshot)?;

    let data_format_version = Snapshot::get_format_version(&mut snapshot_reader)
        .map_err(SnapshotVersionError::SnapshotVersion)?;

    println!("v{}", data_format_version);
    Ok(())
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum BuildFromJsonError {
    /// Configuration for VMM from one single json failed: {0}
    ParseFromJson(vmm::resources::ResourcesError),
    /// Could not Start MicroVM from one single json: {0}
    StartMicroVM(StartMicrovmError),
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
) -> Result<(VmResources, Arc<Mutex<vmm::Vmm>>), BuildFromJsonError> {
    let mut vm_resources =
        VmResources::from_json(&config_json, &instance_info, mmds_size_limit, metadata_json)
            .map_err(BuildFromJsonError::ParseFromJson)?;
    vm_resources.boot_timer = boot_timer_enabled;
    let vmm = vmm::builder::build_and_boot_microvm(
        &instance_info,
        &vm_resources,
        event_manager,
        seccomp_filters,
    )
    .map_err(BuildFromJsonError::StartMicroVM)?;

    info!("Successfully started microvm that was configured from one single json");

    Ok((vm_resources, vmm))
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
enum RunWithoutApiError {
    /// MicroVMStopped without an error: {0:?}
    Shutdown(FcExitCode),
    /// Failed to build MicroVM from Json: {0}
    BuildMicroVMFromJson(BuildFromJsonError),
}

fn run_without_api(
    seccomp_filters: &BpfThreadMap,
    config_json: Option<String>,
    instance_info: InstanceInfo,
    bool_timer_enabled: bool,
    mmds_size_limit: usize,
    metadata_json: Option<&str>,
) -> Result<(), RunWithoutApiError> {
    let mut event_manager = EventManager::new().expect("Unable to create EventManager");

    // Create the firecracker metrics object responsible for periodically printing metrics.
    let firecracker_metrics = Arc::new(Mutex::new(metrics::PeriodicMetrics::new()));
    event_manager.add_subscriber(firecracker_metrics.clone());

    // Build the microVm. We can ignore VmResources since it's not used without api.
    let (_, vmm) = build_microvm_from_json(
        seccomp_filters,
        &mut event_manager,
        // Safe to unwrap since '--no-api' requires this to be set.
        config_json.unwrap(),
        instance_info,
        bool_timer_enabled,
        mmds_size_limit,
        metadata_json,
    )
    .map_err(RunWithoutApiError::BuildMicroVMFromJson)?;

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

        match vmm.lock().unwrap().shutdown_exit_code() {
            Some(FcExitCode::Ok) => break,
            Some(exit_code) => return Err(RunWithoutApiError::Shutdown(exit_code)),
            None => continue,
        }
    }
    Ok(())
}
