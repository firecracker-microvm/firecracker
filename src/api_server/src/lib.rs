// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![deny(missing_docs)]
//! Implements the interface for intercepting API requests, forwarding them to the VMM
//! and responding to the user.
//! It is constructed on top of an HTTP Server that uses Unix Domain Sockets and `EPOLL` to
//! handle multiple connections on the same thread.
mod parsed_request;
mod request;

use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use std::time::Duration;
use std::{fmt, io};

use libc::{c_int, c_void, siginfo_t};
use logger::{
    debug, error, info, update_metric_with_elapsed_time, warn, ProcessTimeReporter, METRICS,
};
pub use micro_http::{
    Body, HttpServer, Method, Request, RequestError, Response, ServerError, ServerRequest,
    ServerResponse, StatusCode, Version,
};
use seccompiler::{BpfProgram, BpfProgramRef};
use serde_json::json;
use utils::eventfd::EventFd;
use utils::signal::{register_signal_handler, sigrtmax, Killable};
use vmm::rpc_interface::{VmmAction, VmmActionError, VmmData};
use vmm::vmm_config::snapshot::SnapshotType;

use crate::parsed_request::{ParsedRequest, RequestAction};

/// Shorthand type for a request containing a boxed VmmAction.
pub type ApiRequest = Box<VmmAction>;
/// Shorthand type for a response containing a boxed Result.
pub type ApiResponse = Box<std::result::Result<VmmData, VmmActionError>>;

/// Errors thrown when binding the API server to the socket path.
pub enum Error {
    /// IO related error.
    Io(io::Error),
    /// EventFD related error.
    Eventfd(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref err) => write!(f, "IO error: {}", err),
            Error::Eventfd(ref err) => write!(f, "EventFd error: {}", err),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref err) => write!(f, "IO error: {}", err),
            Error::Eventfd(ref err) => write!(f, "EventFd error: {}", err),
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

/// Repeatedly tries to connect to unix socket specified by `socket_path`.
///
/// Retries to connect `retries` times, with `interval` duration between tries.
pub fn try_connect(
    socket_path: PathBuf,
    mut retries: u32,
    interval: Duration,
) -> io::Result<UnixStream> {
    let mut sock = UnixStream::connect(socket_path.clone());
    while retries > 0 {
        if sock.is_ok() {
            break;
        }
        std::thread::sleep(interval);
        retries = retries - 1;
        sock = UnixStream::connect(socket_path.clone());
    }
    sock
}

/// An owned handle to an ApiServer thread, used to stop and join the thread.
pub struct ThreadedApiServerHandle {
    stop_signum: c_int,
    stop_flag: Arc<AtomicBool>,
    thread_handle: JoinHandle<()>,
}

impl ThreadedApiServerHandle {
    /// Signals the ApiServer to stop and waits for the associated thread to finish.
    ///
    /// This function will return immediately if the associated thread has already finished.
    pub fn stop_and_join(self) {
        // Set the stop/shutdown flag for the ApiServer.
        self.stop_flag.store(true, Ordering::Release);
        // Kick the Api thread so it sees it should shut down.
        // Only reason for error here is if thread is already down, safely ignore it.
        let _ = self.thread_handle.kill(self.stop_signum);
        // Wait for the thread to cleanly finish.
        // Only returns error on panics, so unwrap() to cascade the panic.
        self.thread_handle.join().unwrap();
    }
}

/// Structure associated with the API server implementation.
pub struct ApiServer {
    /// Sender which allows passing messages to the VMM.
    api_request_sender: mpsc::Sender<ApiRequest>,
    /// Receiver which collects messages from the VMM.
    vmm_response_receiver: mpsc::Receiver<ApiResponse>,
    /// FD on which we notify the VMM that we have sent at least one
    /// `VmmRequest`.
    to_vmm_fd: EventFd,
    /// If this flag is set, the API thread will go down.
    shutdown_flag: Arc<AtomicBool>,
}

impl ApiServer {
    /// Creates, binds and runs the ApiServer in its own thread.
    ///
    /// Returns a `ThreadedApiServerHandle` object for stopping the server and joining the thread.
    ///
    /// # Example
    ///
    /// ```
    /// use std::env::consts::ARCH;
    /// use std::io::{Read, Write};
    /// use std::os::unix::net::UnixStream;
    /// use std::path::PathBuf;
    /// use std::sync::mpsc::{channel, Receiver, Sender};
    /// use std::sync::{Arc, Barrier};
    /// use std::thread;
    ///
    /// use api_server::{try_connect, ApiServer};
    /// use logger::ProcessTimeReporter;
    /// use utils::eventfd::EventFd;
    /// use utils::tempfile::TempFile;
    /// use vmm::rpc_interface::VmmData;
    /// use vmm::seccomp_filters::{get_filters, SeccompConfig};
    /// use vmm::vmm_config::instance_info::InstanceInfo;
    ///
    /// let mut tmp_socket = TempFile::new().unwrap();
    /// tmp_socket.remove().unwrap();
    /// let path_to_socket = tmp_socket.as_path().to_str().unwrap().to_owned();
    /// let api_thread_path_to_socket = path_to_socket.clone();
    /// let to_vmm_fd = EventFd::new(libc::EFD_NONBLOCK).unwrap();
    /// let (api_request_sender, _from_api) = channel();
    /// let (to_api, vmm_response_receiver) = channel();
    /// let time_reporter = ProcessTimeReporter::new(Some(1), Some(1), Some(1));
    /// let seccomp_filters = get_filters(SeccompConfig::None).unwrap();
    ///
    /// let handle = ApiServer::start_threaded(
    ///     api_request_sender,
    ///     vmm_response_receiver,
    ///     to_vmm_fd,
    ///     PathBuf::from(api_thread_path_to_socket),
    ///     time_reporter,
    ///     seccomp_filters.get("api").unwrap().clone(),
    ///     vmm::HTTP_MAX_PAYLOAD_SIZE,
    /// )
    /// .unwrap();
    ///
    /// to_api
    ///     .send(Box::new(Ok(VmmData::InstanceInformation(
    ///         InstanceInfo::default(),
    ///     ))))
    ///     .unwrap();
    ///
    /// let mut sock = try_connect(
    ///     PathBuf::from(path_to_socket),
    ///     5,
    ///     std::time::Duration::from_millis(10),
    /// )
    /// .unwrap();
    /// // Send a GET instance-info request.
    /// assert!(sock.write_all(b"GET / HTTP/1.1\r\n\r\n").is_ok());
    /// let mut buf: [u8; 100] = [0; 100];
    /// assert!(sock.read(&mut buf[..]).unwrap() > 0);
    ///
    /// handle.stop_and_join();
    /// ```
    pub fn start_threaded(
        api_request_sender: mpsc::Sender<ApiRequest>,
        vmm_response_receiver: mpsc::Receiver<ApiResponse>,
        to_vmm_fd: EventFd,
        api_bind_path: PathBuf,
        process_time_reporter: ProcessTimeReporter,
        seccomp_filter: Arc<BpfProgram>,
        api_payload_limit: usize,
    ) -> std::io::Result<ThreadedApiServerHandle> {
        let stop_signum = sigrtmax();
        // We register a noop signal handler for `SIGRTMAX` whose purpose is to wake
        // the api thread so it can check `stop_flag` in its main loop and terminate.
        extern "C" fn noop_handle(_: c_int, _: *mut siginfo_t, _: *mut c_void) {}
        register_signal_handler(stop_signum, noop_handle)
            .expect("Failed to register vcpu signal handler");

        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_clone = stop_flag.clone();
        // Create api thread and run ApiServer.
        let thread_handle = std::thread::Builder::new()
            .name("fc_api".to_owned())
            .spawn(move || {
                match ApiServer::new(
                    api_request_sender,
                    vmm_response_receiver,
                    to_vmm_fd,
                    stop_flag_clone,
                )
                .bind_and_run(
                    api_bind_path,
                    process_time_reporter,
                    &seccomp_filter,
                    api_payload_limit,
                ) {
                    Ok(_) => (),
                    Err(Error::Io(inner)) => match inner.kind() {
                        std::io::ErrorKind::AddrInUse => {
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
            })?;
        Ok(ThreadedApiServerHandle {
            stop_signum,
            stop_flag,
            thread_handle,
        })
    }

    /// Constructor for `ApiServer`.
    ///
    /// Returns the newly formed `ApiServer`.
    pub fn new(
        api_request_sender: mpsc::Sender<ApiRequest>,
        vmm_response_receiver: mpsc::Receiver<ApiResponse>,
        to_vmm_fd: EventFd,
        shutdown_flag: Arc<AtomicBool>,
    ) -> Self {
        ApiServer {
            api_request_sender,
            vmm_response_receiver,
            to_vmm_fd,
            shutdown_flag,
        }
    }

    /// Starts the HTTP Server by binding to the socket path provided as
    /// an argument.
    ///
    /// # Arguments
    ///
    /// * `path` - the socket path on which the server will wait for requests.
    /// * `start_time_us` - the timestamp for when the process was started in us.
    /// * `start_time_cpu_us` - the timestamp for when the process was started in CPU us.
    /// * `seccomp_filter` - the seccomp filter to apply.
    ///
    /// # Example
    ///
    /// ```
    /// use std::convert::TryInto;
    /// use std::env::consts::ARCH;
    /// use std::io::{Read, Write};
    /// use std::os::unix::net::UnixStream;
    /// use std::path::PathBuf;
    /// use std::sync::mpsc::{channel, Receiver, Sender};
    /// use std::sync::{Arc, Barrier};
    /// use std::thread;
    /// use std::time::Duration;
    ///
    /// use api_server::{try_connect, ApiServer};
    /// use logger::ProcessTimeReporter;
    /// use utils::eventfd::EventFd;
    /// use utils::tempfile::TempFile;
    /// use vmm::rpc_interface::VmmData;
    /// use vmm::seccomp_filters::{get_filters, SeccompConfig};
    /// use vmm::vmm_config::instance_info::InstanceInfo;
    /// use vmm::HTTP_MAX_PAYLOAD_SIZE;
    ///
    /// let mut tmp_socket = TempFile::new().unwrap();
    /// tmp_socket.remove().unwrap();
    /// let path_to_socket = tmp_socket.as_path().to_str().unwrap().to_owned();
    /// let api_thread_path_to_socket = path_to_socket.clone();
    /// let to_vmm_fd = EventFd::new(libc::EFD_NONBLOCK).unwrap();
    /// let (api_request_sender, _from_api) = channel();
    /// let (to_api, vmm_response_receiver) = channel();
    /// let time_reporter = ProcessTimeReporter::new(Some(1), Some(1), Some(1));
    /// let seccomp_filters = get_filters(SeccompConfig::None).unwrap();
    /// let payload_limit = HTTP_MAX_PAYLOAD_SIZE;
    ///
    /// thread::Builder::new()
    ///     .name("fc_api_test".to_owned())
    ///     .spawn(move || {
    ///         ApiServer::new(
    ///             api_request_sender,
    ///             vmm_response_receiver,
    ///             to_vmm_fd,
    ///             Default::default(),
    ///         )
    ///         .bind_and_run(
    ///             PathBuf::from(api_thread_path_to_socket),
    ///             time_reporter,
    ///             seccomp_filters.get("api").unwrap(),
    ///             payload_limit,
    ///         )
    ///         .unwrap();
    ///     })
    ///     .unwrap();
    ///
    /// to_api
    ///     .send(Box::new(Ok(VmmData::InstanceInformation(
    ///         InstanceInfo::default(),
    ///     ))))
    ///     .unwrap();
    /// let mut sock = try_connect(
    ///     PathBuf::from(path_to_socket),
    ///     5,
    ///     std::time::Duration::from_millis(10),
    /// )
    /// .unwrap();
    /// // Send a GET instance-info request.
    /// assert!(sock.write_all(b"GET / HTTP/1.1\r\n\r\n").is_ok());
    /// let mut buf: [u8; 100] = [0; 100];
    /// assert!(sock.read(&mut buf[..]).unwrap() > 0);
    /// ```
    pub fn bind_and_run(
        &mut self,
        path: PathBuf,
        process_time_reporter: ProcessTimeReporter,
        seccomp_filter: BpfProgramRef,
        api_payload_limit: usize,
    ) -> Result<()> {
        let mut server = HttpServer::new(path).unwrap_or_else(|err| {
            error!("Error creating the HTTP server: {}", err);
            std::process::exit(vmm::FcExitCode::GenericError as i32);
        });
        // Set the api payload size limit.
        server.set_payload_max_size(api_payload_limit);

        // Store process start time metric.
        process_time_reporter.report_start_time();
        // Store process CPU start time metric.
        process_time_reporter.report_cpu_start_time();

        // Load seccomp filters on the API thread.
        // Execution panics if filters cannot be loaded, use --no-seccomp if skipping filters
        // altogether is the desired behaviour.
        if let Err(err) = seccompiler::apply_filter(seccomp_filter) {
            panic!(
                "Failed to set the requested seccomp filters on the API thread: {}",
                err
            );
        }

        server.start_server().expect("Cannot start HTTP server");

        loop {
            let request_vec = match server.requests() {
                Ok(vec) => vec,
                Err(err) => {
                    // print request error, but keep server running
                    error!("API Server error on retrieving incoming request: {}", err);
                    continue;
                }
            };
            for server_request in request_vec {
                let request_processing_start_us =
                    utils::time::get_time_us(utils::time::ClockType::Monotonic);
                server
                    .respond(
                        // Use `self.handle_request()` as the processing callback.
                        server_request.process(|request| {
                            self.handle_request(request, request_processing_start_us)
                        }),
                    )
                    .or_else(|err| {
                        error!("API Server encountered an error on response: {}", err);
                        Ok(())
                    })?;

                let delta_us = utils::time::get_time_us(utils::time::ClockType::Monotonic)
                    - request_processing_start_us;
                debug!("Total previous API call duration: {} us.", delta_us);
            }
            if self.shutdown_flag.load(Ordering::Acquire) {
                server.flush_outgoing_writes();
                debug!("Api shutdown flag set, API server thread now ending itself");
                return Ok(());
            }
        }
    }

    /// Handles an API request received through the associated socket.
    pub fn handle_request(
        &mut self,
        request: &Request,
        request_processing_start_us: u64,
    ) -> Response {
        match ParsedRequest::try_from_request(request).map(|r| r.into_parts()) {
            Ok((req_action, mut parsing_info)) => {
                let mut response = match req_action {
                    RequestAction::Sync(vmm_action) => {
                        self.serve_vmm_action_request(vmm_action, request_processing_start_us)
                    }
                };
                if let Some(message) = parsing_info.take_deprecation_message() {
                    warn!("{}", message);
                    response.set_deprecation();
                }
                response
            }
            Err(err) => {
                error!("{}", err);
                err.into()
            }
        }
    }

    fn serve_vmm_action_request(
        &mut self,
        vmm_action: Box<VmmAction>,
        request_processing_start_us: u64,
    ) -> Response {
        let metric_with_action = match *vmm_action {
            VmmAction::CreateSnapshot(ref params) => match params.snapshot_type {
                SnapshotType::Full => Some((
                    &METRICS.latencies_us.full_create_snapshot,
                    "create full snapshot",
                )),
                SnapshotType::Diff => Some((
                    &METRICS.latencies_us.diff_create_snapshot,
                    "create diff snapshot",
                )),
            },
            VmmAction::LoadSnapshot(_) => {
                Some((&METRICS.latencies_us.load_snapshot, "load snapshot"))
            }
            VmmAction::Pause => Some((&METRICS.latencies_us.pause_vm, "pause vm")),
            VmmAction::Resume => Some((&METRICS.latencies_us.resume_vm, "resume vm")),
            _ => None,
        };

        self.api_request_sender
            .send(vmm_action)
            .expect("Failed to send VMM message");
        self.to_vmm_fd.write(1).expect("Cannot update send VMM fd");
        let vmm_outcome = *(self.vmm_response_receiver.recv().expect("VMM disconnected"));
        let response = ParsedRequest::convert_to_response(&vmm_outcome);

        if vmm_outcome.is_ok() {
            if let Some((metric, action)) = metric_with_action {
                let elapsed_time_us =
                    update_metric_with_elapsed_time(metric, request_processing_start_us);
                info!("'{}' API request took {} us.", action, elapsed_time_us);
            }
        }
        response
    }

    /// An HTTP response which also includes a body.
    pub(crate) fn json_response<T: Into<String>>(status: StatusCode, body: T) -> Response {
        let mut response = Response::new(Version::Http11, status);
        response.set_body(Body::new(body.into()));
        response
    }

    fn json_fault_message<T: AsRef<str> + serde::Serialize>(msg: T) -> String {
        json!({ "fault_message": msg }).to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc::channel;
    use std::thread;
    use std::time::Duration;

    use logger::StoreMetric;
    use micro_http::HttpConnection;
    use utils::tempfile::TempFile;
    use utils::time::ClockType;
    use vmm::builder::StartMicrovmError;
    use vmm::rpc_interface::VmmActionError;
    use vmm::seccomp_filters::{get_filters, SeccompConfig};
    use vmm::vmm_config::instance_info::InstanceInfo;
    use vmm::vmm_config::snapshot::CreateSnapshotParams;

    use super::*;

    #[test]
    fn test_error_messages() {
        let err = Error::Io(io::Error::from_raw_os_error(0));
        assert_eq!(
            format!("{}", err),
            format!("IO error: {}", io::Error::from_raw_os_error(0))
        );
        let err = Error::Eventfd(io::Error::from_raw_os_error(0));
        assert_eq!(
            format!("{}", err),
            format!("EventFd error: {}", io::Error::from_raw_os_error(0))
        );
    }

    #[test]
    fn test_error_debug() {
        let err = Error::Io(io::Error::from_raw_os_error(0));
        assert_eq!(
            format!("{:?}", err),
            format!("IO error: {}", io::Error::from_raw_os_error(0))
        );
        let err = Error::Eventfd(io::Error::from_raw_os_error(0));
        assert_eq!(
            format!("{:?}", err),
            format!("EventFd error: {}", io::Error::from_raw_os_error(0))
        );
    }

    #[test]
    fn test_serve_vmm_action_request() {
        let to_vmm_fd = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let (api_request_sender, _from_api) = channel();
        let (to_api, vmm_response_receiver) = channel();

        let mut api_server = ApiServer::new(
            api_request_sender,
            vmm_response_receiver,
            to_vmm_fd,
            Default::default(),
        );
        to_api
            .send(Box::new(Err(VmmActionError::StartMicrovm(
                StartMicrovmError::MissingKernelConfig,
            ))))
            .unwrap();
        let response = api_server.serve_vmm_action_request(Box::new(VmmAction::StartMicroVm), 0);
        assert_eq!(response.status(), StatusCode::BadRequest);

        let start_time_us = utils::time::get_time_us(ClockType::Monotonic);
        assert_eq!(METRICS.latencies_us.pause_vm.fetch(), 0);
        to_api.send(Box::new(Ok(VmmData::Empty))).unwrap();
        let response =
            api_server.serve_vmm_action_request(Box::new(VmmAction::Pause), start_time_us);
        assert_eq!(response.status(), StatusCode::NoContent);
        assert_ne!(METRICS.latencies_us.pause_vm.fetch(), 0);

        assert_eq!(METRICS.latencies_us.diff_create_snapshot.fetch(), 0);
        to_api
            .send(Box::new(Err(VmmActionError::OperationNotSupportedPreBoot)))
            .unwrap();
        let response = api_server.serve_vmm_action_request(
            Box::new(VmmAction::CreateSnapshot(CreateSnapshotParams {
                snapshot_type: SnapshotType::Diff,
                snapshot_path: PathBuf::new(),
                mem_file_path: PathBuf::new(),
                version: None,
            })),
            start_time_us,
        );
        assert_eq!(response.status(), StatusCode::BadRequest);
        // The metric should not be updated if the request wasn't successful.
        assert_eq!(METRICS.latencies_us.diff_create_snapshot.fetch(), 0);

        to_api.send(Box::new(Ok(VmmData::Empty))).unwrap();
        let response = api_server.serve_vmm_action_request(
            Box::new(VmmAction::CreateSnapshot(CreateSnapshotParams {
                snapshot_type: SnapshotType::Diff,
                snapshot_path: PathBuf::new(),
                mem_file_path: PathBuf::new(),
                version: None,
            })),
            start_time_us,
        );
        assert_eq!(response.status(), StatusCode::NoContent);
        assert_ne!(METRICS.latencies_us.diff_create_snapshot.fetch(), 0);
        assert_eq!(METRICS.latencies_us.full_create_snapshot.fetch(), 0);
    }

    #[test]
    fn test_handle_request() {
        let to_vmm_fd = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let (api_request_sender, _from_api) = channel();
        let (to_api, vmm_response_receiver) = channel();

        let mut api_server = ApiServer::new(
            api_request_sender,
            vmm_response_receiver,
            to_vmm_fd,
            Default::default(),
        );

        // Test an Actions request.
        let (mut sender, receiver) = UnixStream::pair().unwrap();
        let mut connection = HttpConnection::new(receiver);
        sender
            .write_all(
                b"PUT /actions HTTP/1.1\r\n\
                Content-Type: application/json\r\n\
                Content-Length: 49\r\n\r\n{ \
                \"action_type\": \"Invalid\", \
                \"payload\": \"string\" \
                }",
            )
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        let response = api_server.handle_request(&req, 0);
        assert_eq!(response.status(), StatusCode::BadRequest);

        // Test a Get Info request.
        to_api
            .send(Box::new(Ok(VmmData::InstanceInformation(
                InstanceInfo::default(),
            ))))
            .unwrap();
        sender.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        let response = api_server.handle_request(&req, 0);
        assert_eq!(response.status(), StatusCode::OK);

        // Test erroneous request.
        sender
            .write_all(
                b"GET /mmds HTTP/1.1\r\n\
                Content-Type: application/json\r\n\
                Content-Length: 2\r\n\r\n{}",
            )
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        let response = api_server.handle_request(&req, 0);
        assert_eq!(response.status(), StatusCode::BadRequest);
    }

    #[test]
    fn test_bind_and_run() {
        let mut tmp_socket = TempFile::new().unwrap();
        tmp_socket.remove().unwrap();
        let path_to_socket = tmp_socket.as_path().to_str().unwrap().to_owned();
        let api_thread_path_to_socket = path_to_socket.clone();

        let to_vmm_fd = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let (api_request_sender, _from_api) = channel();
        let (to_api, vmm_response_receiver) = channel();
        let seccomp_filters = get_filters(SeccompConfig::Advanced).unwrap();

        thread::Builder::new()
            .name("fc_api_test".to_owned())
            .spawn(move || {
                ApiServer::new(
                    api_request_sender,
                    vmm_response_receiver,
                    to_vmm_fd,
                    Default::default(),
                )
                .bind_and_run(
                    PathBuf::from(api_thread_path_to_socket),
                    ProcessTimeReporter::new(Some(1), Some(1), Some(1)),
                    seccomp_filters.get("api").unwrap(),
                    vmm::HTTP_MAX_PAYLOAD_SIZE,
                )
                .unwrap();
            })
            .unwrap();

        to_api
            .send(Box::new(Ok(VmmData::InstanceInformation(
                InstanceInfo::default(),
            ))))
            .unwrap();
        let mut sock =
            try_connect(PathBuf::from(path_to_socket), 5, Duration::from_millis(10)).unwrap();

        // Send a GET InstanceInfo request.
        assert!(sock.write_all(b"GET / HTTP/1.1\r\n\r\n").is_ok());
        let mut buf: [u8; 100] = [0; 100];
        assert!(sock.read(&mut buf[..]).unwrap() > 0);

        // Send an erroneous request.
        assert!(sock.write_all(b"OPTIONS / HTTP/1.1\r\n\r\n").is_ok());
        let mut buf: [u8; 100] = [0; 100];
        assert!(sock.read(&mut buf[..]).unwrap() > 0);
    }

    #[test]
    fn test_bind_and_run_with_limit() {
        let mut tmp_socket = TempFile::new().unwrap();
        tmp_socket.remove().unwrap();
        let path_to_socket = tmp_socket.as_path().to_str().unwrap().to_owned();
        let api_thread_path_to_socket = path_to_socket.clone();

        let to_vmm_fd = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let (api_request_sender, _from_api) = channel();
        let (_to_api, vmm_response_receiver) = channel();
        let seccomp_filters = get_filters(SeccompConfig::Advanced).unwrap();

        thread::Builder::new()
            .name("fc_api_test".to_owned())
            .spawn(move || {
                ApiServer::new(
                    api_request_sender,
                    vmm_response_receiver,
                    to_vmm_fd,
                    Default::default(),
                )
                .bind_and_run(
                    PathBuf::from(api_thread_path_to_socket),
                    ProcessTimeReporter::new(Some(1), Some(1), Some(1)),
                    seccomp_filters.get("api").unwrap(),
                    50,
                )
                .unwrap();
            })
            .unwrap();

        let mut sock =
            try_connect(PathBuf::from(path_to_socket), 5, Duration::from_millis(10)).unwrap();

        // Send a GET mmds request.
        assert!(sock
            .write_all(
                b"PUT http://localhost/home HTTP/1.1\r\n\
                  Content-Length: 50000\r\n\r\naaaaaa"
            )
            .is_ok());
        let mut buf: [u8; 265] = [0; 265];
        assert!(sock.read(&mut buf[..]).unwrap() > 0);
        let error_message = b"HTTP/1.1 400 \r\n\
                              Server: Firecracker API\r\n\
                              Connection: keep-alive\r\n\
                              Content-Type: application/json\r\n\
                              Content-Length: 146\r\n\r\n{ \"error\": \"\
                              Request payload with size 50000 is larger than \
                              the limit of 50 allowed by server.\nAll previous \
                              unanswered requests will be dropped.\" }";
        assert_eq!(&buf[..], &error_message[..]);
    }
}
