// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Implements the interface for intercepting API requests, forwarding them to the VMM
//! and responding to the user.
//! It is constructed on top of an HTTP Server that uses Unix Domain Sockets and `EPOLL` to
//! handle multiple connections on the same thread.

pub mod parsed_request;
pub mod request;

use std::fmt::Debug;
use std::sync::mpsc;

pub use micro_http::{Body, HttpServer, Request, Response, ServerError, StatusCode, Version};
use parsed_request::{ParsedRequest, RequestAction};
use serde_json::json;
use utils::time::{ClockType, get_time_us};
use vmm::logger::{
    METRICS, ProcessTimeReporter, debug, error, info, update_metric_with_elapsed_time, warn,
};
use vmm::rpc_interface::{ApiRequest, ApiResponse, VmmAction};
use vmm::seccomp::BpfProgramRef;
use vmm::vmm_config::snapshot::SnapshotType;
use vmm_sys_util::eventfd::EventFd;

/// Structure associated with the API server implementation.
#[derive(Debug)]
pub struct ApiServer {
    /// Sender which allows passing messages to the VMM.
    api_request_sender: mpsc::Sender<ApiRequest>,
    /// Receiver which collects messages from the VMM.
    vmm_response_receiver: mpsc::Receiver<ApiResponse>,
    /// FD on which we notify the VMM that we have sent at least one
    /// `VmmRequest`.
    to_vmm_fd: EventFd,
}

impl ApiServer {
    /// Constructor for `ApiServer`.
    ///
    /// Returns the newly formed `ApiServer`.
    pub fn new(
        api_request_sender: mpsc::Sender<ApiRequest>,
        vmm_response_receiver: mpsc::Receiver<ApiResponse>,
        to_vmm_fd: EventFd,
    ) -> Self {
        ApiServer {
            api_request_sender,
            vmm_response_receiver,
            to_vmm_fd,
        }
    }

    /// Runs the Api Server.
    ///
    /// # Arguments
    ///
    /// * `path` - the socket path on which the server will wait for requests.
    /// * `start_time_us` - the timestamp for when the process was started in us.
    /// * `start_time_cpu_us` - the timestamp for when the process was started in CPU us.
    /// * `seccomp_filter` - the seccomp filter to apply.
    pub fn run(
        &mut self,
        mut server: HttpServer,
        process_time_reporter: ProcessTimeReporter,
        seccomp_filter: BpfProgramRef,
        api_payload_limit: usize,
    ) {
        // Set the api payload size limit.
        server.set_payload_max_size(api_payload_limit);

        // Load seccomp filters on the API thread.
        // Execution panics if filters cannot be loaded, use --no-seccomp if skipping filters
        // altogether is the desired behaviour.
        if let Err(err) = vmm::seccomp::apply_filter(seccomp_filter) {
            panic!(
                "Failed to set the requested seccomp filters on the API thread: {}",
                err
            );
        }

        server.start_server().expect("Cannot start HTTP server");
        info!("API server started.");

        // Store process start time metric.
        process_time_reporter.report_start_time();
        // Store process CPU start time metric.
        process_time_reporter.report_cpu_start_time();

        loop {
            let request_vec = match server.requests() {
                Ok(vec) => vec,
                Err(ServerError::ShutdownEvent) => {
                    server.flush_outgoing_writes();
                    debug!("shutdown request received, API server thread ending.");
                    return;
                }
                Err(err) => {
                    // print request error, but keep server running
                    error!("API Server error on retrieving incoming request: {}", err);
                    continue;
                }
            };
            for server_request in request_vec {
                let request_processing_start_us = get_time_us(ClockType::Monotonic);
                // Use `self.handle_request()` as the processing callback.
                let response = server_request
                    .process(|request| self.handle_request(request, request_processing_start_us));
                if let Err(err) = server.respond(response) {
                    error!("API Server encountered an error on response: {}", err);
                };

                let delta_us = get_time_us(ClockType::Monotonic) - request_processing_start_us;
                debug!("Total previous API call duration: {} us.", delta_us);
            }
        }
    }

    /// Handles an API request received through the associated socket.
    pub fn handle_request(
        &mut self,
        request: &Request,
        request_processing_start_us: u64,
    ) -> Response {
        match ParsedRequest::try_from(request).map(|r| r.into_parts()) {
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
                error!("{:?}", err);
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
    pub(crate) fn json_response<T: Into<String> + Debug>(status: StatusCode, body: T) -> Response {
        let mut response = Response::new(Version::Http11, status);
        response.set_body(Body::new(body.into()));
        response
    }

    fn json_fault_message<T: AsRef<str> + serde::Serialize + Debug>(msg: T) -> String {
        json!({ "fault_message": msg }).to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::sync::mpsc::channel;
    use std::thread;

    use micro_http::HttpConnection;
    use utils::time::ClockType;
    use vmm::builder::StartMicrovmError;
    use vmm::logger::StoreMetric;
    use vmm::rpc_interface::{VmmActionError, VmmData};
    use vmm::seccomp::get_empty_filters;
    use vmm::vmm_config::instance_info::InstanceInfo;
    use vmm::vmm_config::snapshot::CreateSnapshotParams;
    use vmm_sys_util::tempfile::TempFile;

    use super::request::cpu_configuration::parse_put_cpu_config;
    use super::*;

    /// Test unescaped CPU template in JSON format.
    /// Newlines injected into a field's value to
    /// test deserialization and logging.
    #[cfg(target_arch = "x86_64")]
    const TEST_UNESCAPED_JSON_TEMPLATE: &str = r#"{
        "msr_modifiers": [
            {
                "addr": "0x0\n\n\n\nTEST\n\n\n\n",
                "bitmap": "0b00"
            }
        ]
    }"#;
    #[cfg(target_arch = "aarch64")]
    pub const TEST_UNESCAPED_JSON_TEMPLATE: &str = r#"{
        "reg_modifiers": [
            {
                "addr": "0x0\n\n\n\nTEST\n\n\n\n",
                "bitmap": "0b00"
            }
        ]
    }"#;

    #[test]
    fn test_serve_vmm_action_request() {
        let to_vmm_fd = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let (api_request_sender, _from_api) = channel();
        let (to_api, vmm_response_receiver) = channel();

        let mut api_server = ApiServer::new(api_request_sender, vmm_response_receiver, to_vmm_fd);
        to_api
            .send(Box::new(Err(VmmActionError::StartMicrovm(
                StartMicrovmError::MissingKernelConfig,
            ))))
            .unwrap();
        let response = api_server.serve_vmm_action_request(Box::new(VmmAction::StartMicroVm), 0);
        assert_eq!(response.status(), StatusCode::BadRequest);

        // Since the vmm side is mocked out in this test, the call to serve_vmm_action_request can
        // complete very fast (under 1us, the resolution of our metrics). In these cases, the
        // latencies_us.pause_vm metric can be set to 0, failing the assertion below. By
        // subtracting 1 we assure that the metric will always be set to at least 1 (if it gets set
        // at all, which is what this test is trying to prove).
        let start_time_us = get_time_us(ClockType::Monotonic) - 1;
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

        let mut api_server = ApiServer::new(api_request_sender, vmm_response_receiver, to_vmm_fd);

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
        connection.try_read().unwrap();
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
        connection.try_read().unwrap();
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
        connection.try_read().unwrap();
        let req = connection.pop_parsed_request().unwrap();
        let response = api_server.handle_request(&req, 0);
        assert_eq!(response.status(), StatusCode::BadRequest);
    }

    #[test]
    fn test_handle_request_logging() {
        let cpu_template_json = TEST_UNESCAPED_JSON_TEMPLATE;
        let result = parse_put_cpu_config(&Body::new(cpu_template_json.as_bytes()));
        let result_error = result.unwrap_err();
        let err_msg = format!("{}", result_error);
        assert_ne!(
            1,
            err_msg.lines().count(),
            "Error Body response:\n{}",
            err_msg
        );

        let err_msg_with_debug = format!("{:?}", result_error);
        // Check the loglines are on one line.
        assert_eq!(
            1,
            err_msg_with_debug.lines().count(),
            "Error Body response:\n{}",
            err_msg_with_debug
        );
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
        let seccomp_filters = get_empty_filters();
        let server = HttpServer::new(PathBuf::from(api_thread_path_to_socket)).unwrap();
        thread::Builder::new()
            .name("fc_api_test".to_owned())
            .spawn(move || {
                ApiServer::new(api_request_sender, vmm_response_receiver, to_vmm_fd).run(
                    server,
                    ProcessTimeReporter::new(Some(1), Some(1), Some(1)),
                    seccomp_filters.get("api").unwrap(),
                    vmm::HTTP_MAX_PAYLOAD_SIZE,
                );
            })
            .unwrap();

        to_api
            .send(Box::new(Ok(VmmData::InstanceInformation(
                InstanceInfo::default(),
            ))))
            .unwrap();
        let mut sock = UnixStream::connect(PathBuf::from(path_to_socket)).unwrap();

        // Send a GET InstanceInfo request.
        sock.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
        let mut buf: [u8; 100] = [0; 100];
        assert!(sock.read(&mut buf[..]).unwrap() > 0);

        // Send an erroneous request.
        sock.write_all(b"OPTIONS / HTTP/1.1\r\n\r\n").unwrap();
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
        let seccomp_filters = get_empty_filters();

        let server = HttpServer::new(PathBuf::from(api_thread_path_to_socket)).unwrap();
        thread::Builder::new()
            .name("fc_api_test".to_owned())
            .spawn(move || {
                ApiServer::new(api_request_sender, vmm_response_receiver, to_vmm_fd).run(
                    server,
                    ProcessTimeReporter::new(Some(1), Some(1), Some(1)),
                    seccomp_filters.get("api").unwrap(),
                    50,
                )
            })
            .unwrap();

        let mut sock = UnixStream::connect(PathBuf::from(path_to_socket)).unwrap();

        // Send a GET mmds request.
        sock.write_all(
            b"PUT http://localhost/home HTTP/1.1\r\n\
                  Content-Length: 50000\r\n\r\naaaaaa",
        )
        .unwrap();
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

    #[test]
    fn test_kill_switch() {
        let mut tmp_socket = TempFile::new().unwrap();
        tmp_socket.remove().unwrap();
        let path_to_socket = tmp_socket.as_path().to_str().unwrap().to_owned();

        let to_vmm_fd = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let (api_request_sender, _from_api) = channel();
        let (_to_api, vmm_response_receiver) = channel();
        let seccomp_filters = get_empty_filters();

        let api_kill_switch = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let kill_switch = api_kill_switch.try_clone().unwrap();

        let mut server = HttpServer::new(PathBuf::from(path_to_socket)).unwrap();
        server.add_kill_switch(kill_switch).unwrap();

        let api_thread = thread::Builder::new()
            .name("fc_api_test".to_owned())
            .spawn(move || {
                ApiServer::new(api_request_sender, vmm_response_receiver, to_vmm_fd).run(
                    server,
                    ProcessTimeReporter::new(Some(1), Some(1), Some(1)),
                    seccomp_filters.get("api").unwrap(),
                    vmm::HTTP_MAX_PAYLOAD_SIZE,
                )
            })
            .unwrap();
        // Signal the API thread it should shut down.
        api_kill_switch.write(1).unwrap();
        // Verify API thread was brought down.
        api_thread.join().unwrap();
    }
}
