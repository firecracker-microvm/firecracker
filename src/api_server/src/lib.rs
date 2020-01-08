// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

extern crate epoll;
#[macro_use]
extern crate logger;
extern crate micro_http;
extern crate mmds;
extern crate seccomp;
extern crate utils;
extern crate vmm;

mod parsed_request;
mod request;

use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::{fmt, io};

use logger::{Metric, METRICS};
pub use micro_http::{
    Body, HttpServer, Method, Request, RequestError, Response, ServerError, ServerRequest,
    ServerResponse, StatusCode, Version,
};
use mmds::data_store;
use mmds::data_store::Mmds;
use parsed_request::ParsedRequest;
use seccomp::{BpfProgram, SeccompFilter};
use utils::eventfd::EventFd;
use vmm::vmm_config::boot_source::BootSourceConfig;
use vmm::vmm_config::drive::BlockDeviceConfig;
use vmm::vmm_config::instance_info::InstanceInfo;
use vmm::vmm_config::logger::LoggerConfig;
use vmm::vmm_config::machine_config::VmConfig;
use vmm::vmm_config::net::{NetworkInterfaceConfig, NetworkInterfaceUpdateConfig};
use vmm::vmm_config::vsock::VsockDeviceConfig;
use vmm::VmmActionError;

/// This enum represents the public interface of the VMM. Each action contains various
/// bits of information (ids, paths, etc.).
#[derive(PartialEq)]
pub enum VmmAction {
    /// Configure the boot source of the microVM using as input the `ConfigureBootSource`. This
    /// action can only be called before the microVM has booted.
    ConfigureBootSource(BootSourceConfig),
    /// Configure the logger using as input the `LoggerConfig`. This action can only be called
    /// before the microVM has booted.
    ConfigureLogger(LoggerConfig),
    /// Get the configuration of the microVM.
    GetVmConfiguration,
    /// Flush the metrics. This action can only be called after the logger has been configured.
    FlushMetrics,
    /// Add a new block device or update one that already exists using the `BlockDeviceConfig` as
    /// input. This action can only be called before the microVM has booted.
    InsertBlockDevice(BlockDeviceConfig),
    /// Add a new network interface config or update one that already exists using the
    /// `NetworkInterfaceConfig` as input. This action can only be called before the microVM has
    /// booted.
    InsertNetworkDevice(NetworkInterfaceConfig),
    /// Set the vsock device or update the one that already exists using the
    /// `VsockDeviceConfig` as input. This action can only be called before the microVM has
    /// booted.
    SetVsockDevice(VsockDeviceConfig),
    /// Update the size of an existing block device specified by an ID. The ID is the first data
    /// associated with this enum variant. This action can only be called after the microVM is
    /// started.
    RescanBlockDevice(String),
    /// Set the microVM configuration (memory & vcpu) using `VmConfig` as input. This
    /// action can only be called before the microVM has booted.
    SetVmConfiguration(VmConfig),
    /// Launch the microVM. This action can only be called before the microVM has booted.
    StartMicroVm,
    /// Send CTRL+ALT+DEL to the microVM, using the i8042 keyboard function. If an AT-keyboard
    /// driver is listening on the guest end, this can be used to shut down the microVM gracefully.
    #[cfg(target_arch = "x86_64")]
    SendCtrlAltDel,
    /// Update the path of an existing block device. The data associated with this variant
    /// represents the `drive_id` and the `path_on_host`.
    UpdateBlockDevicePath(String, String),
    /// Update a network interface, after microVM start. Currently, the only updatable properties
    /// are the RX and TX rate limiters.
    UpdateNetworkInterface(NetworkInterfaceUpdateConfig),
}

/// The enum represents the response sent by the VMM in case of success. The response is either
/// empty, when no data needs to be sent, or an internal VMM structure.
#[derive(Debug)]
pub enum VmmData {
    /// No data is sent on the channel.
    Empty,
    /// The microVM configuration represented by `VmConfig`.
    MachineConfiguration(VmConfig),
}

pub enum Error {
    Io(io::Error),
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

pub type Result<T> = std::result::Result<T, Error>;

pub type VmmRequest = Box<VmmAction>;
pub type VmmResponse = Box<std::result::Result<VmmData, VmmActionError>>;

pub struct ApiServer {
    /// MMDS info directly accessible from the API thread.
    mmds_info: Arc<Mutex<Mmds>>,
    /// VMM instance info directly accessible from the API thread.
    vmm_shared_info: Arc<RwLock<InstanceInfo>>,
    /// Sender which allows passing messages to the VMM.
    api_request_sender: mpsc::Sender<VmmRequest>,
    /// Receiver which collects messages from the VMM.
    vmm_response_receiver: mpsc::Receiver<VmmResponse>,
    /// FD on which we notify the VMM that we have sent at least one
    /// `VmmRequest`.
    to_vmm_fd: EventFd,
}

impl ApiServer {
    pub fn new(
        mmds_info: Arc<Mutex<Mmds>>,
        vmm_shared_info: Arc<RwLock<InstanceInfo>>,
        api_request_sender: mpsc::Sender<VmmRequest>,
        vmm_response_receiver: mpsc::Receiver<VmmResponse>,
        to_vmm_fd: EventFd,
    ) -> Result<Self> {
        Ok(ApiServer {
            mmds_info,
            vmm_shared_info,
            api_request_sender,
            vmm_response_receiver,
            to_vmm_fd,
        })
    }

    pub fn bind_and_run(
        &mut self,
        path: PathBuf,
        start_time_us: Option<u64>,
        start_time_cpu_us: Option<u64>,
        seccomp_filter: BpfProgram,
    ) -> Result<()> {
        let mut server = HttpServer::new(path).expect("Error creating the HTTP server");

        if let Some(start_time) = start_time_us {
            let delta_us =
                (utils::time::get_time(utils::time::ClockType::Monotonic) / 1000) - start_time;
            METRICS
                .api_server
                .process_startup_time_us
                .add(delta_us as usize);
        }

        if let Some(cpu_start_time) = start_time_cpu_us {
            let delta_us =
                utils::time::get_time(utils::time::ClockType::ProcessCpu) / 1000 - cpu_start_time;
            METRICS
                .api_server
                .process_startup_time_cpu_us
                .add(delta_us as usize);
        }

        // Load seccomp filters on the API thread.
        // Execution panics if filters cannot be loaded, use --seccomp-level=0 if skipping filters
        // altogether is the desired behaviour.
        if let Err(e) = SeccompFilter::apply(seccomp_filter) {
            panic!(
                "Failed to set the requested seccomp filters on the API thread: Error: {:?}",
                e
            );
        }

        server.start_server().unwrap();
        loop {
            match server.requests() {
                Ok(request_vec) => {
                    for server_request in request_vec {
                        server
                            .respond(
                                // Use `self.handle_request()` as the processing callback.
                                server_request.process(|request| self.handle_request(request)),
                            )
                            .or_else(|e| {
                                error!("API Server encountered an error on response: {}", e);
                                Ok(())
                            })?;
                    }
                }
                Err(e) => {
                    error!(
                        "API Server error on retrieving incoming request. Error: {}",
                        e
                    );
                }
            }
        }
    }

    fn handle_request(&self, request: &Request) -> Response {
        match ParsedRequest::try_from_request(request) {
            Ok(ParsedRequest::Sync(vmm_action)) => self.serve_vmm_action_request(vmm_action),
            Ok(ParsedRequest::GetInstanceInfo) => self.get_instance_info(),
            Ok(ParsedRequest::GetMMDS) => self.get_mmds(),
            Ok(ParsedRequest::PatchMMDS(value)) => self.patch_mmds(value),
            Ok(ParsedRequest::PutMMDS(value)) => self.put_mmds(value),
            Err(e) => {
                error!("{}", e);
                e.into()
            }
        }
    }

    fn serve_vmm_action_request(&self, vmm_action: VmmAction) -> Response {
        self.api_request_sender.send(Box::new(vmm_action)).unwrap();
        self.to_vmm_fd.write(1).unwrap();
        let vmm_outcome = *(self.vmm_response_receiver.recv().unwrap());
        ParsedRequest::convert_to_response(vmm_outcome)
    }

    fn get_instance_info(&self) -> Response {
        let shared_info_lock = self.vmm_shared_info.clone();
        // unwrap() to crash if the other thread poisoned this lock
        let shared_info = shared_info_lock
            .read()
            .expect("Failed to read shared_info due to poisoned lock");
        // Serialize it to a JSON string.
        let body_result = serde_json::to_string(&(*shared_info));
        match body_result {
            Ok(body) => ApiServer::json_response(StatusCode::OK, body),
            Err(e) => {
                // This is an api server metrics as the shared info is obtained internally.
                METRICS.get_api_requests.instance_info_fails.inc();
                ApiServer::json_response(
                    StatusCode::BadRequest,
                    ApiServer::json_fault_message(e.to_string()),
                )
            }
        }
    }

    fn get_mmds(&self) -> Response {
        ApiServer::json_response(
            StatusCode::OK,
            self.mmds_info
                .lock()
                .expect("Failed to acquire lock on MMDS info")
                .get_data_str(),
        )
    }

    fn patch_mmds(&self, value: serde_json::Value) -> Response {
        let mmds_response = self
            .mmds_info
            .lock()
            .expect("Failed to acquire lock on MMDS info")
            .patch_data(value);
        match mmds_response {
            Ok(_) => Response::new(Version::Http11, StatusCode::NoContent),
            Err(e) => match e {
                data_store::Error::NotFound => ApiServer::json_response(
                    StatusCode::NotFound,
                    ApiServer::json_fault_message(e.to_string()),
                ),
                data_store::Error::UnsupportedValueType => ApiServer::json_response(
                    StatusCode::BadRequest,
                    ApiServer::json_fault_message(e.to_string()),
                ),
            },
        }
    }

    fn put_mmds(&self, value: serde_json::Value) -> Response {
        let mmds_response = self
            .mmds_info
            .lock()
            .expect("Failed to acquire lock on MMDS info")
            .put_data(value);
        match mmds_response {
            Ok(_) => Response::new(Version::Http11, StatusCode::NoContent),
            Err(e) => ApiServer::json_response(
                StatusCode::BadRequest,
                ApiServer::json_fault_message(e.to_string()),
            ),
        }
    }

    /// An HTTP response which also includes a body.
    pub fn json_response<T: Into<String>>(status: StatusCode, body: T) -> Response {
        let mut response = Response::new(Version::Http11, status);
        response.set_body(Body::new(body.into()));
        response
    }

    // Builds a string that looks like (where $ stands for substitution):
    //  {
    //    "$k": "$v"
    //  }
    // Mainly used for building fault message response json bodies.
    fn basic_json_body<K: AsRef<str>, V: AsRef<str>>(k: K, v: V) -> String {
        format!("{{\n  \"{}\": \"{}\"\n}}", k.as_ref(), v.as_ref())
    }

    fn json_fault_message<T: AsRef<str>>(msg: T) -> String {
        ApiServer::basic_json_body("fault_message", msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc::channel;
    use std::{fs, thread};

    use micro_http::HttpConnection;
    use mmds::MMDS;
    use std::time::Duration;
    use vmm::vmm_config::instance_info::{InstanceInfo, InstanceState};
    use vmm::{ErrorKind, StartMicrovmError, VmmActionError};

    #[test]
    fn test_error_messages() {
        let e = Error::Io(io::Error::from_raw_os_error(0));
        assert_eq!(
            format!("{}", e),
            format!("IO error: {}", io::Error::from_raw_os_error(0))
        );
        let e = Error::Eventfd(io::Error::from_raw_os_error(0));
        assert_eq!(
            format!("{}", e),
            format!("EventFd error: {}", io::Error::from_raw_os_error(0))
        );
    }

    #[test]
    fn test_error_debug() {
        let e = Error::Io(io::Error::from_raw_os_error(0));
        assert_eq!(
            format!("{:?}", e),
            format!("IO error: {}", io::Error::from_raw_os_error(0))
        );
        let e = Error::Eventfd(io::Error::from_raw_os_error(0));
        assert_eq!(
            format!("{:?}", e),
            format!("EventFd error: {}", io::Error::from_raw_os_error(0))
        );
    }

    #[test]
    fn test_serve_vmm_action_request() {
        let vmm_shared_info = Arc::new(RwLock::new(InstanceInfo {
            state: InstanceState::Uninitialized,
            id: "test_serve_action_req".to_string(),
            vmm_version: "version 0.1.0".to_string(),
        }));

        let to_vmm_fd = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let (api_request_sender, _from_api) = channel();
        let (to_api, vmm_response_receiver) = channel();
        let mmds_info = MMDS.clone();

        let api_server = ApiServer::new(
            mmds_info,
            vmm_shared_info,
            api_request_sender,
            vmm_response_receiver,
            to_vmm_fd,
        )
        .unwrap();

        to_api
            .send(Box::new(Err(VmmActionError::StartMicrovm(
                ErrorKind::User,
                StartMicrovmError::EventFd,
            ))))
            .unwrap();
        let response = api_server.serve_vmm_action_request(VmmAction::StartMicroVm);
        assert_eq!(response.status(), StatusCode::BadRequest);
    }

    #[test]
    fn test_get_instance_info() {
        let vmm_shared_info = Arc::new(RwLock::new(InstanceInfo {
            state: InstanceState::Uninitialized,
            id: "test_get_instance_info".to_string(),
            vmm_version: "version 0.1.0".to_string(),
        }));

        let to_vmm_fd = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let (api_request_sender, _from_api) = channel();
        let (_to_api, vmm_response_receiver) = channel();
        let mmds_info = MMDS.clone();

        let api_server = ApiServer::new(
            mmds_info,
            vmm_shared_info,
            api_request_sender,
            vmm_response_receiver,
            to_vmm_fd,
        )
        .unwrap();

        let response = api_server.get_instance_info();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_get_mmds() {
        let vmm_shared_info = Arc::new(RwLock::new(InstanceInfo {
            state: InstanceState::Uninitialized,
            id: "test_get_mmds".to_string(),
            vmm_version: "version 0.1.0".to_string(),
        }));

        let to_vmm_fd = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let (api_request_sender, _from_api) = channel();
        let (_to_api, vmm_response_receiver) = channel();
        let mmds_info = MMDS.clone();

        let api_server = ApiServer::new(
            mmds_info,
            vmm_shared_info,
            api_request_sender,
            vmm_response_receiver,
            to_vmm_fd,
        )
        .unwrap();

        let response = api_server.get_mmds();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_put_mmds() {
        let vmm_shared_info = Arc::new(RwLock::new(InstanceInfo {
            state: InstanceState::Uninitialized,
            id: "test_put_mmds".to_string(),
            vmm_version: "version 0.1.0".to_string(),
        }));

        let to_vmm_fd = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let (api_request_sender, _from_api) = channel();
        let (_to_api, vmm_response_receiver) = channel();
        let mmds_info = MMDS.clone();

        let api_server = ApiServer::new(
            mmds_info,
            vmm_shared_info,
            api_request_sender,
            vmm_response_receiver,
            to_vmm_fd,
        )
        .unwrap();

        let response = api_server.put_mmds(serde_json::Value::String("string".to_string()));
        assert_eq!(response.status(), StatusCode::NoContent);

        let response = api_server.put_mmds(serde_json::Value::Bool(true));
        assert_eq!(response.status(), StatusCode::BadRequest);
    }

    #[test]
    fn test_patch_mmds() {
        let vmm_shared_info = Arc::new(RwLock::new(InstanceInfo {
            state: InstanceState::Uninitialized,
            id: "test_patch_mmds".to_string(),
            vmm_version: "version 0.1.0".to_string(),
        }));

        let to_vmm_fd = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let (api_request_sender, _from_api) = channel();
        let (_to_api, vmm_response_receiver) = channel();
        let mmds_info = MMDS.clone();

        let api_server = ApiServer::new(
            mmds_info,
            vmm_shared_info,
            api_request_sender,
            vmm_response_receiver,
            to_vmm_fd,
        )
        .unwrap();

        let response = api_server.put_mmds(serde_json::Value::String("string".to_string()));
        assert_eq!(response.status(), StatusCode::NoContent);

        let response = api_server.patch_mmds(serde_json::Value::String("string".to_string()));
        assert_eq!(response.status(), StatusCode::NoContent);

        let response = api_server.patch_mmds(serde_json::Value::Bool(true));
        assert_eq!(response.status(), StatusCode::BadRequest);
    }

    #[test]
    fn test_handle_request() {
        let vmm_shared_info = Arc::new(RwLock::new(InstanceInfo {
            state: InstanceState::Uninitialized,
            id: "test_handle_request".to_string(),
            vmm_version: "version 0.1.0".to_string(),
        }));

        let to_vmm_fd = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let (api_request_sender, _from_api) = channel();
        let (to_api, vmm_response_receiver) = channel();
        let mmds_info = MMDS.clone();

        let api_server = ApiServer::new(
            mmds_info,
            vmm_shared_info,
            api_request_sender,
            vmm_response_receiver,
            to_vmm_fd,
        )
        .unwrap();
        to_api
            .send(Box::new(Err(VmmActionError::StartMicrovm(
                ErrorKind::User,
                StartMicrovmError::EventFd,
            ))))
            .unwrap();

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
        let response = api_server.handle_request(&req);
        assert_eq!(response.status(), StatusCode::BadRequest);

        // Test a Get Info request.
        sender.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        let response = api_server.handle_request(&req);
        assert_eq!(response.status(), StatusCode::OK);

        // Test a Get Mmds request.
        sender.write_all(b"GET /mmds HTTP/1.1\r\n\r\n").unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        let response = api_server.handle_request(&req);
        assert_eq!(response.status(), StatusCode::OK);

        // Test a Put Mmds request.
        sender
            .write_all(
                b"PUT /mmds HTTP/1.1\r\n\
                Content-Type: application/json\r\n\
                Content-Length: 2\r\n\r\n{}",
            )
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        let response = api_server.handle_request(&req);
        assert_eq!(response.status(), StatusCode::NoContent);

        // Test a Patch Mmds request.
        sender
            .write_all(
                b"PATCH /mmds HTTP/1.1\r\n\
                Content-Type: application/json\r\n\
                Content-Length: 2\r\n\r\n{}",
            )
            .unwrap();
        assert!(connection.try_read().is_ok());
        let req = connection.pop_parsed_request().unwrap();
        let response = api_server.handle_request(&req);
        assert_eq!(response.status(), StatusCode::NoContent);

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
        let response = api_server.handle_request(&req);
        assert_eq!(response.status(), StatusCode::BadRequest);
    }

    #[test]
    fn test_bind_and_run() {
        let path_to_socket = "/tmp/api_server_test_socket.sock";
        fs::remove_file(path_to_socket).unwrap_or_default();
        let vmm_shared_info = Arc::new(RwLock::new(InstanceInfo {
            state: InstanceState::Uninitialized,
            id: "test_handle_request".to_string(),
            vmm_version: "version 0.1.0".to_string(),
        }));

        let to_vmm_fd = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let (api_request_sender, _from_api) = channel();
        let (_to_api, vmm_response_receiver) = channel();
        let mmds_info = MMDS.clone();

        thread::Builder::new()
            .name("fc_api_test".to_owned())
            .spawn(move || {
                ApiServer::new(
                    mmds_info,
                    vmm_shared_info,
                    api_request_sender,
                    vmm_response_receiver,
                    to_vmm_fd,
                )
                .expect("Cannot create API server")
                .bind_and_run(
                    PathBuf::from(path_to_socket.to_string()),
                    Some(1),
                    Some(1),
                    SeccompFilter::empty().into_bpf().unwrap(),
                )
                .unwrap();
            })
            .unwrap();

        // Wait for the server to set itself up.
        thread::sleep(Duration::new(0, 10_000_000));
        let mut sock = UnixStream::connect(PathBuf::from(path_to_socket.to_string())).unwrap();

        // Send a GET instance-info request.
        assert!(sock.write_all(b"GET / HTTP/1.1\r\n\r\n").is_ok());
        let mut buf: [u8; 100] = [0; 100];
        assert!(sock.read(&mut buf[..]).unwrap() > 0);

        // Send an erroneous request.
        assert!(sock.write_all(b"OPTIONS / HTTP/1.1\r\n\r\n").is_ok());
        let mut buf: [u8; 100] = [0; 100];
        assert!(sock.read(&mut buf[..]).unwrap() > 0);
    }
}
