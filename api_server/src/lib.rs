// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

extern crate epoll;
extern crate fc_util;
#[macro_use]
extern crate logger;
extern crate micro_http;
extern crate mmds;
extern crate sys_util;
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
use sys_util::EventFd;
use vmm::vmm_config::instance_info::InstanceInfo;
use vmm::VmmAction;
use vmm::{default_syscalls, VmmRequestOutcome};

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

pub struct ApiServer {
    /// MMDS info directly accessible from the API thread.
    mmds_info: Arc<Mutex<Mmds>>,
    /// VMM instance info directly accessible from the API thread.
    vmm_shared_info: Arc<RwLock<InstanceInfo>>,
    /// Sender which allows passing messages to the VMM.
    api_request_sender: mpsc::Sender<Box<VmmAction>>,
    /// Receiver which collects messages from the VMM.
    vmm_response_receiver: mpsc::Receiver<Box<VmmRequestOutcome>>,
    /// FD on which we notify the VMM that we have sent at least one
    /// `VmmActionRequest`.
    to_vmm_fd: EventFd,
}

impl ApiServer {
    pub fn new(
        mmds_info: Arc<Mutex<Mmds>>,
        vmm_shared_info: Arc<RwLock<InstanceInfo>>,
        api_request_sender: mpsc::Sender<Box<VmmAction>>,
        vmm_response_receiver: mpsc::Receiver<Box<VmmRequestOutcome>>,
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
        seccomp_level: u32,
    ) -> Result<()> {
        let mut server = HttpServer::new(path).unwrap();

        if let Some(start_time) = start_time_us {
            let delta_us = (fc_util::get_time(fc_util::ClockType::Monotonic) / 1000) - start_time;
            METRICS
                .api_server
                .process_startup_time_us
                .add(delta_us as usize);
        }

        if let Some(cpu_start_time) = start_time_cpu_us {
            let delta_us =
                fc_util::get_time(fc_util::ClockType::ProcessCpu) / 1000 - cpu_start_time;
            METRICS
                .api_server
                .process_startup_time_cpu_us
                .add(delta_us as usize);
        }

        // Load seccomp filters on the API thread.
        // Execution panics if filters cannot be loaded, use --seccomp-level=0 if skipping filters
        // altogether is the desired behaviour.
        if let Err(e) = default_syscalls::set_seccomp_level(seccomp_level) {
            panic!(
                "Failed to set the requested seccomp filters on the API thread: Error: {:?}",
                e
            );
        }

        server.start_server().unwrap();
        loop {
            match server.incoming() {
                Ok(request_vec) => {
                    for server_request in request_vec {
                        server
                            .respond(server_request.process(|request| self.handle_request(request)))
                            .or_else(|e| {
                                error!("API Server encountered an error on response: {}", e);
                                Ok(())
                            })?;
                    }
                }
                Err(_error) => {
                    // Maybe log error or crash.
                }
            }
        }
    }

    fn handle_request(&self, request: &Request) -> Response {
        match ParsedRequest::try_from_request(request) {
            Ok(ParsedRequest::Sync(vmm_action)) => self.server_vmm_action_request(vmm_action),
            Ok(ParsedRequest::GetInstanceInfo) => self.get_instance_info(),
            Ok(ParsedRequest::GetMMDS) => self.get_mmds(),
            Ok(ParsedRequest::PatchMMDS(value)) => self.patch_mmds(value),
            Ok(ParsedRequest::PutMMDS(value)) => self.put_mmds(value),
            Err(e) => e.into(),
        }
    }

    fn server_vmm_action_request(&self, vmm_action: VmmAction) -> Response {
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

    // An HTTP response which also includes a body.
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
}
