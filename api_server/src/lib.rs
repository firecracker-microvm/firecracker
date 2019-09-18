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

use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;

use logger::{Metric, METRICS};
pub use micro_http::{
    Body, HttpServer, Method, Request, RequestError, Response, StatusCode, Token, Version,
};
use mmds::data_store;
use mmds::data_store::Mmds;
use parsed_request::ParsedRequest;
use std::collections::{HashMap, VecDeque};
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

enum ApiServerDispatch {
    ServerNotification,
    FromVmmFd,
    ToVmmFd,
}

pub struct ApiServer {
    /// MMDS info directly accessible from the API thread.
    mmds_info: Arc<Mutex<Mmds>>,
    /// VMM instance info directly accessible from the API thread.
    vmm_shared_info: Arc<RwLock<InstanceInfo>>,
    /// Sender which allows passing messages to the VMM.
    api_request_sender: mpsc::Sender<Box<(VmmAction, Token)>>,
    /// Receiver which collects messages from the VMM.
    vmm_response_receiver: mpsc::Receiver<Box<(VmmRequestOutcome, Token)>>,
    /// FD on which we notify the VMM that we have sent at least one
    /// `VmmActionRequest`.
    to_vmm_fd: EventFd,
    /// FD on which we are notified by the VMM that we have received at least
    /// one `VmmRequestOutcome`.
    from_vmm_fd: EventFd,
    /// The FD of the `epoll` structure pertaining to the API server. This `epoll`
    /// structure has FDs which fire on either a `ServerNotification`, which means
    /// that the `HttpServer`.
    epoll_fd: RawFd,
    dispatch_table: HashMap<Token, ApiServerDispatch>,
}

impl ApiServer {
    pub fn new(
        mmds_info: Arc<Mutex<Mmds>>,
        vmm_shared_info: Arc<RwLock<InstanceInfo>>,
        api_request_sender: mpsc::Sender<Box<(VmmAction, Token)>>,
        vmm_response_receiver: mpsc::Receiver<Box<(VmmRequestOutcome, Token)>>,
        to_vmm_fd: EventFd,
        from_vmm_fd: EventFd,
    ) -> Result<Self> {
        let epoll_fd = epoll::create(false).map_err(Error::Io)?;
        let mut dispatch_table = HashMap::new();
        dispatch_table.insert(0, ApiServerDispatch::ServerNotification);
        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            from_vmm_fd.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, 1),
        )
        .map_err(Error::Io)?;
        dispatch_table.insert(1, ApiServerDispatch::FromVmmFd);
        dispatch_table.insert(2, ApiServerDispatch::ToVmmFd);

        Ok(ApiServer {
            mmds_info,
            vmm_shared_info,
            api_request_sender,
            vmm_response_receiver,
            to_vmm_fd,
            from_vmm_fd,
            epoll_fd,
            dispatch_table,
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
        epoll::ctl(
            self.epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            server.get_epoll_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, 0),
        )
        .map_err(Error::Io)?;

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

        let mut transit_queue: VecDeque<(Token, VmmAction)> = VecDeque::new();

        loop {
            let mut events =
                vec![epoll::Event::new(epoll::Events::empty(), 0); self.dispatch_table.len()];
            let num_ev = epoll::wait(self.epoll_fd, -1, &mut events[..]).map_err(Error::Io)?;
            for e in events.iter().take(num_ev) {
                let epoll_token = e.data as u64;
                match self.dispatch_table[&epoll_token] {
                    ApiServerDispatch::ServerNotification => {
                        if let Ok(request_vec) = server.wait_server() {
                            for (token, request) in request_vec {
                                if let Some(vmm_action) =
                                    self.request_triage(&mut server, request, token)
                                {
                                    if transit_queue.is_empty() {
                                        epoll::ctl(
                                            self.epoll_fd,
                                            epoll::ControlOptions::EPOLL_CTL_ADD,
                                            self.to_vmm_fd.as_raw_fd(),
                                            epoll::Event::new(epoll::Events::EPOLLOUT, 2),
                                        )
                                        .map_err(Error::Io)?;
                                    }
                                    transit_queue.push_back((token, vmm_action));
                                }
                            }
                        }
                    }
                    ApiServerDispatch::FromVmmFd => {
                        let num_responses = self.from_vmm_fd.read().unwrap();
                        let mut responses = Vec::with_capacity(num_responses as usize);
                        for _ in 0..num_responses {
                            let (vmm_outcome, token) = *self.vmm_response_receiver.recv().unwrap();
                            let response = ParsedRequest::convert_to_response(vmm_outcome);
                            responses.push((token, response));
                        }
                        server.enqueue_responses(responses);
                    }
                    ApiServerDispatch::ToVmmFd => {
                        let (token, vmm_action) = transit_queue.pop_front().unwrap();
                        self.to_vmm_fd.write(1).unwrap();
                        self.api_request_sender
                            .send(Box::new((vmm_action, token)))
                            .unwrap();

                        if transit_queue.is_empty() {
                            epoll::ctl(
                                self.epoll_fd,
                                epoll::ControlOptions::EPOLL_CTL_DEL,
                                self.to_vmm_fd.as_raw_fd(),
                                epoll::Event::new(epoll::Events::EPOLLOUT, 2),
                            )
                            .map_err(Error::Io)?;
                        }
                    }
                }
            }
        }
    }

    fn request_triage(
        &self,
        server: &mut HttpServer,
        request: Request,
        token: Token,
    ) -> Option<VmmAction> {
        match ParsedRequest::try_from_request(request, token) {
            Ok(ParsedRequest::Sync(vmm_action)) => {
                return Some(vmm_action);
            }
            Ok(ParsedRequest::GetInstanceInfo) => {
                let shared_info_lock = self.vmm_shared_info.clone();
                METRICS.get_api_requests.instance_info_count.inc();
                //log_received_api_request(describe(&method_copy, &path, &None));
                // unwrap() to crash if the other thread poisoned this lock
                let shared_info = shared_info_lock
                    .read()
                    .expect("Failed to read shared_info due to poisoned lock");
                // Serialize it to a JSON string.
                let body_result = serde_json::to_string(&(*shared_info));
                let response = match body_result {
                    Ok(body) => ApiServer::json_response(StatusCode::OK, body),
                    Err(e) => {
                        // This is an api server metrics as the shared info is obtained internally.
                        METRICS.get_api_requests.instance_info_fails.inc();
                        ApiServer::json_response(
                            StatusCode::BadRequest,
                            ApiServer::json_fault_message(e.to_string()),
                        )
                    }
                };
                server.enqueue_responses(vec![(token, response)]);
            }
            Ok(ParsedRequest::GetMMDS) => {
                //log_received_api_request(describe(&method_copy, &path, &None));
                server.enqueue_responses(vec![(
                    token,
                    ApiServer::json_response(
                        StatusCode::OK,
                        self.mmds_info
                            .lock()
                            .expect("Failed to acquire lock on MMDS info")
                            .get_data_str(),
                    ),
                )]);
            }
            Ok(ParsedRequest::PatchMMDS(value)) => {
                //log_received_api_request(describe(&method_copy, &path, &None));
                let mmds_response = self
                    .mmds_info
                    .lock()
                    .expect("Failed to acquire lock on MMDS info")
                    .patch_data(value);
                let response = match mmds_response {
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
                };
                server.enqueue_responses(vec![(token, response)]);
            }
            Ok(ParsedRequest::PutMMDS(value)) => {
                //log_received_api_request(describe(&method_copy, &path, &None));
                let mmds_response = self
                    .mmds_info
                    .lock()
                    .expect("Failed to acquire lock on MMDS info")
                    .put_data(value);
                let response = match mmds_response {
                    Ok(_) => Response::new(Version::Http11, StatusCode::NoContent),
                    Err(e) => ApiServer::json_response(
                        StatusCode::BadRequest,
                        ApiServer::json_fault_message(e.to_string()),
                    ),
                };
                server.enqueue_responses(vec![(token, response)]);
            }
            Err(e) => {
                server.enqueue_responses(vec![(token, e.into())]);
            }
        };

        None
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
