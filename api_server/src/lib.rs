// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate chrono;
extern crate futures;
extern crate hyper;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate tokio_core;
extern crate tokio_uds;

extern crate fc_util;
#[macro_use]
extern crate logger;
extern crate mmds;
extern crate sys_util;
extern crate vmm;

mod http_service;
pub mod request;

use std::io;
use std::os::unix::io::FromRawFd;
use std::path::Path;
use std::rc::Rc;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, RwLock};

use futures::{Future, Stream};
use hyper::server::Http;
use tokio_core::reactor::Core;
use tokio_uds::UnixListener;

use http_service::ApiServerHttpService;
use logger::{Metric, METRICS};
use mmds::data_store::Mmds;
use sys_util::EventFd;
use vmm::vmm_config::instance_info::InstanceInfo;
use vmm::VmmAction;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Eventfd(sys_util::Error),
}

pub enum UnixDomainSocket<P> {
    Path(P),
    Fd(i32),
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct ApiServer {
    // MMDS info directly accessible from the API thread.
    mmds_info: Arc<Mutex<Mmds>>,
    // VMM instance info directly accessible from the API thread.
    vmm_shared_info: Arc<RwLock<InstanceInfo>>,
    // Sender which allows passing messages to the VMM.
    api_request_sender: Rc<mpsc::Sender<Box<VmmAction>>>,
    efd: Rc<EventFd>,
}

impl ApiServer {
    pub fn new(
        mmds_info: Arc<Mutex<Mmds>>,
        vmm_shared_info: Arc<RwLock<InstanceInfo>>,
        api_request_sender: mpsc::Sender<Box<VmmAction>>,
    ) -> Result<Self> {
        Ok(ApiServer {
            mmds_info,
            vmm_shared_info,
            api_request_sender: Rc::new(api_request_sender),
            efd: Rc::new(EventFd::new().map_err(Error::Eventfd)?),
        })
    }

    // TODO: does tokio_uds also support abstract domain sockets?
    pub fn bind_and_run<P: AsRef<Path>>(
        &self,
        path_or_fd: UnixDomainSocket<P>,
        start_time_us: Option<u64>,
        start_time_cpu_us: Option<u64>,
    ) -> Result<()> {
        let mut core = Core::new().map_err(Error::Io)?;
        let handle = Rc::new(core.handle());

        let listener = match path_or_fd {
            UnixDomainSocket::Path(path) => UnixListener::bind(path, &handle).map_err(Error::Io)?,
            UnixDomainSocket::Fd(fd) => {
                // Safe because we assume fd is a valid file descriptor number, associated with a
                // previously bound UnixListener.
                UnixListener::from_listener(
                    unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) },
                    &handle,
                ).map_err(Error::Io)?
            }
        };

        if let Some(start_time) = start_time_us {
            let delta_us = (chrono::Utc::now().timestamp_nanos() / 1000) as u64 - start_time;
            METRICS
                .api_server
                .process_startup_time_us
                .add(delta_us as usize);
        }

        if let Some(cpu_start_time) = start_time_cpu_us {
            let delta_us = fc_util::now_cputime_us() - cpu_start_time;
            METRICS
                .api_server
                .process_startup_time_cpu_us
                .add(delta_us as usize);
        }

        let http: Http<hyper::Chunk> = Http::new();

        let f = listener
            .incoming()
            .for_each(|(stream, _)| {
                // For the sake of clarity: when we use self.efd.clone(), the intent is to
                // clone the wrapping Rc, not the EventFd itself.
                let service = ApiServerHttpService::new(
                    self.mmds_info.clone(),
                    self.vmm_shared_info.clone(),
                    self.api_request_sender.clone(),
                    self.efd.clone(),
                );
                let connection = http.serve_connection(stream, service);
                // todo: is spawn() any better/worse than execute()?
                // We have to adjust the future item and error, to fit spawn()'s definition.
                handle.spawn(connection.map(|_| ()).map_err(|_| ()));
                Ok(())
            }).map_err(Error::Io);

        // This runs forever, unless an error is returned somewhere within f (but nothing happens
        // for errors which might arise inside the connections we spawn from f, unless we explicitly
        // do something in their future chain). When this returns, ongoing connections will be
        // interrupted, and other futures will not complete, as the event loop stops working.
        core.run(f)
    }

    pub fn get_event_fd_clone(&self) -> Result<EventFd> {
        self.efd.try_clone().map_err(Error::Eventfd)
    }
}
