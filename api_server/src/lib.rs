// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

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

use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, RwLock};
use std::{fmt, io};

use futures::sync::oneshot;
use futures::{Future, Stream};
use hyper::server::Http;
use tokio_core::reactor::Core;
use tokio_uds::UnixListener;

use http_service::ApiServerHttpService;
use logger::{Metric, METRICS};
use mmds::data_store::Mmds;
use sys_util::EventFd;
use vmm::default_syscalls;
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

/// One shot channel used by VMM to send a response.
pub type ResponseSender = oneshot::Sender<std::result::Result<VmmData, VmmActionError>>;
/// One shot channel used to receive a response from the VMM.
pub type ResponseReceiver = oneshot::Receiver<std::result::Result<VmmData, VmmActionError>>;

/// Wrapper over requested action to be done by the VMM and sender where the response will go.
/// This is wrapped in a struct to allow custom PartialEq.
pub struct VmmRequest {
    inner: Box<(VmmAction, ResponseSender)>,
}

impl VmmRequest {
    /// Create a VmmRequest from given VmmAction and ResponseSender.
    pub fn new(action: VmmAction, response_sender: ResponseSender) -> VmmRequest {
        VmmRequest {
            inner: Box::new((action, response_sender)),
        }
    }

    pub fn unpack(self) -> (VmmAction, ResponseSender) {
        let inner_box = *self.inner;
        (inner_box.0, inner_box.1)
    }
}

impl PartialEq for VmmRequest {
    fn eq(&self, other: &VmmRequest) -> bool {
        self.inner.0 == other.inner.0
    }
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

pub struct ApiServer {
    // MMDS info directly accessible from the API thread.
    mmds_info: Arc<Mutex<Mmds>>,
    // VMM instance info directly accessible from the API thread.
    vmm_shared_info: Arc<RwLock<InstanceInfo>>,
    // Sender which allows passing messages to the VMM.
    api_request_sender: Rc<mpsc::Sender<VmmRequest>>,
    efd: Rc<EventFd>,
}

impl ApiServer {
    pub fn new(
        mmds_info: Arc<Mutex<Mmds>>,
        vmm_shared_info: Arc<RwLock<InstanceInfo>>,
        api_request_sender: mpsc::Sender<VmmRequest>,
        kick_vmm_efd: EventFd,
    ) -> Result<Self> {
        Ok(ApiServer {
            mmds_info,
            vmm_shared_info,
            api_request_sender: Rc::new(api_request_sender),
            efd: Rc::new(kick_vmm_efd),
        })
    }

    // TODO: does tokio_uds also support abstract domain sockets?
    pub fn bind_and_run(
        &self,
        path: PathBuf,
        start_time_us: Option<u64>,
        start_time_cpu_us: Option<u64>,
        seccomp_level: u32,
    ) -> Result<()> {
        let mut core = Core::new().map_err(Error::Io)?;
        let handle = Rc::new(core.handle());

        let listener = UnixListener::bind(path, &handle).map_err(Error::Io)?;

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
            })
            .map_err(Error::Io);

        // Load seccomp filters on the API thread.
        // Execution panics if filters cannot be loaded, use --seccomp-level=0 if skipping filters
        // altogether is the desired behaviour.
        if let Err(e) = default_syscalls::set_seccomp_level(seccomp_level) {
            panic!(
                "Failed to set the requested seccomp filters on the API thread: Error: {:?}",
                e
            );
        }

        // This runs forever, unless an error is returned somewhere within f (but nothing happens
        // for errors which might arise inside the connections we spawn from f, unless we explicitly
        // do something in their future chain). When this returns, ongoing connections will be
        // interrupted, and other futures will not complete, as the event loop stops working.
        core.run(f)
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
