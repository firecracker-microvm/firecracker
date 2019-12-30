// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, RecvError, Sender, TryRecvError};
use std::sync::{Arc, RwLock};
use std::thread;

use api_server::{ApiRequest, ApiResponse, ApiServer};
use mmds::MMDS;
use seccomp::BpfProgram;
use utils::eventfd::EventFd;
use vmm::controller::VmmController;
use vmm::rpc_interface::{
    PrebootApiAdapter, PrebootApiController, RuntimeApiAdapter, RuntimeApiController,
};
use vmm::vmm_config::instance_info::InstanceInfo;

use super::FIRECRACKER_VERSION;

struct ApiServerAdapter {
    api_event_fd: EventFd,
    from_api: Receiver<ApiRequest>,
    to_api: Sender<ApiResponse>,
}

impl ApiServerAdapter {
    pub fn new(
        api_event_fd: EventFd,
        from_api: Receiver<ApiRequest>,
        to_api: Sender<ApiResponse>,
    ) -> Self {
        ApiServerAdapter {
            api_event_fd,
            from_api,
            to_api,
        }
    }
}

impl PrebootApiAdapter for ApiServerAdapter {
    /// Handles the control events received before microVM boot.
    /// Receives and runs the Vmm action and sends back a response.
    /// Attempts to build and boot a microVM on the `StartMicrovm` request.
    fn preboot_request_injector(&self, handler: &mut PrebootApiController) -> Option<vmm::Vmm> {
        match self.from_api.recv() {
            Ok(vmm_request) => {
                // Also consume the API event. This is safe since communication
                // between this thread and the API thread is synchronous.
                let _ = self.api_event_fd.read().map_err(|e| {
                    error!("VMM: Failed to read the API event_fd: {}", e);
                    std::process::exit(i32::from(vmm::FC_EXIT_CODE_GENERIC_ERROR));
                });

                let (response, maybe_vmm) = handler.handle_preboot_request(*vmm_request);

                // Send back the result.
                self.to_api
                    .send(Box::new(response))
                    .map_err(|_| ())
                    .expect("one-shot channel closed");

                maybe_vmm
            }
            Err(RecvError) => {
                panic!("The channel's sending half was disconnected. Cannot receive data.");
            }
        }
    }
}

impl RuntimeApiAdapter for ApiServerAdapter {
    /// Handles the control event received at microVM runtime.
    /// Receives and runs the Vmm action and sends back a response.
    /// Provides program exit codes on errors.
    fn runtime_request_injector(&self, handler: &mut RuntimeApiController) -> Result<(), u8> {
        self.api_event_fd.read().map_err(|e| {
            error!("VMM: Failed to read the API event_fd: {}", e);
            vmm::FC_EXIT_CODE_GENERIC_ERROR
        })?;

        match self.from_api.try_recv() {
            Ok(api_request) => {
                let response = handler.handle_request(*api_request);
                // Send back the result.
                self.to_api
                    .send(Box::new(response))
                    .map_err(|_| ())
                    .expect("one-shot channel closed");
            }
            Err(TryRecvError::Empty) => {
                warn!("Got a spurious notification from api thread");
            }
            Err(TryRecvError::Disconnected) => {
                panic!("The channel's sending half was disconnected. Cannot receive data.");
            }
        };
        Ok(())
    }
}

pub fn run_with_api(
    seccomp_filter: BpfProgram,
    config_json: Option<String>,
    bind_path: PathBuf,
    instance_info: InstanceInfo,
    start_time_us: Option<u64>,
    start_time_cpu_us: Option<u64>,
) {
    // FD to notify of API events.
    let api_event_fd = EventFd::new(libc::EFD_NONBLOCK)
        .map_err(api_server::Error::Eventfd)
        .expect("Cannot create API Eventfd.");
    // Channels for both directions between Vmm and Api threads.
    let (to_vmm, from_api) = channel();
    let (to_api, from_vmm) = channel();

    // MMDS only supported with API.
    let mmds_info = MMDS.clone();
    let api_shared_info = Arc::new(RwLock::new(instance_info));
    let vmm_shared_info = api_shared_info.clone();
    let to_vmm_event_fd = api_event_fd.try_clone().unwrap();

    let api_seccomp_filter = seccomp_filter.clone();
    // Start the separate API thread.
    thread::Builder::new()
        .name("fc_api".to_owned())
        .spawn(move || {
            match ApiServer::new(
                mmds_info,
                vmm_shared_info,
                to_vmm,
                from_vmm,
                to_vmm_event_fd,
            )
            .expect("Cannot create API server")
            .bind_and_run(
                bind_path,
                start_time_us,
                start_time_cpu_us,
                api_seccomp_filter,
            ) {
                Ok(_) => (),
                Err(api_server::Error::Io(inner)) => match inner.kind() {
                    std::io::ErrorKind::AddrInUse => panic!(
                        "Failed to open the API socket: {:?}",
                        api_server::Error::Io(inner)
                    ),
                    _ => panic!(
                        "Failed to communicate with the API socket: {:?}",
                        api_server::Error::Io(inner)
                    ),
                },
                Err(eventfd_err @ api_server::Error::Eventfd(_)) => {
                    panic!("Failed to open the API socket: {:?}", eventfd_err)
                }
            }
        })
        .expect("API thread spawn failed.");

    // The driving epoll engine.
    let mut epoll_context = vmm::EpollContext::new().expect("Cannot create the epoll context.");

    epoll_context
        .add_epollin_event(&api_event_fd, vmm::EpollDispatch::VmmActionRequest)
        .expect("Cannot add vmm control_fd to epoll.");

    let api_handler = ApiServerAdapter::new(api_event_fd, from_api, to_api);
    // Configure, build and start the microVM.
    let (vm_resources, vmm) = match config_json {
        Some(json) => super::build_microvm_from_json(seccomp_filter, &mut epoll_context, json),
        None => api_handler.build_microvm_from_requests(
            seccomp_filter,
            &mut epoll_context,
            FIRECRACKER_VERSION.to_string(),
        ),
    };

    // Update the api shared instance info.
    api_shared_info.write().unwrap().started = true;

    api_handler.run(VmmController::new(epoll_context, vm_resources, vmm));
}
