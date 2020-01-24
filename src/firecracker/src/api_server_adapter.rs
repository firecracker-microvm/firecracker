// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;

use api_server::{ApiRequest, ApiResponse, ApiServer};
use mmds::MMDS;
use polly::event_manager::EventManager;
use seccomp::BpfProgram;
use utils::eventfd::EventFd;
use vmm::controller::VmmController;
use vmm::rpc_interface::{PrebootApiController, RuntimeApiController};
use vmm::vmm_config::instance_info::InstanceInfo;
use vmm::EpollDispatch;

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

    /// Runs the vmm to completion, while any arising control events are deferred
    /// to a `RuntimeApiController`.
    fn run_microvm(&self, vmm_controller: VmmController) {
        let mut controller = RuntimeApiController(vmm_controller);
        let exit_code = loop {
            match controller.0.run_event_loop() {
                Err(e) => {
                    error!("Abruptly exited VMM control loop: {:?}", e);
                    break vmm::FC_EXIT_CODE_GENERIC_ERROR;
                }
                Ok(exit_reason) => match exit_reason {
                    vmm::EventLoopExitReason::Break => {
                        info!("Gracefully terminated VMM control loop");
                        break vmm::FC_EXIT_CODE_OK;
                    }
                    vmm::EventLoopExitReason::ControlAction => {
                        if let Err(e) = self.api_event_fd.read() {
                            error!("VMM: Failed to read the API event_fd: {}", e);
                            break vmm::FC_EXIT_CODE_GENERIC_ERROR;
                        };

                        match self.from_api.try_recv() {
                            Ok(api_request) => {
                                let response = controller.handle_request(*api_request);
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
                    }
                },
            };
        };
        controller.0.stop(i32::from(exit_code));
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
    // The event manager to replace EpollContext.
    let mut event_manager = EventManager::new().expect("Unable to create EventManager");
    // Cascade EventManager in EpollContext.
    epoll_context
        .add_epollin_event(&event_manager, EpollDispatch::PollyEvent)
        .expect("Cannot cascade EventManager from epoll_context");

    // Create the firecracker metrics object responsible for periodically printing metrics.
    let firecracker_metrics = Arc::new(Mutex::new(super::metrics::PeriodicMetrics::new()));
    event_manager
        .register(firecracker_metrics.clone())
        .expect("Cannot register the metrics event to the event manager.");

    epoll_context
        .add_epollin_event(&api_event_fd, EpollDispatch::VmmActionRequest)
        .expect("Cannot add vmm control_fd to epoll.");

    // Configure, build and start the microVM.
    let (vm_resources, vmm) = match config_json {
        Some(json) => super::build_microvm_from_json(
            seccomp_filter,
            &mut epoll_context,
            &mut event_manager,
            json,
        ),
        None => PrebootApiController::build_microvm_from_requests(
            seccomp_filter,
            &mut epoll_context,
            &mut event_manager,
            FIRECRACKER_VERSION.to_string(),
            || {
                let req = from_api
                    .recv()
                    .expect("The channel's sending half was disconnected. Cannot receive data.");
                // Also consume the API event along with the message. It is safe to unwrap()
                // since communication between this thread and the API thread is synchronous.
                api_event_fd
                    .read()
                    .expect("VMM: Failed to read the API event_fd");
                *req
            },
            |response| {
                to_api
                    .send(Box::new(response))
                    .expect("one-shot channel closed")
            },
        ),
    };

    // Start the metrics.
    firecracker_metrics
        .lock()
        .expect("Metrics lock poisoned.")
        .start(super::metrics::WRITE_METRICS_PERIOD_MS);

    // Update the api shared instance info.
    api_shared_info.write().unwrap().started = true;

    let api_handler = ApiServerAdapter::new(api_event_fd, from_api, to_api);
    api_handler.run_microvm(VmmController::new(
        epoll_context,
        event_manager,
        vm_resources,
        vmm,
    ));
}
