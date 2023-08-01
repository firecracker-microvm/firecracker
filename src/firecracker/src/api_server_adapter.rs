// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io::prelude::*;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;

use api_server::ApiServer;
use event_manager::{EventOps, Events, MutEventSubscriber, SubscriberOps};
use logger::{error, warn, ProcessTimeReporter};
use seccompiler::BpfThreadMap;
use utils::epoll::EventSet;
use utils::eventfd::EventFd;
use vmm::resources::VmResources;
use vmm::rpc_interface::{
    ApiRequest, ApiResponse, PostbootApiController, PrebootApiController, VmmAction,
};
use vmm::vmm_config::instance_info::InstanceInfo;
use vmm::{EventManager, FcExitCode, Vmm};

use crate::BuildMicrovmFromJsonError;

struct ApiServerAdapter {
    api_event_fd: EventFd,
    from_api: Receiver<ApiRequest>,
    to_api: Sender<ApiResponse>,
    controller: PostbootApiController,
}

impl ApiServerAdapter {
    /// Runs the vmm to completion, while any arising control events are deferred
    /// to a `PostbootApiController`.
    fn run_microvm(
        api_event_fd: EventFd,
        from_api: Receiver<ApiRequest>,
        to_api: Sender<ApiResponse>,
        vm_resources: VmResources,
        vmm: Arc<Mutex<Vmm>>,
        event_manager: &mut EventManager,
    ) {
        let api_adapter = Arc::new(Mutex::new(Self {
            api_event_fd,
            from_api,
            to_api,
            controller: PostbootApiController::new(vm_resources, vmm.clone()),
        }));
        event_manager.add_subscriber(api_adapter);
        loop {
            event_manager
                .run()
                .expect("EventManager events driver fatal error");
            if let Some(result) = vmm.lock().unwrap().shutdown_result() {
                return;
            }
        }
    }

    fn handle_request(&mut self, req_action: VmmAction) {
        let response = self.controller.handle_postboot_request(req_action);
        let wrapped = response.map_err(vmm::rpc_interface::VmmActionError::HandlePostbootRequest);
        // Send back the result.
        self.to_api
            .send(Box::new(wrapped))
            .map_err(|_| ())
            .expect("one-shot channel closed");
    }
}
impl MutEventSubscriber for ApiServerAdapter {
    /// Handle a read event (EPOLLIN).
    fn process(&mut self, event: Events, _: &mut EventOps) {
        let source = event.fd();
        let event_set = event.event_set();

        if source == self.api_event_fd.as_raw_fd() && event_set == EventSet::IN {
            let _ = self.api_event_fd.read();
            match self.from_api.try_recv() {
                Ok(api_request) => {
                    let request_is_pause = *api_request == VmmAction::Pause;
                    self.handle_request(*api_request);

                    // If the latest req is a pause request, temporarily switch to a mode where we
                    // do blocking `recv`s on the `from_api` receiver in a loop, until we get
                    // unpaused. The device emulation is implicitly paused since we do not
                    // relinquish control to the event manager because we're not returning from
                    // `process`.
                    if request_is_pause {
                        // This loop only attempts to process API requests, so things like the
                        // metric flush timerfd handling are frozen as well.
                        loop {
                            let req = self.from_api.recv().expect("Error receiving API request.");
                            let req_is_resume = *req == VmmAction::Resume;
                            self.handle_request(*req);
                            if req_is_resume {
                                break;
                            }
                        }
                    }
                }
                Err(TryRecvError::Empty) => {
                    warn!("Got a spurious notification from api thread");
                }
                Err(TryRecvError::Disconnected) => {
                    panic!("The channel's sending half was disconnected. Cannot receive data.");
                }
            };
        } else {
            error!("Spurious EventManager event for handler: ApiServerAdapter");
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        if let Err(err) = ops.add(Events::new(&self.api_event_fd, EventSet::IN)) {
            error!("Failed to register activate event: {}", err);
        }
    }
}

/// Error type for [`run_with_api`].
#[derive(Debug, thiserror::Error)]
pub(super) enum RunWithApiError {
    /// Cannot create API Eventfd
    #[error("Cannot create API Eventfd: {0}")]
    ApiEventFd(std::io::Error),
    /// Failed to clone API event FD
    #[error("Failed to clone API event FD: {0}")]
    CloneApiEventFd(std::io::Error),
    /// Missing seccomp filter for API thread
    #[error("Missing seccomp filter for API thread: {0}")]
    SeccompFilter(i32),
    /// MicroVMStopped without an error
    #[error("MicroVMStopped without an error: {0:?}")]
    MicroVMStoppedWithoutError(FcExitCode),
    /// Failed to bind and run API server
    #[error("Failed to bind and run API server: {0}")]
    BindAndRun(api_server::BindAndRunError),
    /// Failed to build MicroVM from Json
    #[error("Failed to build MicroVM from Json: {0:?}")]
    BuildMicrovmFromJson(BuildMicrovmFromJsonError),
    /// Failed to build microvm from requests
    #[error("Failed to build microvm from requests: {0}")]
    BuildMicrovmFromRequests(vmm::rpc_interface::BuildMicrovmFromRequestsError),
    /// todo
    #[error("{0}")]
    ApiServerAdapter(vmm::RunMicrovmError),
    /// Failed to create API exit eventfd.
    #[error("Failed to create API exit eventfd: {0}")]
    CreateApiExit(std::io::Error),
    /// Failed to write to API exit eventfd.
    #[error("Failed to write to API exit eventfd: {0}")]
    WriteApiExit(std::io::Error),
}



#[allow(clippy::too_many_arguments)]
pub(crate) fn run_with_api(
    seccomp_filters: &mut BpfThreadMap,
    config_json: Option<String>,
    bind_path: PathBuf,
    instance_info: InstanceInfo,
    process_time_reporter: ProcessTimeReporter,
    boot_timer_enabled: bool,
    api_payload_limit: usize,
    mmds_size_limit: usize,
    metadata_json: Option<&str>,
) -> Result<(), RunWithApiError> {
    // FD to notify of API events. This is a blocking eventfd by design.
    // It is used in the config/pre-boot loop which is a simple blocking loop
    // which only consumes API events.
    let api_event_fd = EventFd::new(libc::EFD_SEMAPHORE).map_err(RunWithApiError::ApiEventFd)?;

    // Channels for both directions between Vmm and Api threads.
    let (to_vmm, from_api) = channel();
    let (to_api, from_vmm) = channel();
    let (socket_ready_sender, socket_ready_receiver) = channel();

    let to_vmm_event_fd = api_event_fd
        .try_clone()
        .map_err(RunWithApiError::CloneApiEventFd)?;
    let api_bind_path = bind_path.clone();
    let api_seccomp_filter = seccomp_filters
        .remove("api")
        .expect("Missing seccomp filter for API thread.");

    // Start the separate API thread.
    let api_exit = EventFd::new(0).map_err(RunWithApiError::CreateApiExit)?;
    let api_thread = thread::Builder::new()
        .name("fc_api".to_owned())
        .spawn(move || {
            ApiServer::new(to_vmm, from_vmm, to_vmm_event_fd)
                .bind_and_run(
                    &api_bind_path,
                    process_time_reporter,
                    &api_seccomp_filter,
                    api_payload_limit,
                    socket_ready_sender,
                    api_exit,
                )
                .map_err(RunWithApiError::BindAndRun)
        });

    let mut event_manager = EventManager::new().expect("Unable to create EventManager");

    // Create the firecracker metrics object responsible for periodically printing metrics.
    let firecracker_metrics = Arc::new(Mutex::new(super::metrics::PeriodicMetrics::new()));
    event_manager.add_subscriber(firecracker_metrics.clone());

    // Configure, build and start the microVM.
    let (vm_resources, vmm) = match config_json {
        Some(json) => super::build_microvm_from_json(
            seccomp_filters,
            &mut event_manager,
            json,
            instance_info,
            boot_timer_enabled,
            mmds_size_limit,
            metadata_json,
        )
        .map_err(RunWithApiError::BuildMicrovmFromJson),
        None => PrebootApiController::build_microvm_from_requests(
            seccomp_filters,
            &mut event_manager,
            instance_info,
            &from_api,
            &to_api,
            &api_event_fd,
            boot_timer_enabled,
            mmds_size_limit,
            metadata_json,
        )
        .map_err(RunWithApiError::BuildMicrovmFromRequests),
    }?;

    dbg!("here?asd 1");

    firecracker_metrics
        .lock()
        .expect("Poisoned lock")
        .start(super::metrics::WRITE_METRICS_PERIOD_MS);

    // Due to limitations in event manager `run_microvm` will exit when `shutdown_result` is set.
    let api_sever_adapter = ApiServerAdapter::run_microvm(
        api_event_fd,
        from_api,
        to_api,
        vm_resources,
        vmm,
        &mut event_manager,
    );
    // We then propagate the possible error in `shutdown_result` by moving `vmm` out of the mutex.
    let vmm = vmm.into_inner().unwrap();
    vmm.shutdown_result.unwrap().map_err(RunWithApiError::ApiServerAdapter)?;

    api_exit.write(1).map_err(RunWithApiError::WriteApiExit)?;

    dbg!("here?asd 2");

    // This call to thread::join() should block until the API thread has processed the
    // shutdown-internal and returns from its function.
    api_thread.unwrap().join().unwrap()?;

    Ok(())
}
