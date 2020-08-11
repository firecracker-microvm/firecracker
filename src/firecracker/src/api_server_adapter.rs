// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    os::unix::io::AsRawFd,
    path::PathBuf,
    sync::mpsc::{channel, Receiver, Sender, TryRecvError},
    sync::{Arc, Mutex, RwLock},
    thread,
};

use api_server::{ApiRequest, ApiResponse, ApiServer};
use logger::{error, warn};
use mmds::MMDS;
use polly::event_manager::{EventManager, Subscriber};
use seccomp::BpfProgram;
use utils::{
    epoll::{EpollEvent, EventSet},
    eventfd::EventFd,
};
use vmm::{
    rpc_interface::{PrebootApiController, RuntimeApiController},
    vmm_config::instance_info::InstanceInfo,
    vmm_config::machine_config::VmConfig,
    Vmm,
};

struct ApiServerAdapter {
    api_event_fd: EventFd,
    from_api: Receiver<ApiRequest>,
    to_api: Sender<ApiResponse>,
    controller: RuntimeApiController,
}

impl ApiServerAdapter {
    /// Runs the vmm to completion, while any arising control events are deferred
    /// to a `RuntimeApiController`.
    fn run_microvm(
        api_event_fd: EventFd,
        from_api: Receiver<ApiRequest>,
        to_api: Sender<ApiResponse>,
        vm_config: VmConfig,
        vmm: Arc<Mutex<Vmm>>,
        event_manager: &mut EventManager,
    ) {
        let api_adapter = Arc::new(Mutex::new(Self {
            api_event_fd,
            from_api,
            to_api,
            controller: RuntimeApiController::new(vm_config, vmm),
        }));
        event_manager
            .add_subscriber(api_adapter)
            .expect("Cannot register the api event to the event manager.");
        loop {
            event_manager
                .run()
                .expect("EventManager events driver fatal error");
        }
    }
}
impl Subscriber for ApiServerAdapter {
    /// Handle a read event (EPOLLIN).
    fn process(&mut self, event: &EpollEvent, _: &mut EventManager) {
        let source = event.fd();
        let event_set = event.event_set();

        if source == self.api_event_fd.as_raw_fd() && event_set == EventSet::IN {
            match self.from_api.try_recv() {
                Ok(api_request) => {
                    let response = self.controller.handle_request(*api_request);
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
            let _ = self.api_event_fd.read();
        } else {
            error!("Spurious EventManager event for handler: ApiServerAdapter");
        }
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        vec![EpollEvent::new(
            EventSet::IN,
            self.api_event_fd.as_raw_fd() as u64,
        )]
    }
}

pub fn run_with_api(
    seccomp_filter: BpfProgram,
    config_json: Option<String>,
    bind_path: PathBuf,
    instance_info: InstanceInfo,
    start_time_us: Option<u64>,
    start_time_cpu_us: Option<u64>,
    boot_timer_enabled: bool,
) {
    // FD to notify of API events. This is a blocking eventfd by design.
    // It is used in the config/pre-boot loop which is a simple blocking loop
    // which only consumes API events.
    let api_event_fd = EventFd::new(0).expect("Cannot create API Eventfd.");
    // Channels for both directions between Vmm and Api threads.
    let (to_vmm, from_api) = channel();
    let (to_api, from_vmm) = channel();

    // MMDS only supported with API.
    let mmds_info = MMDS.clone();
    let api_shared_info = Arc::new(RwLock::new(instance_info.clone()));
    let vmm_shared_info = api_shared_info.clone();
    let to_vmm_event_fd = api_event_fd
        .try_clone()
        .expect("Failed to clone API event FD");

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

    let mut event_manager = EventManager::new().expect("Unable to create EventManager");

    // Create the firecracker metrics object responsible for periodically printing metrics.
    let firecracker_metrics = Arc::new(Mutex::new(super::metrics::PeriodicMetrics::new()));
    event_manager
        .add_subscriber(firecracker_metrics.clone())
        .expect("Cannot register the metrics event to the event manager.");

    // Configure, build and start the microVM.
    let (vm_resources, vmm) = match config_json {
        Some(json) => super::build_microvm_from_json(
            seccomp_filter,
            &mut event_manager,
            json,
            &instance_info,
            boot_timer_enabled,
        ),
        None => PrebootApiController::build_microvm_from_requests(
            seccomp_filter,
            &mut event_manager,
            instance_info,
            || {
                let req = from_api
                    .recv()
                    .expect("The channel's sending half was disconnected. Cannot receive data.");
                // Also consume the API event along with the message. It is safe to unwrap()
                // because this event_fd is blocking.
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
            boot_timer_enabled,
        ),
    };

    // Start the metrics.
    firecracker_metrics
        .lock()
        .expect("Poisoned lock")
        .start(super::metrics::WRITE_METRICS_PERIOD_MS);

    // Update the api shared instance info.
    api_shared_info.write().unwrap().started = true;

    ApiServerAdapter::run_microvm(
        api_event_fd,
        from_api,
        to_api,
        vm_resources.vm_config().clone(),
        vmm,
        &mut event_manager,
    );
}
