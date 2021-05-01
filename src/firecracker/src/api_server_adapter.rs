// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{
    os::unix::io::AsRawFd,
    path::PathBuf,
    sync::mpsc::{channel, Receiver, Sender, TryRecvError},
    sync::{Arc, Mutex},
    thread,

    os::unix::net::UnixStream,  // for main thread to send ShutdownInternal to API thread
    io::prelude::*,  // UnixStream write_all() requires prelude
};

use api_server::{ApiRequest, ApiResponse, ApiServer};
use logger::{error, warn, ProcessTimeReporter};
use mmds::MMDS;
use polly::event_manager::{EventManager, Subscriber, ExitCode};
use seccomp::BpfProgram;
use utils::{
    epoll::{EpollEvent, EventSet},
    eventfd::EventFd,
};
use vmm::signal_handler::{mask_handled_signals, SignalManager};
use vmm::{
    resources::VmResources,
    rpc_interface::{PrebootApiController, RuntimeApiController, VmmAction},
    vmm_config::instance_info::InstanceInfo,
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
        vm_resources: VmResources,
        vmm: Arc<Mutex<Vmm>>,
        event_manager: &mut EventManager,
    ) -> ExitCode {
        let api_adapter = Arc::new(Mutex::new(Self {
            api_event_fd,
            from_api,
            to_api,
            controller: RuntimeApiController::new(vm_resources, vmm),
        }));
        event_manager
            .add_subscriber(api_adapter)
            .expect("Cannot register the api event to the event manager.");

        loop {
            let opt_exit_code = event_manager
                .run_maybe_exiting()
                .expect("EventManager events driver fatal error");

            if let Some(exit_code) = opt_exit_code { return exit_code; }
        }
    }

    fn handle_request(&mut self, req_action: VmmAction) {
        let response = self.controller.handle_request(req_action);
        // Send back the result.
        self.to_api
            .send(Box::new(response))
            .map_err(|_| ())
            .expect("one-shot channel closed");
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

pub(crate) fn run_with_api(
    seccomp_filter: BpfProgram,
    config_json: Option<String>,
    bind_path: PathBuf,
    instance_info: InstanceInfo,
    process_time_reporter: ProcessTimeReporter,
    boot_timer_enabled: bool,
) -> ExitCode {
    // FD to notify of API events. This is a blocking eventfd by design.
    // It is used in the config/pre-boot loop which is a simple blocking loop
    // which only consumes API events.
    let api_event_fd = EventFd::new(0).expect("Cannot create API Eventfd.");
    // Channels for both directions between Vmm and Api threads.
    let (to_vmm, from_api) = channel();
    let (to_api, from_vmm) = channel();

    // MMDS only supported with API.
    let mmds_info = MMDS.clone();
    let api_server_instance_info = instance_info.clone();
    let to_vmm_event_fd = api_event_fd
        .try_clone()
        .expect("Failed to clone API event FD");

    let api_bind_path = bind_path.clone();
    let api_seccomp_filter = seccomp_filter.clone();
    // Start the separate API thread.
    let api_thread = thread::Builder::new()
        .name("fc_api".to_owned())
        .spawn(move || {
            mask_handled_signals().expect("Unable to install signal mask on API thread.");

            match ApiServer::new(
                mmds_info,
                api_server_instance_info,
                to_vmm,
                from_vmm,
                to_vmm_event_fd,
            )
            .bind_and_run(api_bind_path, process_time_reporter, api_seccomp_filter)
            {
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
    // Right before creating the signalfd,
    // mask the handled signals so that the default handlers are bypassed.
    mask_handled_signals().expect("Unable to install signal mask on VMM thread.");
    let signal_manager = Arc::new(Mutex::new(
        SignalManager::new().expect("Unable to create SignalManager."),
    ));

    // Register the signal handler event fd.
    event_manager
        .add_subscriber(signal_manager)
        .expect("Cannot register the signal handler fd to the event manager.");

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

    let exit_code = ApiServerAdapter::run_microvm(
        api_event_fd,
        from_api,
        to_api,
        vm_resources,
        vmm,
        &mut event_manager,
    );

    // We want to tell the API thread to shut down for a clean exit.  But this is after
    // the Vmm.stop() has been called, so it's a moment of internal finalization (as
    // opposed to be something the client might call to shut the Vm down).  Since it's
    // an internal signal implementing it with an HTTP request is probably not the ideal
    // way to do it...but having another way would involve waiting on the socket or some
    // other signal.  This leverages the existing wait.
    //
    // !!! Since the code is only needed for a "clean" shutdown mode, a non-clean mode
    // could not respond to the request, making this effectively a debug-only feature.
    //
    let mut sock = UnixStream::connect(bind_path).unwrap();
    assert!(sock.write_all(b"GET /shutdown-internal HTTP/1.1\r\n\r\n").is_ok());

    // This call to thread::join() should block until the API thread has processed the
    // shutdown-internal and returns from its function.  If it doesn't block here, then
    // that means it got the message; so no need to process a response.
    //
    api_thread.join().unwrap();

    exit_code
}
