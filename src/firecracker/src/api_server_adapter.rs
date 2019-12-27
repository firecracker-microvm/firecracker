// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, RecvError, Sender, TryRecvError};
use std::sync::{Arc, RwLock};
use std::thread;

use api_server::{ApiRequest, ApiResponse, ApiServer};
use mmds::MMDS;
use seccomp::{BpfProgram, BpfProgramRef};
use utils::eventfd::EventFd;
use vmm::controller::{ErrorKind, VmmAction, VmmActionError, VmmController, VmmData};
use vmm::resources::VmResources;
use vmm::vmm_config;
use vmm::vmm_config::instance_info::InstanceInfo;

use super::FIRECRACKER_VERSION;

struct ApiAdapter {
    api_event_fd: EventFd,
    from_api: Receiver<ApiRequest>,
    to_api: Sender<ApiResponse>,
}

impl ApiAdapter {
    pub fn new(
        api_event_fd: EventFd,
        from_api: Receiver<ApiRequest>,
        to_api: Sender<ApiResponse>,
    ) -> Self {
        ApiAdapter {
            api_event_fd,
            from_api,
            to_api,
        }
    }

    /// Builds and starts a microVM. It either uses a config json or receives API requests to
    /// get the microVM configuration.
    ///
    /// Returns a running `Vmm` object.
    pub fn build_microvm_from_requests(
        &self,
        seccomp_filter: BpfProgram,
        // FIXME: epoll context can be polluted by failing boot attempts
        epoll_context: &mut vmm::EpollContext,
    ) -> (VmResources, vmm::Vmm) {
        let mut vm_resources = VmResources::default();
        // Configure and start microVM through successive API calls.
        // Iterate through API calls to configure microVm.
        // The loop breaks when a microVM is successfully started, and returns a running Vmm.
        let mut built_vmm = None;
        while built_vmm.is_none() {
            match self.from_api.recv() {
                Ok(vmm_request) => {
                    // Also consume the API event. This is safe since communication
                    // between this thread and the API thread is synchronous.
                    let _ = self.api_event_fd.read().map_err(|e| {
                        error!("VMM: Failed to read the API event_fd: {}", e);
                        std::process::exit(i32::from(vmm::FC_EXIT_CODE_GENERIC_ERROR));
                    });

                    let (response, maybe_vmm) = self.handle_preboot_request(
                        *vmm_request,
                        &mut vm_resources,
                        &seccomp_filter,
                        epoll_context,
                    );

                    // Send back the result.
                    self.to_api
                        .send(response)
                        .map_err(|_| ())
                        .expect("one-shot channel closed");
                    built_vmm = maybe_vmm;
                }
                Err(RecvError) => {
                    panic!("The channel's sending half was disconnected. Cannot receive data.");
                }
            };
        }
        // Safe to unwrap because previous loop cannot end on None.
        (vm_resources, built_vmm.unwrap())
    }

    /// Handles the incoming request and provides a response for it.
    /// Returns a built/running `Vmm` after handling a successful `StartMicroVm` request.
    fn handle_preboot_request(
        &self,
        action_request: VmmAction,
        vm_resources: &mut VmResources,
        seccomp_filter: BpfProgramRef,
        epoll_context: &mut vmm::EpollContext,
    ) -> (ApiResponse, Option<vmm::Vmm>) {
        use vmm::controller::VmmAction::*;

        let mut maybe_vmm = None;
        let response = match action_request {
            /////////////////////////////////////////
            // Supported operations allowed pre-boot.
            ConfigureBootSource(boot_source_body) => vm_resources
                .set_boot_source(boot_source_body)
                .map(|_| VmmData::Empty)
                .map_err(|e| VmmActionError::BootSource(ErrorKind::User, e)),
            ConfigureLogger(logger_description) => {
                vmm_config::logger::init_logger(logger_description, FIRECRACKER_VERSION.to_string())
                    .map(|_| VmmData::Empty)
                    .map_err(|e| VmmActionError::Logger(ErrorKind::User, e))
            }
            GetVmConfiguration => Ok(VmmData::MachineConfiguration(
                vm_resources.vm_config().clone(),
            )),
            InsertBlockDevice(block_device_config) => vm_resources
                .set_block_device(block_device_config)
                .map(|_| VmmData::Empty)
                .map_err(|e| e.into()),
            InsertNetworkDevice(netif_body) => vm_resources
                .set_net_device(netif_body)
                .map(|_| VmmData::Empty)
                .map_err(|e| e.into()),
            SetVsockDevice(vsock_cfg) => {
                vm_resources.set_vsock_device(vsock_cfg);
                Ok(VmmData::Empty)
            }
            SetVmConfiguration(machine_config_body) => vm_resources
                .set_vm_config(machine_config_body)
                .map(|_| VmmData::Empty)
                .map_err(|e| e.into()),
            UpdateBlockDevicePath(drive_id, path_on_host) => vm_resources
                .update_block_device_path(drive_id, path_on_host)
                .map(|_| VmmData::Empty)
                .map_err(|e| e.into()),
            UpdateNetworkInterface(netif_update) => vm_resources
                .update_net_rate_limiters(netif_update)
                .map(|_| VmmData::Empty)
                .map_err(|e| e.into()),
            StartMicroVm => {
                vmm::builder::build_microvm(&vm_resources, epoll_context, seccomp_filter).map(
                    |vmm| {
                        maybe_vmm = Some(vmm);
                        VmmData::Empty
                    },
                )
            }

            ///////////////////////////////////
            // Operations not allowed pre-boot.
            FlushMetrics => Err(VmmActionError::Logger(
                ErrorKind::User,
                vmm_config::logger::LoggerConfigError::FlushMetrics(
                    "Cannot flush metrics before starting microVM.".to_string(),
                ),
            )),
            SendCtrlAltDel => Err(VmmActionError::OperationNotSupportedPreBoot),
        };

        (Box::new(response), maybe_vmm)
    }
}

impl vmm::controller::ControlEventHandler for ApiAdapter {
    /// Handles the control event received at microVM runtime.
    /// Receives and runs the Vmm action and sends back a response.
    /// Provides program exit codes on errors.
    fn handle_control_event(&self, controller: &mut VmmController) -> Result<(), u8> {
        use vmm::controller::VmmAction::*;

        self.api_event_fd.read().map_err(|e| {
            error!("VMM: Failed to read the API event_fd: {}", e);
            vmm::FC_EXIT_CODE_GENERIC_ERROR
        })?;

        match self.from_api.try_recv() {
            Ok(vmm_request) => {
                let action_request = *vmm_request;
                let response = match action_request {
                    ///////////////////////////////////
                    // Supported operations allowed post-boot.
                    FlushMetrics => controller.flush_metrics().map(|_| VmmData::Empty),
                    GetVmConfiguration => Ok(VmmData::MachineConfiguration(
                        controller.vm_config().clone(),
                    )),
                    #[cfg(target_arch = "x86_64")]
                    SendCtrlAltDel => controller.send_ctrl_alt_del().map(|_| VmmData::Empty),
                    UpdateBlockDevicePath(drive_id, path_on_host) => controller
                        .update_block_device_path(drive_id, path_on_host)
                        .map(|_| VmmData::Empty),
                    UpdateNetworkInterface(netif_update) => controller
                        .update_net_rate_limiters(netif_update)
                        .map(|_| VmmData::Empty),

                    ///////////////////////////////////
                    // Operations not allowed post-boot.
                    ConfigureBootSource(_) => Err(VmmActionError::BootSource(
                        ErrorKind::User,
                        vmm_config::boot_source::BootSourceConfigError::UpdateNotAllowedPostBoot,
                    )),
                    ConfigureLogger(_) => Err(VmmActionError::Logger(
                        ErrorKind::User,
                        vmm_config::logger::LoggerConfigError::InitializationFailure(
                            "Cannot initialize logger after boot.".to_string(),
                        ),
                    )),
                    InsertBlockDevice(_) => {
                        Err(vmm_config::drive::DriveError::UpdateNotAllowedPostBoot.into())
                    }
                    InsertNetworkDevice(_) => {
                        Err(vmm_config::net::NetworkInterfaceError::UpdateNotAllowedPostBoot.into())
                    }
                    SetVsockDevice(_) => Err(VmmActionError::VsockConfig(
                        ErrorKind::User,
                        vmm_config::vsock::VsockError::UpdateNotAllowedPostBoot,
                    )),
                    SetVmConfiguration(_) => Err(
                        vmm_config::machine_config::VmConfigError::UpdateNotAllowedPostBoot.into(),
                    ),

                    StartMicroVm => {
                        Err(vmm::builder::StartMicrovmError::MicroVMAlreadyRunning.into())
                    }
                };
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

    let api_handler = ApiAdapter::new(api_event_fd, from_api, to_api);

    // Configure, build and start the microVM.
    let (vm_resources, vmm) = match config_json {
        Some(json) => super::build_microvm_from_json(seccomp_filter, json, &mut epoll_context),
        None => api_handler.build_microvm_from_requests(seccomp_filter, &mut epoll_context),
    };

    // Update the api shared instance info.
    api_shared_info.write().unwrap().started = true;

    let vm_controller: VmmController = VmmController::new(epoll_context, vm_resources, vmm);
    vm_controller.run(&api_handler);
}
