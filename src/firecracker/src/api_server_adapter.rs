// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, RecvError, Sender, TryRecvError};
use std::sync::{Arc, RwLock};
use std::thread;

use api_server::{ApiServer, VmmRequest, VmmResponse};
use mmds::MMDS;
use utils::eventfd::EventFd;
use vmm::controller::VmmController;
use vmm::resources::VmResources;
use vmm::vmm_config;
use vmm::vmm_config::instance_info::InstanceInfo;
use vmm::EventLoopExitReason;

pub fn run_with_api(
    seccomp_level: u32,
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
            .bind_and_run(bind_path, start_time_us, start_time_cpu_us, seccomp_level)
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

    // The driving epoll engine.
    let mut epoll_context = vmm::EpollContext::new().expect("Cannot create the epoll context.");

    epoll_context
        .add_epollin_event(&api_event_fd, vmm::EpollDispatch::VmmActionRequest)
        .expect("Cannot add vmm control_fd to epoll.");

    // Configure, build and start the microVM.
    let (vm_resources, vmm) = match config_json {
        Some(json) => super::build_microvm_from_json(seccomp_level, json, &mut epoll_context),
        None => build_microvm_from_api(
            &api_event_fd,
            &from_api,
            &to_api,
            seccomp_level,
            &mut epoll_context,
        ),
    };

    api_shared_info.write().unwrap().started = true;

    let mut vm_controller: VmmController = VmmController::new(epoll_context, vm_resources, vmm);

    let exit_code = loop {
        match vm_controller.run_event_loop() {
            Err(e) => {
                error!("Abruptly exited VMM control loop: {:?}", e);
                break vmm::FC_EXIT_CODE_GENERIC_ERROR;
            }
            Ok(exit_reason) => match exit_reason {
                EventLoopExitReason::Break => {
                    info!("Gracefully terminated VMM control loop");
                    break vmm::FC_EXIT_CODE_OK;
                }
                EventLoopExitReason::ControlAction => {
                    if let Err(exit_code) =
                        vmm_control_event(&mut vm_controller, &api_event_fd, &from_api, &to_api)
                    {
                        break exit_code;
                    }
                }
            },
        };
    };

    vm_controller.stop(i32::from(exit_code));
}

/// Builds and starts a microVM. It either uses a config json or receives API requests to
/// get the microVM configuration.
///
/// Returns a running `Vmm` object.
fn build_microvm_from_api(
    api_event_fd: &EventFd,
    from_api: &Receiver<VmmRequest>,
    to_api: &Sender<VmmResponse>,
    seccomp_level: u32,
    // FIXME: epoll context can be polluted by failing boot attempts
    epoll_context: &mut vmm::EpollContext,
) -> (VmResources, vmm::Vmm) {
    use vmm::{ErrorKind, VmmActionError};

    let mut vm_resources = VmResources::default();
    // Configure and start microVM through successive API calls.
    // Iterate through API calls to configure microVm.
    // The loop breaks when a microVM is successfully started, and returns a running Vmm.
    let vmm = loop {
        let mut built_vmm = None;
        match from_api.recv() {
            Ok(vmm_request) => {
                use api_server::VmmAction::*;
                let action_request = *vmm_request;

                // Also consume the API event. This is safe since communication
                // between this thread and the API thread is synchronous.
                let _ = api_event_fd.read().map_err(|e| {
                    error!("VMM: Failed to read the API event_fd: {}", e);
                    std::process::exit(i32::from(vmm::FC_EXIT_CODE_GENERIC_ERROR));
                });

                let response = match action_request {
                    /////////////////////////////////////////
                    // Supported operations allowed pre-boot.
                    ConfigureBootSource(boot_source_body) => vm_resources
                        .set_boot_source(boot_source_body)
                        .map(|_| api_server::VmmData::Empty)
                        .map_err(|e| VmmActionError::BootSource(ErrorKind::User, e)),
                    ConfigureLogger(logger_description) => vmm_config::logger::init_logger(
                        logger_description,
                        crate_version!().to_string(),
                    )
                    .map(|_| api_server::VmmData::Empty)
                    .map_err(|e| VmmActionError::Logger(ErrorKind::User, e)),
                    GetVmConfiguration => Ok(api_server::VmmData::MachineConfiguration(
                        vm_resources.vm_config().clone(),
                    )),
                    InsertBlockDevice(block_device_config) => vm_resources
                        .set_block_device(block_device_config)
                        .map(|_| api_server::VmmData::Empty)
                        .map_err(|e| e.into()),
                    InsertNetworkDevice(netif_body) => vm_resources
                        .set_net_device(netif_body)
                        .map(|_| api_server::VmmData::Empty)
                        .map_err(|e| e.into()),
                    SetVsockDevice(vsock_cfg) => {
                        vm_resources.set_vsock_device(vsock_cfg);
                        Ok(api_server::VmmData::Empty)
                    }
                    SetVmConfiguration(machine_config_body) => vm_resources
                        .set_vm_config(machine_config_body)
                        .map(|_| api_server::VmmData::Empty)
                        .map_err(|e| e.into()),
                    UpdateBlockDevicePath(drive_id, path_on_host) => vm_resources
                        .update_block_device_path(drive_id, path_on_host)
                        .map(|_| api_server::VmmData::Empty)
                        .map_err(|e| e.into()),
                    UpdateNetworkInterface(netif_update) => vm_resources
                        .update_net_rate_limiters(netif_update)
                        .map(|_| api_server::VmmData::Empty)
                        .map_err(|e| e.into()),
                    StartMicroVm => {
                        vmm::builder::build_microvm(&vm_resources, epoll_context, seccomp_level)
                            .map(|vmm| {
                                built_vmm = Some(vmm);
                                api_server::VmmData::Empty
                            })
                    }

                    ///////////////////////////////////
                    // Operations not allowed pre-boot.
                    FlushMetrics => Err(VmmActionError::Logger(
                        ErrorKind::User,
                        vmm_config::logger::LoggerConfigError::FlushMetrics(
                            "Cannot flush metrics before starting microVM.".to_string(),
                        ),
                    )),
                    RescanBlockDevice(_) => {
                        Err(vmm_config::drive::DriveError::OperationNotAllowedPreBoot.into())
                    }
                    SendCtrlAltDel => Err(vmm::error::VmmActionError::OperationNotSupportedPreBoot),
                };

                // Send back the result.
                to_api
                    .send(Box::new(response))
                    .map_err(|_| ())
                    .expect("one-shot channel closed");
                // If microVM was successfully started, return the Vmm.
                if let Some(vmm) = built_vmm {
                    break vmm;
                }
            }
            Err(RecvError) => {
                panic!("The channel's sending half was disconnected. Cannot receive data.");
            }
        };
    };
    (vm_resources, vmm)
}

/// Handles the control event.
/// Receives and runs the Vmm action and sends back a response.
/// Provides program exit codes on errors.
fn vmm_control_event(
    controller: &mut VmmController,
    api_event_fd: &EventFd,
    from_api: &Receiver<VmmRequest>,
    to_api: &Sender<VmmResponse>,
) -> Result<(), u8> {
    use vmm::{ErrorKind, VmmActionError};

    api_event_fd.read().map_err(|e| {
        error!("VMM: Failed to read the API event_fd: {}", e);
        vmm::FC_EXIT_CODE_GENERIC_ERROR
    })?;

    match from_api.try_recv() {
        Ok(vmm_request) => {
            use api_server::VmmAction::*;
            let action_request = *vmm_request;
            let response = match action_request {
                ///////////////////////////////////
                // Supported operations allowed post-boot.
                FlushMetrics => controller
                    .flush_metrics()
                    .map(|_| api_server::VmmData::Empty),
                GetVmConfiguration => Ok(api_server::VmmData::MachineConfiguration(
                    controller.vm_config().clone(),
                )),
                RescanBlockDevice(drive_id) => controller
                    .rescan_block_device(&drive_id)
                    .map(|_| api_server::VmmData::Empty),
                #[cfg(target_arch = "x86_64")]
                SendCtrlAltDel => controller
                    .send_ctrl_alt_del()
                    .map(|_| api_server::VmmData::Empty),
                UpdateBlockDevicePath(drive_id, path_on_host) => controller
                    .update_block_device_path(drive_id, path_on_host)
                    .map(|_| api_server::VmmData::Empty),
                UpdateNetworkInterface(netif_update) => controller
                    .update_net_rate_limiters(netif_update)
                    .map(|_| api_server::VmmData::Empty),

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
                SetVmConfiguration(_) => {
                    Err(vmm_config::machine_config::VmConfigError::UpdateNotAllowedPostBoot.into())
                }

                StartMicroVm => Err(vmm::error::StartMicrovmError::MicroVMAlreadyRunning.into()),
            };
            // Send back the result.
            to_api
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
