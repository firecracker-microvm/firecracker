// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::path::PathBuf;
use std::result;

use super::{EpollContext, EventLoopExitReason, Vmm};

use super::Result;
use arch::DeviceType;
use device_manager::mmio::MMIO_CFG_SPACE_OFF;
use devices::virtio::{self, TYPE_BLOCK, TYPE_NET};
use polly::event_manager::EventManager;
use resources::VmResources;
use rpc_interface::VmmActionError;
use vmm_config;
use vmm_config::drive::DriveError;
use vmm_config::machine_config::VmConfig;
use vmm_config::net::NetworkInterfaceUpdateConfig;

/// Shorthand result type for external VMM commands.
pub type ActionResult = std::result::Result<(), VmmActionError>;

/// Enables runtime configuration of a Firecracker VMM.
pub struct VmmController {
    epoll_context: EpollContext,
    event_manager: EventManager,
    vm_resources: VmResources,
    vmm: Vmm,
}

impl VmmController {
    /// Returns the VmConfig.
    pub fn vm_config(&self) -> &VmConfig {
        self.vm_resources.vm_config()
    }

    /// Flush metrics. Defer to inner Vmm. We'll move to a variant where the Vmm
    /// simply exposes functionality like getting the dirty pages, and then we'll have the
    /// metrics flushing logic entirely on the outside.
    pub fn flush_metrics(&mut self) -> ActionResult {
        self.vmm
            .write_metrics()
            .map_err(VmmActionError::InternalVmm)
    }

    /// Injects CTRL+ALT+DEL keystroke combo to the inner Vmm (if present).
    #[cfg(target_arch = "x86_64")]
    pub fn send_ctrl_alt_del(&mut self) -> ActionResult {
        self.vmm
            .send_ctrl_alt_del()
            .map_err(VmmActionError::InternalVmm)
    }

    /// Stops the inner Vmm and exits the process with the provided exit_code.
    pub fn stop(&mut self, exit_code: i32) {
        self.vmm.stop(exit_code)
    }

    /// Creates a new `VmmController`.
    pub fn new(
        epoll_context: EpollContext,
        event_manager: EventManager,
        vm_resources: VmResources,
        vmm: Vmm,
    ) -> Self {
        VmmController {
            epoll_context,
            event_manager,
            vm_resources,
            vmm,
        }
    }

    /// Wait for and dispatch events. Will defer to the inner Vmm loop after it's started.
    pub fn run_event_loop(&mut self) -> Result<EventLoopExitReason> {
        self.vmm
            .run_event_loop(&mut self.epoll_context, &mut self.event_manager)
    }

    /// Triggers a rescan of the host file backing the emulated block device with id `drive_id`.
    pub fn rescan_block_device(&mut self, drive_id: &str) -> ActionResult {
        for drive_config in self.vm_resources.block.config_list.iter() {
            if drive_config.drive_id != *drive_id {
                continue;
            }

            // Use seek() instead of stat() (std::fs::Metadata) to support block devices.
            let new_size = File::open(&drive_config.path_on_host)
                .and_then(|mut f| f.seek(SeekFrom::End(0)))
                .map_err(|_| DriveError::BlockDeviceUpdateFailed)
                .map_err(VmmActionError::DriveConfig)?;

            return match self
                .vmm
                .get_bus_device(DeviceType::Virtio(TYPE_BLOCK), drive_id)
            {
                Some(device) => {
                    let data = devices::virtio::build_config_space(new_size);
                    let mut busdev = device
                        .lock()
                        .map_err(|_| DriveError::BlockDeviceUpdateFailed)
                        .map_err(VmmActionError::DriveConfig)?;

                    busdev.write(MMIO_CFG_SPACE_OFF, &data[..]);
                    let _ = busdev.interrupt(devices::virtio::VIRTIO_MMIO_INT_CONFIG);

                    Ok(())
                }
                None => Err(VmmActionError::DriveConfig(
                    DriveError::BlockDeviceUpdateFailed,
                )),
            };
        }

        Err(VmmActionError::DriveConfig(
            DriveError::InvalidBlockDeviceID,
        ))
    }

    fn update_drive_handler(
        &mut self,
        drive_id: &str,
        disk_image: File,
    ) -> result::Result<(), DriveError> {
        if let Some(handler) = self.vmm.mmio_device_manager.get_block_device(drive_id) {
            handler
                .lock()
                .expect("Poisoned device lock")
                .update_disk_image(disk_image)
                .map_err(|_| DriveError::BlockDeviceUpdateFailed)
        } else {
            // TODO: Update this error after all devices have been ported.
            Err(DriveError::EpollHandlerNotFound)
        }
    }

    /// Updates the path of the host file backing the emulated block device with id `drive_id`.
    pub fn update_block_device_path(
        &mut self,
        drive_id: String,
        path_on_host: String,
    ) -> ActionResult {
        // Get the block device configuration specified by drive_id.
        let block_device_index = self
            .vm_resources
            .block
            .get_index_of_drive_id(&drive_id)
            .ok_or(VmmActionError::DriveConfig(
                DriveError::InvalidBlockDeviceID,
            ))?;

        let file_path = PathBuf::from(path_on_host);
        // Try to open the file specified by path_on_host using the permissions of the block_device.
        let disk_file = OpenOptions::new()
            .read(true)
            .write(!self.vm_resources.block.config_list[block_device_index].is_read_only())
            .open(&file_path)
            .map_err(DriveError::CannotOpenBlockDevice)
            .map_err(VmmActionError::DriveConfig)?;

        // Update the path of the block device with the specified path_on_host.
        self.vm_resources.block.config_list[block_device_index].path_on_host = file_path;

        // When the microvm is running, we also need to update the drive handler and send a
        // rescan command to the drive.
        self.update_drive_handler(&drive_id, disk_file)
            .map_err(VmmActionError::DriveConfig)?;
        self.rescan_block_device(&drive_id)?;
        Ok(())
    }

    /// Updates configuration for an emulated net device as described in `new_cfg`.
    pub fn update_net_rate_limiters(
        &mut self,
        new_cfg: NetworkInterfaceUpdateConfig,
    ) -> ActionResult {
        let handler = self
            .epoll_context
            .get_device_handler_by_device_id::<virtio::NetEpollHandler>(TYPE_NET, &new_cfg.iface_id)
            .map_err(VmmActionError::InternalVmm)?;

        macro_rules! get_handler_arg {
            ($rate_limiter: ident, $metric: ident) => {{
                new_cfg
                    .$rate_limiter
                    .map(|rl| rl.$metric.map(vmm_config::TokenBucketConfig::into))
                    .unwrap_or(None)
            }};
        }

        handler.patch_rate_limiters(
            get_handler_arg!(rx_rate_limiter, bandwidth),
            get_handler_arg!(rx_rate_limiter, ops),
            get_handler_arg!(tx_rate_limiter, bandwidth),
            get_handler_arg!(tx_rate_limiter, ops),
        );
        Ok(())
    }
}
