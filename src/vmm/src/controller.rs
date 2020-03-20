// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::path::PathBuf;
use std::result;
use std::sync::{Arc, Mutex};

use arch::DeviceType;
use device_manager::mmio::MMIO_CFG_SPACE_OFF;
use devices::virtio::{Block, MmioTransport, Net, TYPE_BLOCK, TYPE_NET};
use logger::METRICS;
use resources::VmResources;
use rpc_interface::VmmActionError;
use vmm_config;
use vmm_config::drive::DriveError;
use vmm_config::machine_config::VmConfig;
use vmm_config::net::{NetworkInterfaceError, NetworkInterfaceUpdateConfig};
use Vmm;

/// Shorthand result type for external VMM commands.
pub type ActionResult = std::result::Result<(), VmmActionError>;

/// Enables runtime configuration of a Firecracker VMM.
pub struct VmmController {
    vm_resources: VmResources,
    vmm: Arc<Mutex<Vmm>>,
}

impl VmmController {
    /// Returns the VmConfig.
    pub fn vm_config(&self) -> &VmConfig {
        self.vm_resources.vm_config()
    }

    /// Write the metrics on user demand (flush). We use the word `flush` here to highlight the fact
    /// that the metrics will be written immediately.
    /// Defer to inner Vmm. We'll move to a variant where the Vmm simply exposes functionality like
    /// getting the dirty pages, and then we'll have the metrics flushing logic entirely on the outside.
    pub fn flush_metrics(&mut self) -> ActionResult {
        // FIXME: we're losing the bool saying whether metrics were actually written.
        METRICS
            .write()
            .map(|_| ())
            .map_err(super::Error::Metrics)
            .map_err(VmmActionError::InternalVmm)
    }

    /// Injects CTRL+ALT+DEL keystroke combo to the inner Vmm (if present).
    #[cfg(target_arch = "x86_64")]
    pub fn send_ctrl_alt_del(&mut self) -> ActionResult {
        self.vmm
            .lock()
            .unwrap()
            .send_ctrl_alt_del()
            .map_err(VmmActionError::InternalVmm)
    }

    /// Creates a new `VmmController`.
    pub fn new(vm_resources: VmResources, vmm: Arc<Mutex<Vmm>>) -> Self {
        VmmController { vm_resources, vmm }
    }

    fn update_drive_disk_image(
        &mut self,
        drive_id: &str,
        mut disk_image: File,
    ) -> result::Result<(), DriveError> {
        if let Some(busdev) = self
            .vmm
            .lock()
            .unwrap()
            .get_bus_device(DeviceType::Virtio(TYPE_BLOCK), drive_id)
        {
            // Use seek() instead of stat() (std::fs::Metadata) to support block devices.
            let new_size = disk_image
                .seek(SeekFrom::End(0))
                .map_err(|_| DriveError::BlockDeviceUpdateFailed)?;
            // Return cursor to the start of the file.
            disk_image
                .seek(SeekFrom::Start(0))
                .map_err(|_| DriveError::BlockDeviceUpdateFailed)?;

            // Call the update_disk_image() handler on Block.
            busdev
                .lock()
                .expect("Poisoned device lock")
                .as_any()
                // Only MmioTransport implements BusDevice at this point.
                .downcast_ref::<MmioTransport>()
                .expect("Unexpected BusDevice type")
                .device()
                // Here we get a new clone of Arc<Mutex<dyn VirtioDevice>>.
                .lock()
                .expect("Poisoned device lock")
                .as_mut_any()
                // We know this is a block device from the HashMap.
                .downcast_mut::<Block>()
                .expect("Unexpected VirtioDevice type")
                // Now we have a Block, so call its update handler.
                .update_disk_image(disk_image)
                .map_err(|_| DriveError::BlockDeviceUpdateFailed)?;

            // Update the virtio config space and kick the driver to pick up the changes.
            let new_cfg = devices::virtio::block::device::build_config_space(new_size);
            let mut locked_dev = busdev.lock().expect("Poisoned device lock");
            locked_dev.write(MMIO_CFG_SPACE_OFF, &new_cfg[..]);
            locked_dev
                .interrupt(devices::virtio::VIRTIO_MMIO_INT_CONFIG)
                .map_err(|_| DriveError::BlockDeviceUpdateFailed)?;

            Ok(())
        } else {
            Err(DriveError::InvalidBlockDeviceID)
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
            .write(!self.vm_resources.block.config_list[block_device_index].is_read_only)
            .open(&file_path)
            .map_err(DriveError::CannotOpenBlockDevice)
            .map_err(VmmActionError::DriveConfig)?;

        // Update the path of the block device with the specified path_on_host.
        self.vm_resources.block.config_list[block_device_index].path_on_host = file_path;

        // We need to update the disk image on the device and its virtio configuration.
        self.update_drive_disk_image(&drive_id, disk_file)
            .map_err(VmmActionError::DriveConfig)?;
        Ok(())
    }

    /// Updates configuration for an emulated net device as described in `new_cfg`.
    pub fn update_net_rate_limiters(
        &mut self,
        new_cfg: NetworkInterfaceUpdateConfig,
    ) -> ActionResult {
        if let Some(busdev) = self
            .vmm
            .lock()
            .unwrap()
            .get_bus_device(DeviceType::Virtio(TYPE_NET), &new_cfg.iface_id)
        {
            let virtio_device = busdev
                .lock()
                .expect("Poisoned device lock")
                .as_any()
                .downcast_ref::<MmioTransport>()
                // Only MmioTransport implements BusDevice at this point.
                .expect("Unexpected BusDevice type")
                .device();

            macro_rules! get_handler_arg {
                ($rate_limiter: ident, $metric: ident) => {{
                    new_cfg
                        .$rate_limiter
                        .map(|rl| rl.$metric.map(vmm_config::TokenBucketConfig::into))
                        .unwrap_or(None)
                }};
            }

            virtio_device
                .lock()
                .expect("Poisoned device lock")
                .as_mut_any()
                .downcast_mut::<Net>()
                .unwrap()
                .patch_rate_limiters(
                    get_handler_arg!(rx_rate_limiter, bandwidth),
                    get_handler_arg!(rx_rate_limiter, ops),
                    get_handler_arg!(tx_rate_limiter, bandwidth),
                    get_handler_arg!(tx_rate_limiter, ops),
                );
        } else {
            return Err(VmmActionError::NetworkConfig(
                NetworkInterfaceError::DeviceIdNotFound,
            ));
        }

        Ok(())
    }
}
