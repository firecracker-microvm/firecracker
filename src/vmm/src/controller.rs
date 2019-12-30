// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::path::PathBuf;
use std::result;

use super::{EpollContext, EventLoopExitReason, Vmm};

use arch::DeviceType;
use device_manager::mmio::MMIO_CFG_SPACE_OFF;
use devices::virtio::{self, TYPE_BLOCK, TYPE_NET};
use error::Result;
use resources::VmResources;
use rpc_api_adapters::{ErrorKind, VmmActionError};
use vmm_config;
use vmm_config::drive::DriveError;
use vmm_config::logger::LoggerConfigError;
use vmm_config::machine_config::VmConfig;
use vmm_config::net::{NetworkInterfaceError, NetworkInterfaceUpdateConfig};

/// Shorthand result type for external VMM commands.
pub type ActionResult = std::result::Result<(), VmmActionError>;

/// Enables runtime configuration of a Firecracker VMM.
pub struct VmmController {
    epoll_context: EpollContext,
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
        self.vmm.write_metrics().map_err(|e| {
            VmmActionError::Logger(
                ErrorKind::Internal,
                LoggerConfigError::FlushMetrics(e.to_string()),
            )
        })
    }

    /// Injects CTRL+ALT+DEL keystroke combo to the inner Vmm (if present).
    #[cfg(target_arch = "x86_64")]
    pub fn send_ctrl_alt_del(&mut self) -> ActionResult {
        self.vmm
            .send_ctrl_alt_del()
            .map_err(|e| VmmActionError::SendCtrlAltDel(ErrorKind::Internal, e))
    }

    /// Stops the inner Vmm and exits the process with the provided exit_code.
    pub fn stop(&mut self, exit_code: i32) {
        self.vmm.stop(exit_code)
    }

    /// Creates a new `VmmController`.
    pub fn new(epoll_context: EpollContext, vm_resources: VmResources, vmm: Vmm) -> Self {
        VmmController {
            epoll_context,
            vm_resources,
            vmm,
        }
    }

    /// Wait for and dispatch events. Will defer to the inner Vmm loop after it's started.
    pub fn run_event_loop(&mut self) -> Result<EventLoopExitReason> {
        self.vmm.run_event_loop(&mut self.epoll_context)
    }

    /// Triggers a rescan of the host file backing the emulated block device with id `drive_id`.
    pub fn rescan_block_device(&mut self, drive_id: &str) -> ActionResult {
        // Rescan can only happen after the guest is booted.
        for drive_config in self.vm_resources.block.config_list.iter() {
            if drive_config.drive_id != *drive_id {
                continue;
            }

            // Use seek() instead of stat() (std::fs::Metadata) to support block devices.
            let new_size = File::open(&drive_config.path_on_host)
                .and_then(|mut f| f.seek(SeekFrom::End(0)))
                .map_err(|_| DriveError::BlockDeviceUpdateFailed)?;
            if new_size % virtio::block::SECTOR_SIZE != 0 {
                warn!(
                    "Disk size {} is not a multiple of sector size {}; \
                     the remainder will not be visible to the guest.",
                    new_size,
                    virtio::block::SECTOR_SIZE
                );
            }

            return match self
                .vmm
                .get_bus_device(DeviceType::Virtio(TYPE_BLOCK), drive_id)
            {
                Some(device) => {
                    let data = devices::virtio::build_config_space(new_size);
                    let mut busdev = device
                        .lock()
                        .map_err(|_| VmmActionError::from(DriveError::BlockDeviceUpdateFailed))?;

                    busdev.write(MMIO_CFG_SPACE_OFF, &data[..]);
                    busdev.interrupt(devices::virtio::VIRTIO_MMIO_INT_CONFIG);

                    Ok(())
                }
                None => Err(VmmActionError::from(DriveError::BlockDeviceUpdateFailed)),
            };
        }

        Err(VmmActionError::from(DriveError::InvalidBlockDeviceID))
    }

    fn update_drive_handler(
        &mut self,
        drive_id: &str,
        disk_image: File,
    ) -> result::Result<(), DriveError> {
        let handler = self
            .epoll_context
            .get_device_handler_by_device_id::<virtio::BlockEpollHandler>(TYPE_BLOCK, drive_id)
            .map_err(|_| DriveError::EpollHandlerNotFound)?;

        handler
            .update_disk_image(disk_image)
            .map_err(|_| DriveError::BlockDeviceUpdateFailed)
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
            .ok_or(DriveError::InvalidBlockDeviceID)?;

        let file_path = PathBuf::from(path_on_host);
        // Try to open the file specified by path_on_host using the permissions of the block_device.
        let disk_file = OpenOptions::new()
            .read(true)
            .write(!self.vm_resources.block.config_list[block_device_index].is_read_only())
            .open(&file_path)
            .map_err(DriveError::CannotOpenBlockDevice)?;

        // Update the path of the block device with the specified path_on_host.
        self.vm_resources.block.config_list[block_device_index].path_on_host = file_path;

        // When the microvm is running, we also need to update the drive handler and send a
        // rescan command to the drive.
        self.update_drive_handler(&drive_id, disk_file)?;
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
            .map_err(NetworkInterfaceError::EpollHandlerNotFound)?;

        macro_rules! get_handler_arg {
            ($rate_limiter: ident, $metric: ident) => {{
                new_cfg
                    .$rate_limiter
                    .map(|rl| {
                        rl.$metric
                            .map(vmm_config::TokenBucketConfig::into_token_bucket)
                    })
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

/*
#[cfg(test)]
mod tests {
    extern crate tempfile;

    use super::*;

    use self::tempfile::NamedTempFile;

    fn create_controller_object() -> VmmController {
        let shared_info = Arc::new(RwLock::new(InstanceInfo {
            state: InstanceState::Uninitialized,
            id: "TEST_ID".to_string(),
            vmm_version: "1.0".to_string(),
        }));

        let mut ctrl = VmmController::new(
            shared_info,
            &EventFd::new().expect("Cannot create eventFD"),
            seccomp::SECCOMP_LEVEL_NONE,
        )
        .expect("Cannot Create VMM controller");

        ctrl.set_default_kernel_config(None);
        ctrl.guest_memory = Some(
            GuestMemory::new(&[(GuestAddress(0), 0x10000)])
                .expect("could not create GuestMemory object"),
        );
        ctrl
    }

    impl VmmController {
        fn kernel_cmdline(&self) -> &kernel_cmdline::Cmdline {
            &self
                .kernel_config
                .as_ref()
                .expect("Missing kernel cmdline")
                .cmdline
        }

        fn set_default_kernel_config(&mut self, cust_kernel_path: Option<PathBuf>) {
            let kernel_temp_file =
                NamedTempFile::new().expect("Failed to create temporary kernel file.");
            let kernel_path = match cust_kernel_path {
                Some(kernel_path) => kernel_path,
                None => kernel_temp_file.path().to_path_buf(),
            };
            let kernel_file = File::open(kernel_path).expect("Cannot open kernel file");
            let mut cmdline = kernel_cmdline::Cmdline::new(arch::CMDLINE_MAX_SIZE);
            assert!(cmdline.insert_str(DEFAULT_KERNEL_CMDLINE).is_ok());
            let kernel_cfg = KernelConfig {
                cmdline,
                kernel_file,
            };
            self.set_kernel_config(kernel_cfg);
        }

        fn set_instance_initialized(&mut self) {
            self.instance_initialized = true;
        }
    }

    #[test]
    fn test_insert_block_device() {
        let mut ctrl = create_controller_object();
        let f = NamedTempFile::new().unwrap();
        // Test that creating a new block device returns the correct output.
        let root_block_device = BlockDeviceConfig {
            drive_id: String::from("root"),
            path_on_host: f.path().to_path_buf(),
            is_root_device: true,
            partuuid: None,
            is_read_only: false,
            rate_limiter: None,
        };
        assert!(ctrl.insert_block_device(root_block_device.clone()).is_ok());
        assert!(ctrl
            .vm_resources
            .block
            .config_list
            .contains(&root_block_device));

        // Test that updating a block device returns the correct output.
        let root_block_device = BlockDeviceConfig {
            drive_id: String::from("root"),
            path_on_host: f.path().to_path_buf(),
            is_root_device: true,
            partuuid: None,
            is_read_only: true,
            rate_limiter: None,
        };
        assert!(ctrl.insert_block_device(root_block_device.clone()).is_ok());
        assert!(ctrl
            .vm_resources
            .block
            .config_list
            .contains(&root_block_device));

        // Test insert second drive with the same path fails.
        let root_block_device = BlockDeviceConfig {
            drive_id: String::from("dummy_dev"),
            path_on_host: f.path().to_path_buf(),
            is_root_device: false,
            partuuid: None,
            is_read_only: true,
            rate_limiter: None,
        };
        assert!(ctrl.insert_block_device(root_block_device.clone()).is_err());

        // Test inserting a second drive is ok.
        let f = NamedTempFile::new().unwrap();
        // Test that creating a new block device returns the correct output.
        let non_root = BlockDeviceConfig {
            drive_id: String::from("non_root"),
            path_on_host: f.path().to_path_buf(),
            is_root_device: false,
            partuuid: None,
            is_read_only: false,
            rate_limiter: None,
        };
        assert!(ctrl.insert_block_device(non_root).is_ok());

        // Test that making the second device root fails (it would result in 2 root block
        // devices.
        let non_root = BlockDeviceConfig {
            drive_id: String::from("non_root"),
            path_on_host: f.path().to_path_buf(),
            is_root_device: true,
            partuuid: None,
            is_read_only: false,
            rate_limiter: None,
        };
        assert!(ctrl.insert_block_device(non_root).is_err());

        // Test update after boot.
        ctrl.set_instance_initialized();
        let root_block_device = BlockDeviceConfig {
            drive_id: String::from("root"),
            path_on_host: f.path().to_path_buf(),
            is_root_device: false,
            partuuid: None,
            is_read_only: true,
            rate_limiter: None,
        };
        assert!(ctrl.insert_block_device(root_block_device).is_err())
    }

    #[test]
    fn test_append_block_devices() {
        let block_file = NamedTempFile::new().unwrap();

        {
            // Use Case 1: Root Block Device is not specified through PARTUUID.
            let mut ctrl = create_controller_object();
            let mut device_vec = Vec::new();

            let root_block_device = BlockDeviceConfig {
                drive_id: String::from("root"),
                path_on_host: block_file.path().to_path_buf(),
                is_root_device: true,
                partuuid: None,
                is_read_only: false,
                rate_limiter: None,
            };

            // Test that creating a new block device returns the correct output.
            assert!(ctrl.insert_block_device(root_block_device.clone()).is_ok());
            assert!(ctrl.attach_block_devices(&mut device_vec).is_ok());
            assert!(ctrl.kernel_cmdline().as_str().contains("root=/dev/vda rw"));
        }

        {
            // Use Case 2: Root Block Device is specified through PARTUUID.
            let mut ctrl = create_controller_object();
            let mut device_vec = Vec::new();

            let root_block_device = BlockDeviceConfig {
                drive_id: String::from("root"),
                path_on_host: block_file.path().to_path_buf(),
                is_root_device: true,
                partuuid: Some("0eaa91a0-01".to_string()),
                is_read_only: false,
                rate_limiter: None,
            };

            // Test that creating a new block device returns the correct output.
            assert!(ctrl.insert_block_device(root_block_device.clone()).is_ok());
            assert!(ctrl.attach_block_devices(&mut device_vec).is_ok());
            assert!(ctrl
                .kernel_cmdline()
                .as_str()
                .contains("root=PARTUUID=0eaa91a0-01 rw"));
        }

        {
            // Use Case 3: Root Block Device is not added at all.
            let mut ctrl = create_controller_object();
            let mut device_vec = Vec::new();

            let non_root_block_device = BlockDeviceConfig {
                drive_id: String::from("not_root"),
                path_on_host: block_file.path().to_path_buf(),
                is_root_device: false,
                partuuid: Some("0eaa91a0-01".to_string()),
                is_read_only: false,
                rate_limiter: None,
            };

            // Test that creating a new block device returns the correct output.
            assert!(ctrl
                .insert_block_device(non_root_block_device.clone())
                .is_ok());

            assert!(ctrl.attach_block_devices(&mut device_vec).is_ok());
            // Test that kernel commandline does not contain either /dev/vda or PARTUUID.
            assert!(!ctrl.kernel_cmdline().as_str().contains("root=PARTUUID="));
            assert!(!ctrl.kernel_cmdline().as_str().contains("root=/dev/vda"));

            // Test partial update of block devices.
            let new_block = NamedTempFile::new().unwrap();
            let path = String::from(new_block.path().to_path_buf().to_str().unwrap());
            assert!(ctrl
                .update_block_device_path("not_root".to_string(), path)
                .is_ok());

            // Test partial update of block device fails due to invalid file.
            assert!(ctrl
                .update_block_device_path("not_root".to_string(), String::from("dummy_path"))
                .is_err());

//            vmm.set_instance_state(InstanceState::Running);
//            // Test updating the block device path, after instance start.
//            let path = String::from(new_block.path().to_path_buf().to_str().unwrap());
//            match vmm.update_block_device_path("not_root".to_string(), path) {
//                Err(VmmActionError::DriveConfig(ErrorKind::User, DriveError::EpollHandlerNotFound)) => {}
//                Err(e) => panic!("Unexpected error: {:?}", e),
//                Ok(_) => {
//                    panic!("Updating block device path shouldn't be possible without an epoll handler.")
//                }
//            }
        }
    }
}
*/
