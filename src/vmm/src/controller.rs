// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
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
use vm_memory::{GuestMemory, GuestMemoryRegion, GuestRegionMmap};
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
                .lock()
                .unwrap()
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

    fn update_drive_disk_image(
        &mut self,
        drive_id: &str,
        disk_image: File,
    ) -> result::Result<(), DriveError> {
        if let Some(busdev) = self
            .vmm
            .lock()
            .unwrap()
            .get_bus_device(DeviceType::Virtio(TYPE_BLOCK), drive_id)
        {
            let virtio_device = busdev
                .lock()
                .expect("Poisoned device lock")
                .as_any()
                .downcast_ref::<MmioTransport>()
                // Only MmioTransport implements BusDevice at this point.
                .expect("Unexpected BusDevice type")
                .device();

            // This call wraps the temporary `virtio_device` inside a `MutexGuard`.
            let mut lock = virtio_device.lock().expect("Poisoned device lock");

            // Downcast the inner virtio_device to a Block.
            let block_device: &mut Block = lock
                .as_mut_any()
                .downcast_mut::<Block>()
                .expect("Unexpected Block type");

            block_device
                .update_disk_image(disk_image)
                .map_err(|_| DriveError::BlockDeviceUpdateFailed)
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
            .write(!self.vm_resources.block.config_list[block_device_index].is_read_only())
            .open(&file_path)
            .map_err(DriveError::CannotOpenBlockDevice)
            .map_err(VmmActionError::DriveConfig)?;

        // Update the path of the block device with the specified path_on_host.
        self.vm_resources.block.config_list[block_device_index].path_on_host = file_path;

        // When the microvm is running, we also need to update the disk image and send a
        // rescan command to the drive.
        self.update_drive_disk_image(&drive_id, disk_file)
            .map_err(VmmActionError::DriveConfig)?;
        self.rescan_block_device(&drive_id)?;
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

    /// Retrieves the KVM dirty bitmap for each of the guest's memory regions.
    pub fn get_dirty_bitmap(
        &self,
    ) -> std::result::Result<HashMap<usize, Vec<u64>>, VmmActionError> {
        let mut bitmap: HashMap<usize, Vec<u64>> = HashMap::new();
        let vmm_handle = self.vmm.lock().unwrap();
        vmm_handle.guest_memory.with_regions_mut(
            |slot: usize, region: &GuestRegionMmap| -> std::result::Result<(), VmmActionError> {
                let bitmap_region = vmm_handle
                    .vm
                    .fd()
                    .get_dirty_log(slot as u32, region.len() as usize)
                    .map_err(|e| VmmActionError::InternalVmm(super::Error::DirtyBitmap(e)))?;
                bitmap.insert(slot, bitmap_region);
                Ok(())
            },
        )?;
        Ok(bitmap)
    }
}

#[cfg(test)]
mod tests {
    extern crate kernel;

    use super::*;

    use arch::arch_memory_regions;
    #[cfg(target_arch = "x86_64")]
    use device_manager::legacy::PortIODeviceManager;
    use device_manager::mmio::MMIODeviceManager;
    #[cfg(target_arch = "x86_64")]
    use devices::legacy::Serial;
    use kernel::cmdline::Cmdline;
    use kvm_bindings::{kvm_userspace_memory_region, KVM_MEM_LOG_DIRTY_PAGES};
    use kvm_ioctls::{VcpuExit, VcpuFd, VmFd};
    use utils::eventfd::EventFd;
    use vm_memory::{Address, GuestAddress, GuestMemoryMmap};
    use vstate::{KvmContext, Vm};

    struct DeviceManagers {
        mmio_device_manager: MMIODeviceManager,
        #[cfg(target_arch = "x86_64")]
        pio_device_manager: PortIODeviceManager,
    }

    #[cfg(target_arch = "x86_64")]
    fn create_guest_workload() -> (Vec<u8>, GuestAddress) {
        // HLT instruction.
        (vec![0xf4u8], GuestAddress(0))
    }

    #[cfg(target_arch = "aarch64")]
    fn create_guest_workload() -> (Vec<u8>, GuestAddress) {
        (
            vec![
                0x01, 0x00, 0x00, 0x10, /* adr x1, <this address> */
                0x22, 0x10, 0x00, 0xb9, /* str w2, [x1, #16]; write to this page */
                0x02, 0x00, 0x00, 0xb9, /* str w2, [x0]; force MMIO exit */
                0x00, 0x00, 0x00,
                0x14, /* b <this address>; shouldn't get here, but if so loop forever */
            ],
            GuestAddress(arch::aarch64::layout::DRAM_MEM_START),
        )
    }

    fn create_device_managers() -> DeviceManagers {
        DeviceManagers {
            mmio_device_manager: MMIODeviceManager::new(
                &mut (arch::MMIO_MEM_START as u64),
                (arch::IRQ_BASE, arch::IRQ_MAX),
            ),
            #[cfg(target_arch = "x86_64")]
            pio_device_manager: PortIODeviceManager::new(
                Arc::new(Mutex::new(Serial::new_sink(
                    EventFd::new(libc::EFD_NONBLOCK).unwrap(),
                ))),
                EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            )
            .unwrap(),
        }
    }

    fn create_guest_memory(mem_size: usize, vm_fd: &VmFd) -> GuestMemoryMmap {
        let mem_regions = arch_memory_regions(mem_size);
        let guest_memory = GuestMemoryMmap::from_ranges(&mem_regions).unwrap();
        config_guest_memory(&guest_memory, false, vm_fd);
        guest_memory
    }

    fn config_guest_memory(guest_memory: &GuestMemoryMmap, track_dirty_pages: bool, vm_fd: &VmFd) {
        guest_memory
            .with_regions(|index, region| {
                // It's safe to unwrap because the guest address is valid.
                let host_addr = guest_memory.get_host_address(region.start_addr()).unwrap();
                let memory_region = kvm_userspace_memory_region {
                    slot: index as u32,
                    guest_phys_addr: region.start_addr().raw_value() as u64,
                    memory_size: region.len() as u64,
                    userspace_addr: host_addr as u64,
                    flags: if track_dirty_pages {
                        KVM_MEM_LOG_DIRTY_PAGES
                    } else {
                        0
                    },
                };
                unsafe { vm_fd.set_user_memory_region(memory_region) }
            })
            .unwrap();
    }

    impl Vmm {
        fn empty(guest_memory: GuestMemoryMmap, vm: Vm, device_managers: DeviceManagers) -> Self {
            Vmm {
                events_observer: None,
                guest_memory,
                kernel_cmdline: Cmdline::new(100),
                vcpus_handles: vec![],
                exit_evt: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
                vm,
                mmio_device_manager: device_managers.mmio_device_manager,
                #[cfg(target_arch = "x86_64")]
                pio_device_manager: device_managers.pio_device_manager,
            }
        }

        #[cfg(target_arch = "x86_64")]
        fn config_vcpu(&self, vcpu_fd: &mut VcpuFd, guest_addr: GuestAddress) {
            // x86_64 specific registry setup.
            let mut vcpu_sregs = vcpu_fd.get_sregs().unwrap();
            vcpu_sregs.cs.base = 0;
            vcpu_sregs.cs.selector = 0;
            vcpu_fd.set_sregs(&vcpu_sregs).unwrap();

            let mut vcpu_regs = vcpu_fd.get_regs().unwrap();
            // Set the Instruction Pointer to the guest address where we loaded the code.
            vcpu_regs.rip = guest_addr.0 as u64;
            vcpu_regs.rax = 2;
            vcpu_regs.rbx = 3;
            vcpu_regs.rflags = 2;
            vcpu_fd.set_regs(&vcpu_regs).unwrap();
        }

        #[cfg(target_arch = "aarch64")]
        fn config_vcpu(&self, vcpu_fd: &mut VcpuFd, guest_addr: GuestAddress) {
            // aarch64 specific registry setup.
            let mut kvi = kvm_bindings::kvm_vcpu_init::default();
            self.vm.fd().get_preferred_target(&mut kvi).unwrap();
            vcpu_fd.vcpu_init(&kvi).unwrap();

            let core_reg_base: u64 = 0x6030_0000_0010_0000;
            let mut mem_size = 0;
            self.guest_memory
                .with_regions_mut(|_, region| -> std::result::Result<(), std::io::Error> {
                    mem_size += region.len();
                    Ok(())
                })
                .unwrap();
            let mmio_addr: u64 = (guest_addr.0 + mem_size) as u64;
            vcpu_fd
                .set_one_reg(core_reg_base + 2 * 32, guest_addr.0 as u64)
                .unwrap(); // set PC
            vcpu_fd
                .set_one_reg(core_reg_base + 2 * 0, mmio_addr)
                .unwrap(); // set X0
        }

        fn write_code_to_guest_memory(&self) -> GuestAddress {
            let (asm_code, guest_addr) = create_guest_workload();
            let host_addr = self.guest_memory.get_host_address(guest_addr).unwrap();
            let code_slice: &mut [u8] =
                unsafe { std::slice::from_raw_parts_mut(host_addr as *mut u8, asm_code.len()) };
            code_slice.copy_from_slice(&asm_code);
            guest_addr
        }

        // Prepare a VM with 1 MB memory and 1 vCPU.
        // Dirty a page and run the VM.
        // Return after the first VM exit.
        fn setup_with_code_and_run(&mut self) {
            // Fill guest memory with an asm code snippet.
            let guest_addr = self.write_code_to_guest_memory();

            // Create a vCPU.
            let mut vcpu_fd = self.vm.fd().create_vcpu(0).unwrap();
            self.config_vcpu(&mut vcpu_fd, guest_addr);

            // Run the VM. It will trigger a vCPU exit.
            match vcpu_fd.run().unwrap() {
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                VcpuExit::Hlt => (),
                #[cfg(target_arch = "aarch64")]
                VcpuExit::MmioWrite(_, _) => (),
                exit_reason => panic!("unexpected exit reason: {:?}", exit_reason),
            }
        }
    }

    impl VmmController {
        fn setup_vmm_with_code_and_run(&mut self) {
            self.vmm.lock().unwrap().setup_with_code_and_run()
        }

        fn set_dirty_page_tracking(&self, track_dirty_pages: bool) {
            let vmm = self.vmm.lock().unwrap();
            config_guest_memory(vmm.guest_memory(), track_dirty_pages, vmm.vm.fd());
        }
    }

    #[test]
    fn test_dirty_bitmap() {
        let kvm = KvmContext::new().unwrap();
        let vm = Vm::new(kvm.fd()).unwrap();
        let device_managers = create_device_managers();
        let guest_memory = create_guest_memory(1 << 20, vm.fd());

        let vmm = Vmm::empty(guest_memory, vm, device_managers);

        let mut vmm_controller =
            VmmController::new(VmResources::default(), Arc::new(Mutex::new(vmm)));

        // Error case: dirty tracking off.
        assert_eq!(
            format!("{:?}", vmm_controller.get_dirty_bitmap().err()),
            "Some(InternalVmm(DirtyBitmap(Error(2))))"
        );

        // VM didn't run => empty bitmap.
        vmm_controller.set_dirty_page_tracking(true);
        let mut expected: HashMap<usize, Vec<u64>> = HashMap::new();
        expected.insert(0, vec![0u64; 4]);
        assert_eq!(expected, vmm_controller.get_dirty_bitmap().unwrap());

        // VM ran and dirtied 1 page.
        vmm_controller.setup_vmm_with_code_and_run();
        expected.insert(0, vec![1u64, 0u64, 0u64, 0u64]);
        assert_eq!(expected, vmm_controller.get_dirty_bitmap().unwrap());
    }
}
