// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt;
use std::sync::{Arc, Mutex};

use devices;
use kernel_cmdline;
use kvm::IoeventAddress;
use sys_util;
use sys_util::GuestMemory;
use vm_control::VmRequest;

/// Errors for MMIO device manager.
#[derive(Debug)]
pub enum Error {
    /// Could not create the mmio device to wrap a VirtioDevice.
    CreateMmioDevice(sys_util::Error),
    /// Failed to clone a queue's ioeventfd.
    CloneIoeventFd(sys_util::Error),
    /// Failed to clone the mmio irqfd.
    CloneIrqFd(sys_util::Error),
    /// Appending to kernel command line failed.
    Cmdline(kernel_cmdline::Error),
    /// No more IRQs are available.
    IrqsExhausted,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::CreateMmioDevice(ref e) => write!(f, "failed to create mmio device: {:?}", e),
            &Error::CloneIoeventFd(ref e) => write!(f, "failed to clone ioeventfd: {:?}", e),
            &Error::CloneIrqFd(ref e) => write!(f, "failed to clone irqfd: {:?}", e),
            &Error::Cmdline(ref e) => {
                write!(f, "unable to add device to kernel command line: {}", e)
            }
            &Error::IrqsExhausted => write!(f, "no more IRQs are available"),
        }
    }
}

type Result<T> = ::std::result::Result<T, Error>;

/// Typically, on x86 systems 16 IRQs are used (0-15)
/// Our device manager uses the IRQs from 5 to 16
const MAX_IRQ: u32 = 15;
const IRQ_BASE: u32 = 5;

/// This represents the size of the mmio device specified to the kernel as a cmdline option
/// It has to be larger than 0x100 (the offset where the configuration space starts from
/// the beginning of the memory mapped device registers) + the size of the configuration space
/// Currently hardcoded to 4K
const MMIO_LEN: u64 = 0x1000;

/// Manages the complexities of adding a device.
pub struct MMIODeviceManager {
    pub bus: devices::Bus,
    pub vm_requests: Vec<VmRequest>,
    guest_mem: GuestMemory,
    mmio_base: u64,
    irq: u32,
}

impl MMIODeviceManager {
    /// Create a new DeviceManager.
    pub fn new(guest_mem: GuestMemory, mmio_base: u64) -> MMIODeviceManager {
        MMIODeviceManager {
            guest_mem: guest_mem,
            vm_requests: Vec::new(),
            mmio_base: mmio_base,
            irq: IRQ_BASE,
            bus: devices::Bus::new(),
        }
    }

    /// Register a device to be used via MMIO transport.
    pub fn register_device(
        &mut self,
        device: Box<devices::virtio::VirtioDevice>,
        cmdline: &mut kernel_cmdline::Cmdline,
    ) -> Result<()> {
        if self.irq > MAX_IRQ {
            return Err(Error::IrqsExhausted);
        }

        let mmio_device = devices::virtio::MmioDevice::new(self.guest_mem.clone(), device)
            .map_err(Error::CreateMmioDevice)?;
        for (i, queue_evt) in mmio_device.queue_evts().iter().enumerate() {
            let io_addr =
                IoeventAddress::Mmio(self.mmio_base + devices::virtio::NOTIFY_REG_OFFSET as u64);
            self.vm_requests.push(VmRequest::RegisterIoevent(
                queue_evt.try_clone().map_err(Error::CloneIoeventFd)?,
                io_addr,
                i as u32,
            ));
        }

        if let Some(interrupt_evt) = mmio_device.interrupt_evt() {
            self.vm_requests.push(VmRequest::RegisterIrqfd(
                interrupt_evt.try_clone().map_err(Error::CloneIrqFd)?,
                self.irq,
            ));
        }

        self.bus
            .insert(Arc::new(Mutex::new(mmio_device)), self.mmio_base, MMIO_LEN)
            .unwrap();

        // as per doc, [virtio_mmio.]device=<size>@<baseaddr>:<irq> needs to be appended
        // to kernel commandline for virtio mmio devices to get recognized
        // the size parameter has to be transformed to KiB, so dividing hexadecimal value in
        // bytes to 1024; further, the '{}' formatting rust construct will automatically transform it to decimal
        cmdline
            .insert(
                "virtio_mmio.device",
                &format!("{}K@0x{:08x}:{}", MMIO_LEN / 1024, self.mmio_base, self.irq),
            )
            .map_err(Error::Cmdline)?;
        self.mmio_base += MMIO_LEN;
        self.irq += 1;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use sys_util::{EventFd, GuestAddress, GuestMemory};
    use kernel_cmdline;
    use devices::virtio::{ActivateResult, VirtioDevice};
    const QUEUE_SIZES: &'static [u16] = &[64];

    #[allow(dead_code)]
    #[derive(Clone)]
    struct DummyDevice {
        dummy: u32,
    }

    impl devices::virtio::VirtioDevice for DummyDevice {
        fn device_type(&self) -> u32 {
            0
        }

        fn queue_max_sizes(&self) -> &[u16] {
            QUEUE_SIZES
        }

        #[allow(unused_variables)]
        #[allow(unused_mut)]
        fn activate(
            &mut self,
            mem: GuestMemory,
            interrupt_evt: EventFd,
            status: Arc<AtomicUsize>,
            queues: Vec<devices::virtio::Queue>,
            mut queue_evts: Vec<EventFd>,
        ) -> ActivateResult {
            Ok(())
        }
    }

    #[test]
    fn register_device() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem =
            GuestMemory::new(&vec![(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();
        let mut device_manager = MMIODeviceManager::new(guest_mem, 0xd0000000);

        let mut cmdline = kernel_cmdline::Cmdline::new(4096);
        let dummy_box = Box::new(DummyDevice { dummy: 0 });

        assert!(
            device_manager
                .register_device(dummy_box, &mut cmdline)
                .is_ok()
        );
    }

    #[test]
    fn register_too_many_devices() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem =
            GuestMemory::new(&vec![(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();
        let mut device_manager = MMIODeviceManager::new(guest_mem, 0xd0000000);

        let mut cmdline = kernel_cmdline::Cmdline::new(4096);
        let dummy_box = Box::new(DummyDevice { dummy: 0 });
        for _i in IRQ_BASE..(MAX_IRQ + 1) {
            device_manager
                .register_device(dummy_box.clone(), &mut cmdline)
                .unwrap();
        }
        assert_eq!(
            format!(
                "{}",
                device_manager
                    .register_device(dummy_box.clone(), &mut cmdline)
                    .unwrap_err()
            ),
            "no more IRQs are available".to_string()
        );
    }

    #[test]
    fn test_dummy_device() {
        let mut dummy = DummyDevice { dummy: 0 };
        assert_eq!(dummy.device_type(), 0);
        assert_eq!(dummy.queue_max_sizes(), QUEUE_SIZES);

        // test activate
        let m = GuestMemory::new(&[(GuestAddress(0), 0x1000)]).unwrap();
        let ievt = EventFd::new().unwrap();
        let stat = Arc::new(AtomicUsize::new(0));
        let queue_evts = vec![EventFd::new().unwrap()];
        let result = dummy.activate(m.clone(), ievt, stat, Vec::with_capacity(1), queue_evts);
        assert!(result.is_ok());
    }

    #[test]
    fn test_error_messages() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem =
            GuestMemory::new(&vec![(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();
        let device_manager = MMIODeviceManager::new(guest_mem, 0xd0000000);
        let mut cmdline = kernel_cmdline::Cmdline::new(4096);
        let e = Error::Cmdline(
            cmdline
                .insert(
                    "virtio_mmio=device",
                    &format!(
                        "{}K@0x{:08x}:{}",
                        MMIO_LEN / 1024,
                        device_manager.mmio_base,
                        device_manager.irq
                    ),
                )
                .unwrap_err(),
        );
        assert_eq!(
            format!("{}", e),
            "unable to add device to kernel command line: string contains an equals sign"
        );
        let e = Error::CloneIoeventFd(sys_util::Error::new(0));
        assert_eq!(format!("{}", e), "failed to clone ioeventfd: Error(0)");
        let e = Error::CloneIrqFd(sys_util::Error::new(0));
        assert_eq!(format!("{}", e), "failed to clone irqfd: Error(0)");
    }
}
