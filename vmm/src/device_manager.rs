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

/// Errors for device manager.
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
pub struct DeviceManager {
    pub bus: devices::Bus,
    pub vm_requests: Vec<VmRequest>,
    guest_mem: GuestMemory,
    mmio_base: u64,
    irq: u32,
}

impl DeviceManager {
    /// Create a new DeviceManager.
    pub fn new(
        guest_mem: GuestMemory,
        mmio_base: u64,
    ) -> DeviceManager {
        DeviceManager {
            guest_mem: guest_mem,
            vm_requests: Vec::new(),
            mmio_base: mmio_base,
            irq: IRQ_BASE,
            bus: devices::Bus::new(),
        }
    }

    /// Register a device to be used via MMIO transport.
    pub fn register_mmio(
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
                &format!("{}K@0x{:08x}:{}", MMIO_LEN/1024, self.mmio_base, self.irq),
            )
            .map_err(Error::Cmdline)?;
        self.mmio_base += MMIO_LEN;
        self.irq += 1;

        Ok(())
    }
}

