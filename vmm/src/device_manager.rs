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

//todo: why should 15 be the MAX_IRQ?
const MAX_IRQ: u32 = 15;

/// Manages the complexities of adding a device.
pub struct DeviceManager {
    pub bus: devices::Bus,
    pub vm_requests: Vec<VmRequest>,
    guest_mem: GuestMemory,
    mmio_len: u64,
    mmio_base: u64,
    irq: u32,
}

impl DeviceManager {
    /// Create a new DeviceManager.
    pub fn new(
        guest_mem: GuestMemory,
        mmio_len: u64,
        mmio_base: u64,
        irq_base: u32,
    ) -> DeviceManager {
        DeviceManager {
            guest_mem: guest_mem,
            vm_requests: Vec::new(),
            mmio_len: mmio_len,
            mmio_base: mmio_base,
            irq: irq_base,
            bus: devices::Bus::new(),
        }
    }

    //the crosvm implementation also had a minijail parameter; it was removed, togeter with
    //al the related code
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
            .insert(
                Arc::new(Mutex::new(mmio_device)),
                self.mmio_base,
                self.mmio_len,
            )
            .unwrap();

        cmdline
            .insert(
                "virtio_mmio.device",
                &format!("4K@0x{:08x}:{}", self.mmio_base, self.irq),
            )
            .map_err(Error::Cmdline)?;
        self.mmio_base += self.mmio_len;
        self.irq += 1;

        Ok(())
    }
}
