// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Implements legacy devices (UART, RTC etc).
mod i8042;
#[cfg(target_arch = "aarch64")]
pub mod rtc_pl031;
pub mod serial;

use std::io;
use std::ops::Deref;
#[cfg(target_arch = "riscv64")]
use std::os::fd::AsRawFd;

use serde::Serializer;
use serde::ser::SerializeMap;
use vm_superio::Trigger;
use vmm_sys_util::eventfd::EventFd;
#[cfg(target_arch = "riscv64")]
use vmm_sys_util::{errno, ioctl::ioctl_with_ref, ioctl_ioc_nr, ioctl_iow_nr};

pub use self::i8042::{I8042Device, I8042Error as I8042DeviceError};
#[cfg(target_arch = "aarch64")]
pub use self::rtc_pl031::RTCDevice;
pub use self::serial::{
    IER_RDA_BIT, IER_RDA_OFFSET, SerialDevice, SerialEventsWrapper, SerialWrapper,
};
#[cfg(target_arch = "riscv64")]
use crate::logger::error;

/// Wrapper for implementing the trigger functionality for `EventFd`.
///
/// The trigger is used for handling events in the legacy devices.
#[derive(Debug)]
pub struct EventFdTrigger(EventFd);

impl Trigger for EventFdTrigger {
    type E = io::Error;

    fn trigger(&self) -> io::Result<()> {
        self.write(1)
    }
}

impl Deref for EventFdTrigger {
    type Target = EventFd;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl EventFdTrigger {
    /// Clone an `EventFdTrigger`.
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(EventFdTrigger((**self).try_clone()?))
    }

    /// Create an `EventFdTrigger`.
    pub fn new(evt: EventFd) -> Self {
        Self(evt)
    }

    /// Get the associated event fd out of an `EventFdTrigger`.
    pub fn get_event(&self) -> EventFd {
        self.0.try_clone().unwrap()
    }
}

// TODO: raw_vmfd and gsi are actually never None.
#[cfg(target_arch = "riscv64")]
#[derive(Debug)]
pub struct IrqLineTrigger {
    raw_vmfd: Option<i32>,
    gsi: Option<u32>,
}

#[cfg(target_arch = "riscv64")]
impl IrqLineTrigger {
    pub fn new(raw_vmfd: i32, gsi: u32) -> Self {
        Self {
            raw_vmfd: Some(raw_vmfd),
            gsi: Some(gsi),
        }
    }

    // This function is taken from kvm-ioctls because it requires VmFd, which we don't
    // have at this point. However, it only uses the raw file descriptor, which is just
    // an i32. So, we copy it here and use it directly with the raw fd.
    fn set_irq_line<F: AsRawFd>(fd: F, irq: u32, active: bool) -> Result<(), kvm_ioctls::Error> {
        let mut irq_level = kvm_bindings::kvm_irq_level::default();
        irq_level.__bindgen_anon_1.irq = irq;
        irq_level.level = u32::from(active);

        // SAFETY: Safe because we know that our file is a VM fd, we know the kernel will only read
        // the correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(&fd, IrqLineTrigger::KVM_IRQ_LINE(), &irq_level) };
        if ret == 0 {
            Ok(())
        } else {
            Err(errno::Error::last())
        }
    }

    ioctl_iow_nr!(
        KVM_IRQ_LINE,
        kvm_bindings::KVMIO,
        0x61,
        kvm_bindings::kvm_irq_level
    );
}

#[cfg(target_arch = "riscv64")]
impl Trigger for IrqLineTrigger {
    type E = ::std::io::Error;

    fn trigger(&self) -> ::std::io::Result<()> {
        // Safe to unwrap since `gsi` and `vmfd` have been set
        let gsi = self.gsi.unwrap();

        IrqLineTrigger::set_irq_line(self.raw_vmfd.unwrap().as_raw_fd(), gsi, true).map_err(
            |err| {
                error!("set_irq_line() failed: {err:?}");
                std::io::Error::last_os_error()
            },
        )?;
        IrqLineTrigger::set_irq_line(self.raw_vmfd.unwrap().as_raw_fd(), gsi, false).map_err(
            |err| {
                error!("set_irq_line() failed: {err:?}");
                std::io::Error::last_os_error()
            },
        )?;

        Ok(())
    }
}

/// Called by METRICS.flush(), this function facilitates serialization of aggregated metrics.
pub fn flush_metrics<S: Serializer>(serializer: S) -> Result<S::Ok, S::Error> {
    let mut seq = serializer.serialize_map(Some(1))?;
    seq.serialize_entry("i8042", &i8042::METRICS)?;
    #[cfg(target_arch = "aarch64")]
    seq.serialize_entry("rtc", &rtc_pl031::METRICS)?;
    seq.serialize_entry("uart", &serial::METRICS)?;
    seq.end()
}
