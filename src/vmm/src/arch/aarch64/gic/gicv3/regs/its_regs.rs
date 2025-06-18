// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use kvm_bindings::{
    KVM_DEV_ARM_ITS_RESTORE_TABLES, KVM_DEV_ARM_ITS_SAVE_TABLES, KVM_DEV_ARM_VGIC_GRP_CTRL,
    KVM_DEV_ARM_VGIC_GRP_ITS_REGS,
};
use kvm_ioctls::DeviceFd;
use serde::{Deserialize, Serialize};

use crate::arch::aarch64::gic::GicError;

// ITS registers that we want to preserve across snapshots
const GITS_CTLR: u32 = 0x0000;
const GITS_IIDR: u32 = 0x0004;
const GITS_CBASER: u32 = 0x0080;
const GITS_CWRITER: u32 = 0x0088;
const GITS_CREADR: u32 = 0x0090;
const GITS_BASER: u32 = 0x0100;

fn set_device_attribute(
    its_device: &DeviceFd,
    group: u32,
    attr: u32,
    val: u64,
) -> Result<(), GicError> {
    let gicv3_its_attr = kvm_bindings::kvm_device_attr {
        group,
        attr: attr as u64,
        addr: &val as *const u64 as u64,
        flags: 0,
    };

    its_device
        .set_device_attr(&gicv3_its_attr)
        .map_err(|err| GicError::DeviceAttribute(err, true, group))
}

fn get_device_attribute(its_device: &DeviceFd, group: u32, attr: u32) -> Result<u64, GicError> {
    let mut val = 0;

    let mut gicv3_its_attr = kvm_bindings::kvm_device_attr {
        group,
        attr: attr as u64,
        addr: &mut val as *mut u64 as u64,
        flags: 0,
    };

    // SAFETY: gicv3_its_attr.addr is safe to write to.
    unsafe { its_device.get_device_attr(&mut gicv3_its_attr) }
        .map_err(|err| GicError::DeviceAttribute(err, false, group))?;

    Ok(val)
}

fn its_read_register(its_fd: &DeviceFd, attr: u32) -> Result<u64, GicError> {
    get_device_attribute(its_fd, KVM_DEV_ARM_VGIC_GRP_ITS_REGS, attr)
}

fn its_set_register(its_fd: &DeviceFd, attr: u32, val: u64) -> Result<(), GicError> {
    set_device_attribute(its_fd, KVM_DEV_ARM_VGIC_GRP_ITS_REGS, attr, val)
}

pub fn its_save_tables(its_fd: &DeviceFd) -> Result<(), GicError> {
    set_device_attribute(
        its_fd,
        KVM_DEV_ARM_VGIC_GRP_CTRL,
        KVM_DEV_ARM_ITS_SAVE_TABLES,
        0,
    )
}

pub fn its_restore_tables(its_fd: &DeviceFd) -> Result<(), GicError> {
    set_device_attribute(
        its_fd,
        KVM_DEV_ARM_VGIC_GRP_CTRL,
        KVM_DEV_ARM_ITS_RESTORE_TABLES,
        0,
    )
}

/// ITS registers that we save/restore during snapshot
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ItsRegisterState {
    iidr: u64,
    cbaser: u64,
    creadr: u64,
    cwriter: u64,
    baser: [u64; 8],
    ctlr: u64,
}

impl ItsRegisterState {
    /// Save ITS state
    pub fn save(its_fd: &DeviceFd) -> Result<Self, GicError> {
        let mut state = ItsRegisterState::default();

        for i in 0..8 {
            state.baser[i as usize] = its_read_register(its_fd, GITS_BASER + i * 8)?;
        }
        state.ctlr = its_read_register(its_fd, GITS_CTLR)?;
        state.cbaser = its_read_register(its_fd, GITS_CBASER)?;
        state.creadr = its_read_register(its_fd, GITS_CREADR)?;
        state.cwriter = its_read_register(its_fd, GITS_CWRITER)?;
        state.iidr = its_read_register(its_fd, GITS_IIDR)?;

        Ok(state)
    }

    /// Restore ITS state
    ///
    /// We need to restore ITS registers in a very specific order for things to work. Take a look
    /// at:
    /// https://elixir.bootlin.com/linux/v6.1.141/source/Documentation/virt/kvm/devices/arm-vgic-its.rst#L60
    /// and
    /// https://elixir.bootlin.com/linux/v6.1.141/source/Documentation/virt/kvm/devices/arm-vgic-its.rst#L123
    ///
    /// for more details, but TL;DR is:
    ///
    /// We need to restore GITS_CBASER, GITS_CREADER, GITS_CWRITER, GITS_BASER and GITS_IIDR
    /// registers before restoring ITS tables from guest memory. We also need to set GITS_CTLR
    /// last.
    pub fn restore(&self, its_fd: &DeviceFd) -> Result<(), GicError> {
        its_set_register(its_fd, GITS_IIDR, self.iidr)?;
        its_set_register(its_fd, GITS_CBASER, self.cbaser)?;
        its_set_register(its_fd, GITS_CREADR, self.creadr)?;
        its_set_register(its_fd, GITS_CWRITER, self.cwriter)?;
        for i in 0..8 {
            its_set_register(its_fd, GITS_BASER + i * 8, self.baser[i as usize])?;
        }
        // We need to restore saved ITS tables before restoring GITS_CTLR
        its_restore_tables(its_fd)?;
        its_set_register(its_fd, GITS_CTLR, self.ctlr)
    }
}
