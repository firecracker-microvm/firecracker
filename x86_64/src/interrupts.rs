// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::io::Cursor;
use std::mem;
use std::result;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use kvm;
use kvm_sys::kvm_lapic_state;
use sys_util;

#[derive(Debug)]
pub enum Error {
    GetLapic(sys_util::Error),
    SetLapic(sys_util::Error),
}
pub type Result<T> = result::Result<T, Error>;

// Defines poached from apicdef.h kernel header.
const APIC_LVT0: usize = 0x350;
const APIC_LVT1: usize = 0x360;
const APIC_MODE_NMI: u32 = 0x4;
const APIC_MODE_EXTINT: u32 = 0x7;

fn get_klapic_reg(klapic: &kvm_lapic_state, reg_offset: usize) -> u32 {
    let sliceu8 = unsafe {
        // This array is only accessed as parts of a u32 word, so interpret it as a u8 array.
        // Cursors are only readable on arrays of u8, not i8(c_char).
        mem::transmute::<&[i8], &[u8]>(&klapic.regs[reg_offset..])
    };
    let mut reader = Cursor::new(sliceu8);
    // read_u32 can't fail if the offsets defined above are correct.
    reader.read_u32::<LittleEndian>().unwrap()
}

fn set_klapic_reg(klapic: &mut kvm_lapic_state, reg_offset: usize, value: u32) {
    let sliceu8 = unsafe {
        // This array is only accessed as parts of a u32 word, so interpret it as a u8 array.
        // Cursors are only readable on arrays of u8, not i8(c_char).
        mem::transmute::<&mut [i8], &mut [u8]>(&mut klapic.regs[reg_offset..])
    };
    let mut writer = Cursor::new(sliceu8);
    // read_u32 can't fail if the offsets defined above are correct.
    writer.write_u32::<LittleEndian>(value).unwrap()
}

fn set_apic_delivery_mode(reg: u32, mode: u32) -> u32 {
    (((reg) & !0x700) | ((mode) << 8))
}

/// Configures LAPICs.  LAPIC0 is set for external interrupts, LAPIC1 is set for NMI.
///
/// # Arguments
/// * `vcpu` - The VCPU object to configure.
pub fn set_lint(vcpu: &kvm::VcpuFd) -> Result<()> {
    let mut klapic = vcpu.get_lapic().map_err(Error::GetLapic)?;

    let lvt_lint0 = get_klapic_reg(&klapic, APIC_LVT0);
    set_klapic_reg(
        &mut klapic,
        APIC_LVT0,
        set_apic_delivery_mode(lvt_lint0, APIC_MODE_EXTINT),
    );
    let lvt_lint1 = get_klapic_reg(&klapic, APIC_LVT1);
    set_klapic_reg(
        &mut klapic,
        APIC_LVT1,
        set_apic_delivery_mode(lvt_lint1, APIC_MODE_NMI),
    );

    vcpu.set_lapic(&klapic).map_err(Error::SetLapic)
}
