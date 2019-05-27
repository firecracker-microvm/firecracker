// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::io::{self, Cursor};
use std::result;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use kvm_bindings::kvm_lapic_state;
use kvm_ioctls::VcpuFd;

#[derive(Debug)]
pub enum Error {
    GetLapic(io::Error),
    SetLapic(io::Error),
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
        &*(&klapic.regs[reg_offset..] as *const [i8] as *const [u8])
    };
    let mut reader = Cursor::new(sliceu8);
    // Following call can't fail if the offsets defined above are correct.
    reader
        .read_u32::<LittleEndian>()
        .expect("Failed to read klapic register")
}

fn set_klapic_reg(klapic: &mut kvm_lapic_state, reg_offset: usize, value: u32) {
    let sliceu8 = unsafe {
        // This array is only accessed as parts of a u32 word, so interpret it as a u8 array.
        // Cursors are only readable on arrays of u8, not i8(c_char).
        &mut *(&mut klapic.regs[reg_offset..] as *mut [i8] as *mut [u8])
    };
    let mut writer = Cursor::new(sliceu8);
    // Following call can't fail if the offsets defined above are correct.
    writer
        .write_u32::<LittleEndian>(value)
        .expect("Failed to write klapic register")
}

fn set_apic_delivery_mode(reg: u32, mode: u32) -> u32 {
    (((reg) & !0x700) | ((mode) << 8))
}

/// Configures LAPICs.  LAPIC0 is set for external interrupts, LAPIC1 is set for NMI.
///
/// # Arguments
/// * `vcpu` - The VCPU object to configure.
pub fn set_lint(vcpu: &VcpuFd) -> Result<()> {
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

#[cfg(test)]
mod tests {
    extern crate rand;
    use self::rand::Rng;

    use super::*;
    use kvm_ioctls::Kvm;

    const KVM_APIC_REG_SIZE: usize = 0x400;

    #[test]
    fn test_set_and_get_klapic_reg() {
        let reg_offset = 0x340;
        let mut klapic = kvm_lapic_state::default();
        set_klapic_reg(&mut klapic, reg_offset, 3);
        let value = get_klapic_reg(&klapic, reg_offset);
        assert_eq!(value, 3);
    }

    #[test]
    #[should_panic]
    fn test_set_and_get_klapic_out_of_bounds() {
        let reg_offset = KVM_APIC_REG_SIZE + 10;
        let mut klapic = kvm_lapic_state::default();
        set_klapic_reg(&mut klapic, reg_offset, 3);
    }

    #[test]
    fn test_apic_delivery_mode() {
        let mut rng = rand::thread_rng();
        let mut v: Vec<u32> = (0..20).map(|_| rng.gen::<u32>()).collect();

        v.iter_mut()
            .for_each(|x| *x = set_apic_delivery_mode(*x, 2));
        let after: Vec<u32> = v.iter().map(|x| ((*x & !0x700) | ((2) << 8))).collect();
        assert_eq!(v, after);
    }

    #[test]
    fn test_setlint() {
        let kvm = Kvm::new().unwrap();
        assert!(kvm.check_extension(kvm_ioctls::Cap::Irqchip));
        let vm = kvm.create_vm().unwrap();
        //the get_lapic ioctl will fail if there is no irqchip created beforehand.
        assert!(vm.create_irq_chip().is_ok());
        let vcpu = vm.create_vcpu(0).unwrap();
        let klapic_before: kvm_lapic_state = vcpu.get_lapic().unwrap();

        // Compute the value that is expected to represent LVT0 and LVT1.
        let lint0 = get_klapic_reg(&klapic_before, APIC_LVT0);
        let lint1 = get_klapic_reg(&klapic_before, APIC_LVT1);
        let lint0_mode_expected = set_apic_delivery_mode(lint0, APIC_MODE_EXTINT);
        let lint1_mode_expected = set_apic_delivery_mode(lint1, APIC_MODE_NMI);

        set_lint(&vcpu).unwrap();

        // Compute the value that represents LVT0 and LVT1 after set_lint.
        let klapic_actual: kvm_lapic_state = vcpu.get_lapic().unwrap();
        let lint0_mode_actual = get_klapic_reg(&klapic_actual, APIC_LVT0);
        let lint1_mode_actual = get_klapic_reg(&klapic_actual, APIC_LVT1);
        assert_eq!(lint0_mode_expected, lint0_mode_actual);
        assert_eq!(lint1_mode_expected, lint1_mode_actual);
    }

    #[test]
    fn test_setlint_fails() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        // 'get_lapic' ioctl triggered by the 'set_lint' function will fail if there is no
        // irqchip created beforehand.
        assert!(set_lint(&vcpu).is_err());
    }
}
