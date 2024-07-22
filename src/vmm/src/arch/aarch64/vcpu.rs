// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::mem::offset_of;
use std::path::PathBuf;

use kvm_bindings::*;
use kvm_ioctls::VcpuFd;

use super::get_fdt_addr;
use super::regs::*;
use crate::vstate::memory::GuestMemoryMmap;

/// Errors thrown while setting aarch64 registers.
#[derive(Debug, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
pub enum VcpuError {
    /// Failed to get register {0}: {1}
    GetOneReg(u64, kvm_ioctls::Error),
    /// Failed to set register {0}: {1}
    SetOneReg(u64, kvm_ioctls::Error),
    /// Failed to retrieve list of registers: {0}
    GetRegList(kvm_ioctls::Error),
    /// Failed to get multiprocessor state: {0}
    GetMp(kvm_ioctls::Error),
    /// Failed to set multiprocessor state: {0}
    SetMp(kvm_ioctls::Error),
    /// Failed FamStructWrapper operation: {0}
    Fam(utils::fam::Error),
    /// {0}
    GetMidrEl1(String),
}

/// Extract the Manufacturer ID from a VCPU state's registers.
/// The ID is found between bits 24-31 of MIDR_EL1 register.
///
/// # Arguments
///
/// * `regs` - reference [`Aarch64RegisterVec`] structure with all registers of a VCPU.
pub fn get_manufacturer_id_from_state(regs: &Aarch64RegisterVec) -> Result<u32, VcpuError> {
    let midr_el1 = regs.iter().find(|reg| reg.id == MIDR_EL1);
    match midr_el1 {
        Some(register) => Ok(((register.value::<u64, 8>() >> 24) & 0xFF) as u32),
        None => Err(VcpuError::GetMidrEl1(
            "Failed to find MIDR_EL1 in vCPU state!".to_string(),
        )),
    }
}

/// Extract the Manufacturer ID from the host.
/// The ID is found between bits 24-31 of MIDR_EL1 register.
pub fn get_manufacturer_id_from_host() -> Result<u32, VcpuError> {
    let midr_el1_path =
        &PathBuf::from("/sys/devices/system/cpu/cpu0/regs/identification/midr_el1".to_string());

    let midr_el1 = std::fs::read_to_string(midr_el1_path).map_err(|err| {
        VcpuError::GetMidrEl1(format!("Failed to get MIDR_EL1 from host path: {err}"))
    })?;
    let midr_el1_trimmed = midr_el1.trim_end().trim_start_matches("0x");
    let manufacturer_id = u32::from_str_radix(midr_el1_trimmed, 16)
        .map_err(|err| VcpuError::GetMidrEl1(format!("Invalid MIDR_EL1 found on host: {err}",)))?;

    Ok(manufacturer_id >> 24)
}

/// Configure relevant boot registers for a given vCPU.
///
/// # Arguments
///
/// * `cpu_id` - Index of current vcpu.
/// * `boot_ip` - Starting instruction pointer.
/// * `mem` - Reserved DRAM for current VM.
pub fn setup_boot_regs(
    vcpufd: &VcpuFd,
    cpu_id: u8,
    boot_ip: u64,
    mem: &GuestMemoryMmap,
) -> Result<(), VcpuError> {
    let kreg_off = offset_of!(kvm_regs, regs);

    // Get the register index of the PSTATE (Processor State) register.
    let pstate = offset_of!(user_pt_regs, pstate) + kreg_off;
    let id = arm64_core_reg_id!(KVM_REG_SIZE_U64, pstate);
    vcpufd
        .set_one_reg(id, &PSTATE_FAULT_BITS_64.to_le_bytes())
        .map_err(|err| VcpuError::SetOneReg(id, err))?;

    // Other vCPUs are powered off initially awaiting PSCI wakeup.
    if cpu_id == 0 {
        // Setting the PC (Processor Counter) to the current program address (kernel address).
        let pc = offset_of!(user_pt_regs, pc) + kreg_off;
        let id = arm64_core_reg_id!(KVM_REG_SIZE_U64, pc);
        vcpufd
            .set_one_reg(id, &boot_ip.to_le_bytes())
            .map_err(|err| VcpuError::SetOneReg(id, err))?;

        // Last mandatory thing to set -> the address pointing to the FDT (also called DTB).
        // "The device tree blob (dtb) must be placed on an 8-byte boundary and must
        // not exceed 2 megabytes in size." -> https://www.kernel.org/doc/Documentation/arm64/booting.txt.
        // We are choosing to place it the end of DRAM. See `get_fdt_addr`.
        let regs0 = offset_of!(user_pt_regs, regs) + kreg_off;
        let id = arm64_core_reg_id!(KVM_REG_SIZE_U64, regs0);
        vcpufd
            .set_one_reg(id, &get_fdt_addr(mem).to_le_bytes())
            .map_err(|err| VcpuError::SetOneReg(id, err))?;
    }
    Ok(())
}

/// Read the MPIDR - Multiprocessor Affinity Register.
pub fn get_mpidr(vcpufd: &VcpuFd) -> Result<u64, VcpuError> {
    // MPIDR register is 64 bit wide on aarch64
    let mut mpidr = [0_u8; 8];
    match vcpufd.get_one_reg(MPIDR_EL1, &mut mpidr) {
        Err(err) => Err(VcpuError::GetOneReg(MPIDR_EL1, err)),
        Ok(_) => Ok(u64::from_le_bytes(mpidr)),
    }
}

/// Saves the states of the system registers into `state`.
///
/// # Arguments
///
/// * `regs` - Input/Output vector of registers.
pub fn get_all_registers(vcpufd: &VcpuFd, state: &mut Aarch64RegisterVec) -> Result<(), VcpuError> {
    get_registers(vcpufd, &get_all_registers_ids(vcpufd)?, state)
}

/// Saves states of registers into `state`.
///
/// # Arguments
///
/// * `ids` - Slice of registers ids to save.
/// * `regs` - Input/Output vector of registers.
pub fn get_registers(
    vcpufd: &VcpuFd,
    ids: &[u64],
    regs: &mut Aarch64RegisterVec,
) -> Result<(), VcpuError> {
    let mut big_reg = [0_u8; 256];
    for id in ids.iter() {
        let reg_size = vcpufd
            .get_one_reg(*id, &mut big_reg)
            .map_err(|e| VcpuError::GetOneReg(*id, e))?;
        let reg_ref = Aarch64RegisterRef::new(*id, &big_reg[0..reg_size]);
        regs.push(reg_ref);
    }
    Ok(())
}

/// Returns all registers ids, including core and system
pub fn get_all_registers_ids(vcpufd: &VcpuFd) -> Result<Vec<u64>, VcpuError> {
    // Call KVM_GET_REG_LIST to get all registers available to the guest. For ArmV8 there are
    // less than 500 registers expected, resize to the reported size when necessary.
    let mut reg_list = RegList::new(500).map_err(VcpuError::Fam)?;

    match vcpufd.get_reg_list(&mut reg_list) {
        Ok(_) => Ok(reg_list.as_slice().to_vec()),
        Err(e) => match e.errno() {
            libc::E2BIG => {
                // resize and retry.
                let size: usize = reg_list
                    .as_fam_struct_ref()
                    .n
                    .try_into()
                    // Safe to unwrap as Firecracker only targets 64-bit machines.
                    .unwrap();
                reg_list = RegList::new(size).map_err(VcpuError::Fam)?;
                vcpufd
                    .get_reg_list(&mut reg_list)
                    .map_err(VcpuError::GetRegList)?;

                Ok(reg_list.as_slice().to_vec())
            }
            _ => Err(VcpuError::GetRegList(e)),
        },
    }
}

/// Set the state of one system register.
///
/// # Arguments
///
/// * `reg` - Register to be set.
pub fn set_register(vcpufd: &VcpuFd, reg: Aarch64RegisterRef) -> Result<(), VcpuError> {
    vcpufd
        .set_one_reg(reg.id, reg.as_slice())
        .map_err(|e| VcpuError::SetOneReg(reg.id, e))?;
    Ok(())
}

/// Get the multistate processor.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
pub fn get_mpstate(vcpufd: &VcpuFd) -> Result<kvm_mp_state, VcpuError> {
    vcpufd.get_mp_state().map_err(VcpuError::GetMp)
}

/// Set the state of the system registers.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
/// * `state` - Structure for returning the state of the system registers.
pub fn set_mpstate(vcpufd: &VcpuFd, state: kvm_mp_state) -> Result<(), VcpuError> {
    vcpufd.set_mp_state(state).map_err(VcpuError::SetMp)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
    use kvm_ioctls::Kvm;

    use super::*;
    use crate::arch::aarch64::layout;
    use crate::utilities::test_utils::arch_mem;

    #[test]
    fn test_setup_regs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mem = arch_mem(layout::FDT_MAX_SIZE + 0x1000);

        let res = setup_boot_regs(&vcpu, 0, 0x0, &mem);
        assert!(matches!(
            res.unwrap_err(),
            VcpuError::SetOneReg(0x6030000000100042, _)
        ));

        let mut kvi: kvm_bindings::kvm_vcpu_init = kvm_bindings::kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();
        vcpu.vcpu_init(&kvi).unwrap();

        setup_boot_regs(&vcpu, 0, 0x0, &mem).unwrap();
    }

    #[test]
    fn test_read_mpidr() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut kvi: kvm_bindings::kvm_vcpu_init = kvm_bindings::kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();

        // Must fail when vcpu is not initialized yet.
        let res = get_mpidr(&vcpu);
        assert!(matches!(
            res.unwrap_err(),
            VcpuError::GetOneReg(MPIDR_EL1, _)
        ));

        vcpu.vcpu_init(&kvi).unwrap();
        assert_eq!(get_mpidr(&vcpu).unwrap(), 0x8000_0000);
    }

    #[test]
    fn test_get_set_regs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut kvi: kvm_bindings::kvm_vcpu_init = kvm_bindings::kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();

        // Must fail when vcpu is not initialized yet.
        let mut regs = Aarch64RegisterVec::default();
        let res = get_all_registers(&vcpu, &mut regs);
        assert!(matches!(res.unwrap_err(), VcpuError::GetRegList(_)));

        vcpu.vcpu_init(&kvi).unwrap();
        get_all_registers(&vcpu, &mut regs).unwrap();
        for reg in regs.iter() {
            set_register(&vcpu, reg).unwrap();
        }
    }

    #[test]
    fn test_mpstate() {
        use std::os::unix::io::AsRawFd;

        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut kvi: kvm_bindings::kvm_vcpu_init = kvm_bindings::kvm_vcpu_init::default();
        vm.get_preferred_target(&mut kvi).unwrap();

        let res = get_mpstate(&vcpu);
        set_mpstate(&vcpu, res.unwrap()).unwrap();

        unsafe { libc::close(vcpu.as_raw_fd()) };

        let res = get_mpstate(&vcpu);
        assert!(matches!(res, Err(VcpuError::GetMp(_))), "{:?}", res);

        let res = set_mpstate(&vcpu, kvm_mp_state::default());
        assert!(matches!(res, Err(VcpuError::SetMp(_))), "{:?}", res);
    }
}
