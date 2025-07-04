// Copyright © 2025 Computing Systems Laboratory (CSLab), ECE, NTUA. All rights reserved.
//
// Copyright © 2024 Institute of Software, CAS. All rights reserved.
//
// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.


use std::collections::HashMap;
use std::ffi::CString;

use kvm_bindings::*;
use vm_fdt::{Error as VmFdtError, FdtWriter};
use vm_memory::GuestMemoryError;

use super::super::DeviceType;
use super::aia::AIADevice;
use super::regs::*;
use crate::device_manager::mmio::MMIODeviceInfo;
use crate::logger::error;
use crate::vstate::memory::{Address, GuestMemory, GuestMemoryMmap};
use crate::vstate::vcpu::Vcpu;

const ADDRESS_CELLS: u32 = 0x2;
const SIZE_CELLS: u32 = 0x2;
const CPU_INTC_BASE_PHANDLE: u32 = 3;
const AIA_APLIC_PHANDLE: u32 = 1;
const AIA_IMSIC_PHANDLE: u32 = 2;
const S_MODE_EXT_IRQ: u32 = 9;
const IRQ_TYPE_LEVEL_HIGH: u32 = 4;
const IRQ_TYPE_EDGE_RISING: u32 = 0x00000001;

struct IsaExtInfo<'a> {
    name: &'a [u8],
    ext_id: KVM_RISCV_ISA_EXT_ID,
}

// Sorted alphabetically
const ISA_INFO_ARRAY: [IsaExtInfo; 46] = [
    IsaExtInfo {
        name: b"smstateen",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_SMSTATEEN,
    },
    IsaExtInfo {
        name: b"ssaia",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_SSAIA,
    },
    IsaExtInfo {
        name: b"sstc",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_SSTC,
    },
    IsaExtInfo {
        name: b"svinval",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_SVINVAL,
    },
    IsaExtInfo {
        name: b"svnapot",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_SVNAPOT,
    },
    IsaExtInfo {
        name: b"svpbmt",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_SVPBMT,
    },
    IsaExtInfo {
        name: b"zacas",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZACAS,
    },
    IsaExtInfo {
        name: b"zba",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZBA,
    },
    IsaExtInfo {
        name: b"zbb",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZBB,
    },
    IsaExtInfo {
        name: b"zbc",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZBC,
    },
    IsaExtInfo {
        name: b"zbkb",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZBKB,
    },
    IsaExtInfo {
        name: b"zbkc",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZBKC,
    },
    IsaExtInfo {
        name: b"zbkx",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZBKX,
    },
    IsaExtInfo {
        name: b"zbs",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZBS,
    },
    IsaExtInfo {
        name: b"zfa",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZFA,
    },
    IsaExtInfo {
        name: b"zfh",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZFH,
    },
    IsaExtInfo {
        name: b"zfhmin",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZFHMIN,
    },
    IsaExtInfo {
        name: b"zicbom",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZICBOM,
    },
    IsaExtInfo {
        name: b"zicboz",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZICBOZ,
    },
    IsaExtInfo {
        name: b"zicntr",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZICNTR,
    },
    IsaExtInfo {
        name: b"zicond",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZICOND,
    },
    IsaExtInfo {
        name: b"zicsr",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZICSR,
    },
    IsaExtInfo {
        name: b"zifencei",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZIFENCEI,
    },
    IsaExtInfo {
        name: b"zihintntl",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZIHINTNTL,
    },
    IsaExtInfo {
        name: b"zihintpause",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZIHINTPAUSE,
    },
    IsaExtInfo {
        name: b"zihpm",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZIHPM,
    },
    IsaExtInfo {
        name: b"zknd",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZKND,
    },
    IsaExtInfo {
        name: b"zkne",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZKNE,
    },
    IsaExtInfo {
        name: b"zknh",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZKNH,
    },
    IsaExtInfo {
        name: b"zkr",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZKR,
    },
    IsaExtInfo {
        name: b"zksed",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZKSED,
    },
    IsaExtInfo {
        name: b"zksh",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZKSH,
    },
    IsaExtInfo {
        name: b"zkt",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZKT,
    },
    IsaExtInfo {
        name: b"ztso",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZTSO,
    },
    IsaExtInfo {
        name: b"zvbb",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZVBB,
    },
    IsaExtInfo {
        name: b"zvbc",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZVBC,
    },
    IsaExtInfo {
        name: b"zvfh",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZVFH,
    },
    IsaExtInfo {
        name: b"zvfhmin",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZVFHMIN,
    },
    IsaExtInfo {
        name: b"zvkb",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZVKB,
    },
    IsaExtInfo {
        name: b"zvkg",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZVKG,
    },
    IsaExtInfo {
        name: b"zvkned",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZVKNED,
    },
    IsaExtInfo {
        name: b"zvknha",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZVKNHA,
    },
    IsaExtInfo {
        name: b"zvknhb",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZVKNHB,
    },
    IsaExtInfo {
        name: b"zvksed",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZVKSED,
    },
    IsaExtInfo {
        name: b"zvksh",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZVKSH,
    },
    IsaExtInfo {
        name: b"zvkt",
        ext_id: KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZVKT,
    },
];

/// Errors thrown while configuring the Flattened Device Tree for riscv64.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum FdtError {
    /// Create FDT error: {0}
    CreateFdt(#[from] VmFdtError),
    /// Read cache info error: {0}
    ReadCacheInfo(String),
    /// Failure in writing FDT in memory.
    WriteFdtToMemory(#[from] GuestMemoryError),
    /// Get device attribute error.
    GetDeviceAttr,
    /// Get one register error.
    GetOneReg(u64, kvm_ioctls::Error),
}

pub fn create_fdt(
    vcpus: &[Vcpu],
    guest_mem: &GuestMemoryMmap,
    cmdline: CString,
    timer_freq: u32,
    device_info: &HashMap<(DeviceType, String), MMIODeviceInfo>,
    aia_device: &AIADevice,
) -> Result<Vec<u8>, FdtError> {
    let mut fdt_writer = FdtWriter::new()?;

    let root = fdt_writer.begin_node("")?;

    fdt_writer.property_string("compatible", "linux,dummy-virt")?;
    fdt_writer.property_u32("#address-cells", ADDRESS_CELLS)?;
    fdt_writer.property_u32("#size-cells", SIZE_CELLS)?;
    create_cpu_nodes(&mut fdt_writer, vcpus, timer_freq)?;
    create_memory_node(&mut fdt_writer, guest_mem)?;
    create_chosen_node(&mut fdt_writer, cmdline)?;
    create_aia_node(&mut fdt_writer, aia_device)?;
    create_devices_node(&mut fdt_writer, device_info)?;

    fdt_writer.end_node(root)?;

    let fdt_final = fdt_writer.finish()?;

    Ok(fdt_final)
}

const CPU_ISA_MAX_LEN: usize = ISA_INFO_ARRAY.len() * 16;

// Create FDT cpu nodes the way kvmtool does.
fn create_cpu_nodes(fdt: &mut FdtWriter, vcpus: &[Vcpu], timer_freq: u32) -> Result<(), FdtError> {
    let valid_isa_order = b"IEMAFDQCLBJTPVNSUHKORWXYZG";
    let mut cbom = false;
    let cbom_blksz = &mut [0u8; 8];
    let mut cboz = false;
    let cboz_blksz = &mut [0u8; 8];

    let cpus = fdt.begin_node("cpus")?;

    fdt.property_u32("#address-cells", 0x1)?;
    fdt.property_u32("#size-cells", 0x0)?;
    fdt.property_u32("timebase-frequency", timer_freq)?;

    for (cpu_index, vcpu) in vcpus.iter().enumerate() {
        let vcpu_fd = &vcpu.kvm_vcpu.fd;
        let cpu_index = u32::try_from(cpu_index).unwrap();

        let cpu_isa = &mut [0; CPU_ISA_MAX_LEN];
        let mut pos = "rv64".len();
        cpu_isa[0..pos].copy_from_slice(b"rv64");

        let mut bytes = [0u8; 8];
        let off_isa = std::mem::offset_of!(kvm_riscv_config, isa);
        let id_isa = riscv64_reg_config_id!(off_isa);

        vcpu_fd
            .get_one_reg(id_isa, &mut bytes)
            .map_err(|err| FdtError::GetOneReg(id_isa, err))?;

        let isa = u64::from_le_bytes(bytes);

        for i in valid_isa_order {
            let index = *i - 'A' as u8;
            if isa & (1 << index) != 0 {
                cpu_isa[pos] = 'a' as u8 + index;
                pos += 1;
            }
        }

        for isa_ext_info in ISA_INFO_ARRAY {
            let ext_id = isa_ext_info.ext_id;
            let id_isa_ext = riscv64_reg_isa_ext!(ext_id);
            let isa_ext_out = &mut [0u8; 8];
            if vcpu_fd.get_one_reg(id_isa_ext, isa_ext_out).is_err() {
                continue;
            }

            if u64::from_le_bytes(*isa_ext_out) == 0u64 {
                // This extension is not available
                continue;
            }

            if ext_id == KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZICBOM && !cbom {
                let off_zicbom_blk_size = std::mem::offset_of!(kvm_riscv_config, zicbom_block_size);
                let id_zicbom_blk_size = riscv64_reg_config_id!(off_zicbom_blk_size);
                vcpu_fd
                    .get_one_reg(id_zicbom_blk_size, cbom_blksz)
                    .map_err(|err| {
                        error!("get_one_reg() failed: {err:?}");
                        FdtError::GetDeviceAttr
                    })?;
                cbom = true;
            }

            if ext_id == KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZICBOZ && !cboz {
                let off_zicboz_blk_size = std::mem::offset_of!(kvm_riscv_config, zicboz_block_size);
                let id_zicboz_blk_size = riscv64_reg_config_id!(off_zicboz_blk_size);
                vcpu_fd
                    .get_one_reg(id_zicboz_blk_size, cboz_blksz)
                    .map_err(|err| {
                        error!("get_one_reg() failed: {err:?}");
                        FdtError::GetDeviceAttr
                    })?;
                cboz = true;
            }

            cpu_isa[pos] = '_' as u8;
            pos += 1;
            let name_len = isa_ext_info.name.len();
            cpu_isa[pos..pos + name_len].copy_from_slice(isa_ext_info.name);
            pos += name_len;
        }

        let off_satp = std::mem::offset_of!(kvm_riscv_config, satp_mode);
        let id_satp = riscv64_reg_config_id!(off_satp);
        let b = &mut [0u8; 8];
        let satp_mode = if vcpu_fd.get_one_reg(id_satp, b).is_ok() {
            u64::from_le_bytes(*b)
        } else {
            8
        };

        let cpu = fdt.begin_node(&format!("cpu@{:x}", cpu_index))?;
        fdt.property_string("device_type", "cpu")?;
        fdt.property_string("compatible", "riscv")?;

        match satp_mode {
            10 => fdt.property_string("mmu-type", "riscv,sv57")?,
            9 => fdt.property_string("mmu-type", "riscv,sv48")?,
            8 => fdt.property_string("mmu-type", "riscv,sv39")?,
            _ => fdt.property_string("mmu-type", "riscv,none")?,
        }

        fdt.property_string(
            "riscv,isa",
            ::std::str::from_utf8(&cpu_isa[0..pos]).expect("cpu_isa unexpected error"),
        )?;

        if cbom {
            fdt.property_u32(
                "riscv,cbom-block-size",
                u32::try_from(u64::from_le_bytes(*cbom_blksz)).unwrap(),
            )?;
        }

        if cboz {
            fdt.property_u32(
                "riscv,cboz-block-size",
                u32::try_from(u64::from_le_bytes(*cboz_blksz)).unwrap(),
            )?;
        }

        fdt.property_u32("reg", cpu_index)?;
        fdt.property_string("status", "okay")?;

        // interrupt controller node
        let intc_node = fdt.begin_node("interrupt-controller")?;
        fdt.property_string("compatible", "riscv,cpu-intc")?;
        fdt.property_u32("#interrupt-cells", 1u32)?;
        fdt.property_null("interrupt-controller")?;
        fdt.property_u32("phandle", CPU_INTC_BASE_PHANDLE + cpu_index)?;
        fdt.end_node(intc_node)?;

        fdt.end_node(cpu)?;
    }

    fdt.end_node(cpus)?;

    Ok(())
}

fn create_memory_node(fdt: &mut FdtWriter, guest_mem: &GuestMemoryMmap) -> Result<(), FdtError> {
    let mem_size = guest_mem.last_addr().raw_value()
        - super::layout::DRAM_MEM_START
        - super::layout::SYSTEM_MEM_SIZE
        + 1;
    let mem_reg_prop = &[
        super::layout::DRAM_MEM_START + super::layout::SYSTEM_MEM_SIZE,
        mem_size,
    ];
    let mem = fdt.begin_node("memory@ram")?;
    fdt.property_string("device_type", "memory")?;
    fdt.property_array_u64("reg", mem_reg_prop)?;
    fdt.end_node(mem)?;

    Ok(())
}

fn create_chosen_node(fdt: &mut FdtWriter, cmdline: CString) -> Result<(), FdtError> {
    let chosen = fdt.begin_node("chosen")?;

    let cmdline_string = cmdline
        .into_string()
        .map_err(|_| vm_fdt::Error::InvalidString)?;
    fdt.property_string("bootargs", cmdline_string.as_str())?;

    fdt.end_node(chosen)?;

    Ok(())
}

fn create_aia_node(fdt: &mut FdtWriter, aia: &AIADevice) -> Result<(), FdtError> {
    if aia.msi_compatible() {
        let imsic_name = format!("imsics@{:08x}", super::layout::IMSIC_START);
        let imsic_node = fdt.begin_node(&imsic_name)?;

        fdt.property_string("compatible", aia.imsic_compatibility())?;
        let imsic_reg_prop = aia.imsic_properties();
        fdt.property_array_u32("reg", &imsic_reg_prop)?;
        fdt.property_u32("#interrupt-cells", 0u32)?;
        fdt.property_null("interrupt-controller")?;
        fdt.property_null("msi-controller")?;

        let mut aia_nr_ids: u32 = 0;
        let mut nr_ids_attr = ::kvm_bindings::kvm_device_attr::default();
        nr_ids_attr.group = ::kvm_bindings::KVM_DEV_RISCV_AIA_GRP_CONFIG;
        nr_ids_attr.attr = ::kvm_bindings::KVM_DEV_RISCV_AIA_CONFIG_IDS as u64;
        nr_ids_attr.addr = &mut aia_nr_ids as *mut u32 as u64;

        aia.get_device_attribute(&mut nr_ids_attr)
            .map_err(|_| FdtError::GetDeviceAttr)?;

        fdt.property_u32("riscv,num-ids", aia_nr_ids)?;
        fdt.property_u32("phandle", AIA_IMSIC_PHANDLE)?;

        let mut irq_cells = vec![];
        let num_cpus = aia.vcpu_count() as u32;
        for i in 0..num_cpus {
            irq_cells.push(CPU_INTC_BASE_PHANDLE + i);
            irq_cells.push(S_MODE_EXT_IRQ);
        }
        fdt.property_array_u32("interrupts-extended", &irq_cells)?;

        fdt.end_node(imsic_node)?;
    }

    let aplic_name = format!("aplic@{:x}", super::layout::APLIC_START);
    let aplic_node = fdt.begin_node(&aplic_name)?;

    fdt.property_string("compatible", aia.aplic_compatibility())?;
    let reg_cells = aia.aplic_properties();
    fdt.property_array_u32("reg", &reg_cells)?;
    fdt.property_u32("#interrupt-cells", 2u32)?;
    fdt.property_null("interrupt-controller")?;

    // TODO num-sources should be equal to the IRQ allocated lines, and not randomly hardcoded.
    fdt.property_u32("riscv,num-sources", 10u32)?;
    fdt.property_u32("phandle", AIA_APLIC_PHANDLE)?;
    fdt.property_u32("msi-parent", AIA_IMSIC_PHANDLE)?;

    fdt.end_node(aplic_node)?;

    Ok(())
}

fn create_devices_node(
    fdt: &mut FdtWriter,
    devices_info: &HashMap<(DeviceType, String), MMIODeviceInfo>,
) -> Result<(), FdtError> {
    // Create one temp Vec to store all virtio devices
    let mut ordered_virtio_device: Vec<&MMIODeviceInfo> = Vec::new();

    for ((device_type, _device_id), info) in devices_info {
        match device_type {
            DeviceType::Serial => create_serial_node(fdt, info)?,
            DeviceType::Virtio(_) => {
                ordered_virtio_device.push(info);
            }
        }
    }

    // Sort out virtio devices by address from low to high and insert them into fdt table.
    ordered_virtio_device.sort_by_key(|a| a.addr);
    for ordered_device_info in ordered_virtio_device.drain(..) {
        create_virtio_node(fdt, ordered_device_info)?;
    }

    Ok(())
}

fn create_virtio_node(fdt: &mut FdtWriter, dev_info: &MMIODeviceInfo) -> Result<(), FdtError> {
    let virtio_mmio = fdt.begin_node(&format!("virtio_mmio@{:x}", dev_info.addr))?;
    let irq = [dev_info.irq.unwrap().into(), IRQ_TYPE_EDGE_RISING];

    fdt.property_string("compatible", "virtio,mmio")?;
    fdt.property_array_u64("reg", &[dev_info.addr, dev_info.len])?;
    fdt.property_array_u32("interrupts", &irq)?;
    fdt.property_u32("interrupt-parent", AIA_APLIC_PHANDLE)?;
    fdt.end_node(virtio_mmio)?;

    Ok(())
}

fn create_serial_node(fdt: &mut FdtWriter, dev_info: &MMIODeviceInfo) -> Result<(), FdtError> {
    let serial_reg_prop = [dev_info.addr, dev_info.len];
    let irq = [dev_info.irq.unwrap().into(), IRQ_TYPE_LEVEL_HIGH];

    let serial_name = format!("serial@{:x}", dev_info.addr);
    let serial_node = fdt.begin_node(&serial_name)?;
    fdt.property_string("compatible", "ns16550a")?;
    fdt.property_array_u64("reg", &serial_reg_prop)?;
    fdt.property_u32("clock-frequency", 3686400)?;
    fdt.property_u32("interrupt-parent", AIA_APLIC_PHANDLE)?;
    fdt.property_array_u32("interrupts", &irq)?;
    fdt.end_node(serial_node)?;

    Ok(())
}
