// Copyright © 2024, Institute of Software, CAS. All rights reserved.
// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;
use std::ffi::CString;
use std::fmt::Debug;

use vm_fdt::{Error as VmFdtError, FdtWriter, FdtWriterNode};
use vm_memory::GuestMemoryError;

use super::super::{DeviceType, InitrdConfig};
use super::aia::AIADevice;
use super::get_fdt_addr;
use crate::vstate::memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

const CPU_BASE_PHANDLE: u32 = 0x100;

const AIA_APLIC_PHANDLE: u32 = 2;
const AIA_IMSIC_PHANDLE: u32 = 3;
const CPU_INTC_BASE_PHANDLE: u32 = 4;
// Read the documentation specified when appending the root node to the FDT.
const ADDRESS_CELLS: u32 = 0x2;
const SIZE_CELLS: u32 = 0x2;

// From https://elixir.bootlin.com/linux/v6.10/source/include/dt-bindings/interrupt-controller/irq.h#L14
const IRQ_TYPE_EDGE_RISING: u32 = 1;
const IRQ_TYPE_LEVEL_HI: u32 = 4;

/// Trait for devices to be added to the Flattened Device Tree.
pub trait DeviceInfoForFDT {
    /// Returns the address where this device will be loaded.
    fn addr(&self) -> u64;
    /// Returns the associated interrupt for this device.
    fn irq(&self) -> u32;
    /// Returns the amount of memory that needs to be reserved for this device.
    fn length(&self) -> u64;
}

/// Errors thrown while configuring the Flattened Device Tree for riscv64.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum FdtError {
    /// Create FDT error: {0}
    CreateFdt(#[from] VmFdtError),
    /// Read cache info error: {0}
    ReadCacheInfo(String),
    /// Failure in writing FDT in memory.
    WriteFdtToMemory(#[from] GuestMemoryError),
}

/// Creates the flattened device tree for this riscv64 microVM.
pub fn create_fdt<T: DeviceInfoForFDT + Clone + Debug, S: std::hash::BuildHasher>(
    guest_mem: &GuestMemoryMmap,
    num_cpus: u32,
    cmdline: CString,
    device_info: &HashMap<(DeviceType, String), T, S>,
    aia_device: &AIADevice,
    initrd: &Option<InitrdConfig>,
) -> Result<Vec<u8>, FdtError> {
    // Allocate stuff necessary for storing the blob.
    let mut fdt_writer = FdtWriter::new()?;

    // For an explanation why these nodes were introduced in the blob take a look at
    // https://github.com/devicetree-org/devicetree-specification/releases/tag/v0.4
    // In chapter 3.

    // Header or the root node as per above mentioned documentation.
    let root = fdt_writer.begin_node("")?;
    fdt_writer.property_string("compatible", "linux,dummy-virt")?;
    // For info on #address-cells and size-cells resort to Table 3.1 Root Node
    // Properties
    fdt_writer.property_u32("#address-cells", ADDRESS_CELLS)?;
    fdt_writer.property_u32("#size-cells", SIZE_CELLS)?;
    create_cpu_nodes(&mut fdt_writer, num_cpus)?;
    create_memory_node(&mut fdt_writer, guest_mem)?;
    create_chosen_node(&mut fdt_writer, cmdline, initrd)?;
    create_aia_node(&mut fdt_writer, aia_device)?;
    create_devices_node(&mut fdt_writer, device_info)?;

    // End Header node.
    fdt_writer.end_node(root)?;

    // Allocate another buffer so we can format and then write fdt to guest.
    let fdt_final = fdt_writer.finish()?;

    // Write FDT to memory.
    let fdt_address = GuestAddress(get_fdt_addr(guest_mem));
    guest_mem.write_slice(fdt_final.as_slice(), fdt_address)?;
    Ok(fdt_final)
}

// Following are the auxiliary function for creating the different nodes that we append to our FDT.
fn create_cpu_nodes(fdt: &mut FdtWriter, num_cpus: u32) -> Result<(), FdtError> {
    // See https://elixir.bootlin.com/linux/v6.10/source/Documentation/devicetree/bindings/riscv/cpus.yaml
    let cpus = fdt.begin_node("cpus")?;
    // As per documentation, on RISC-V 64-bit systems value should be set to 1.
    fdt.property_u32("#address-cells", 0x01)?;
    fdt.property_u32("#size-cells", 0x0)?;
    // Retrieve CPU frequency from cpu timer regs
    let timebase_frequency: u32 = 369999;
    fdt.property_u32("timebase-frequency", timebase_frequency);

    for cpu_index in 0..num_cpus {
        let cpu = fdt.begin_node(&format!("cpu@{:x}", cpu_index))?;
        fdt.property_string("device_type", "cpu")?;
        fdt.property_string("compatible", "riscv")?;
        fdt.property_string("mmy-type", "sv48")?;
        fdt.property_string("riscv,isa", "rv64iafdcsu_smaia_ssaia")?;
        fdt.property_string("status", "okay")?;
        fdt.property_u64("reg", cpu_index as u64)?;
        fdt.property_u32("phandle", CPU_BASE_PHANDLE + cpu_index)?;
        fdt.end_node(cpu)?;

        // interrupt controller node
        let intc_node = fdt.begin_node("interrupt-controller")?;
        fdt.property_string("compatible", "riscv,cpu-intc")?;
        fdt.property_u32("#interrupt-cells", 1u32)?;
        fdt.property_array_u32("interrupt-controller", &Vec::new())?;
        fdt.property_u32("phandle", CPU_INTC_BASE_PHANDLE + cpu_index)?;
        fdt.end_node(intc_node)?;
    }
    fdt.end_node(cpus)?;

    Ok(())
}

fn create_memory_node(fdt: &mut FdtWriter, guest_mem: &GuestMemoryMmap) -> Result<(), FdtError> {
    unimplemented!()
}

fn create_chosen_node(
    fdt: &mut FdtWriter,
    cmdline: CString,
    initrd: &Option<InitrdConfig>,
) -> Result<(), FdtError> {
    unimplemented!()
}

fn create_aia_node(fdt: &mut FdtWriter, aia_device: &AIADevice) -> Result<(), FdtError> {
    unimplemented!()
}

fn create_virtio_node<T: DeviceInfoForFDT + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &T,
) -> Result<(), FdtError> {
    unimplemented!()
}

fn create_serial_node<T: DeviceInfoForFDT + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &T,
) -> Result<(), FdtError> {
    unimplemented!()
}

fn create_rtc_node<T: DeviceInfoForFDT + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &T,
) -> Result<(), FdtError> {
    unimplemented!()
}

fn create_devices_node<T: DeviceInfoForFDT + Clone + Debug, S: std::hash::BuildHasher>(
    fdt: &mut FdtWriter,
    dev_info: &HashMap<(DeviceType, String), T, S>,
) -> Result<(), FdtError> {
    unimplemented!()
}

#[cfg(test)]
mod tests {}
