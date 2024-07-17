// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::ffi::CString;
use std::fmt::Debug;

use vm_fdt::{Error as VmFdtError, FdtWriter, FdtWriterNode};
use vm_memory::GuestMemoryError;

use super::super::{DeviceType, InitrdConfig};
use super::cache_info::{read_cache_config, CacheEntry};
use super::get_fdt_addr;
use super::gic::GICDevice;
use crate::devices::acpi::vmgenid::{VmGenId, VMGENID_MEM_SIZE};
use crate::vstate::memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

// This is a value for uniquely identifying the FDT node declaring the interrupt controller.
const GIC_PHANDLE: u32 = 1;
// This is a value for uniquely identifying the FDT node containing the clock definition.
const CLOCK_PHANDLE: u32 = 2;
// You may be wondering why this big value?
// This phandle is used to uniquely identify the FDT nodes containing cache information. Each cpu
// can have a variable number of caches, some of these caches may be shared with other cpus.
// So, we start the indexing of the phandles used from a really big number and then subtract from
// it as we need more and more phandle for each cache representation.
const LAST_CACHE_PHANDLE: u32 = 4000;
// Read the documentation specified when appending the root node to the FDT.
const ADDRESS_CELLS: u32 = 0x2;
const SIZE_CELLS: u32 = 0x2;

// As per kvm tool and
// https://www.kernel.org/doc/Documentation/devicetree/bindings/interrupt-controller/arm%2Cgic.txt
// Look for "The 1st cell..."
const GIC_FDT_IRQ_TYPE_SPI: u32 = 0;
const GIC_FDT_IRQ_TYPE_PPI: u32 = 1;

// From https://elixir.bootlin.com/linux/v4.9.62/source/include/dt-bindings/interrupt-controller/irq.h#L17
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

/// Errors thrown while configuring the Flattened Device Tree for aarch64.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum FdtError {
    /// Create FDT error: {0}
    CreateFdt(#[from] VmFdtError),
    /// Read cache info error: {0}
    ReadCacheInfo(String),
    /// Failure in writing FDT in memory.
    WriteFdtToMemory(#[from] GuestMemoryError),
}

/// Creates the flattened device tree for this aarch64 microVM.
pub fn create_fdt<T: DeviceInfoForFDT + Clone + Debug, S: std::hash::BuildHasher>(
    guest_mem: &GuestMemoryMmap,
    vcpu_mpidr: Vec<u64>,
    cmdline: CString,
    device_info: &HashMap<(DeviceType, String), T, S>,
    gic_device: &GICDevice,
    vmgenid: &Option<VmGenId>,
    initrd: &Option<InitrdConfig>,
) -> Result<Vec<u8>, FdtError> {
    // Allocate stuff necessary for storing the blob.
    let mut fdt_writer = FdtWriter::new()?;

    // For an explanation why these nodes were introduced in the blob take a look at
    // https://github.com/torvalds/linux/blob/master/Documentation/devicetree/booting-without-of.txt#L845
    // Look for "Required nodes and properties".

    // Header or the root node as per above mentioned documentation.
    let root = fdt_writer.begin_node("")?;
    fdt_writer.property_string("compatible", "linux,dummy-virt")?;
    // For info on #address-cells and size-cells read "Note about cells and address representation"
    // from the above mentioned txt file.
    fdt_writer.property_u32("#address-cells", ADDRESS_CELLS)?;
    fdt_writer.property_u32("#size-cells", SIZE_CELLS)?;
    // This is not mandatory but we use it to point the root node to the node
    // containing description of the interrupt controller for this VM.
    fdt_writer.property_u32("interrupt-parent", GIC_PHANDLE)?;
    create_cpu_nodes(&mut fdt_writer, &vcpu_mpidr)?;
    create_memory_node(&mut fdt_writer, guest_mem)?;
    create_chosen_node(&mut fdt_writer, cmdline, initrd)?;
    create_gic_node(&mut fdt_writer, gic_device)?;
    create_timer_node(&mut fdt_writer)?;
    create_clock_node(&mut fdt_writer)?;
    create_psci_node(&mut fdt_writer)?;
    create_devices_node(&mut fdt_writer, device_info)?;
    create_vmgenid_node(&mut fdt_writer, vmgenid)?;

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
fn create_cpu_nodes(fdt: &mut FdtWriter, vcpu_mpidr: &[u64]) -> Result<(), FdtError> {
    // Since the L1 caches are not shareable among CPUs and they are direct attributes of the
    // cpu in the device tree, we process the L1 and non-L1 caches separately.
    // We use sysfs for extracting the cache information.
    let mut l1_caches: Vec<CacheEntry> = Vec::new();
    let mut non_l1_caches: Vec<CacheEntry> = Vec::new();
    // We use sysfs for extracting the cache information.
    read_cache_config(&mut l1_caches, &mut non_l1_caches)
        .map_err(|err| FdtError::ReadCacheInfo(err.to_string()))?;

    // See https://github.com/torvalds/linux/blob/master/Documentation/devicetree/bindings/arm/cpus.yaml.
    let cpus = fdt.begin_node("cpus")?;
    // As per documentation, on ARM v8 64-bit systems value should be set to 2.
    fdt.property_u32("#address-cells", 0x02)?;
    fdt.property_u32("#size-cells", 0x0)?;
    let num_cpus = vcpu_mpidr.len();
    for (cpu_index, mpidr) in vcpu_mpidr.iter().enumerate() {
        let cpu = fdt.begin_node(&format!("cpu@{:x}", cpu_index))?;
        fdt.property_string("device_type", "cpu")?;
        fdt.property_string("compatible", "arm,arm-v8")?;
        // The power state coordination interface (PSCI) needs to be enabled for
        // all vcpus.
        fdt.property_string("enable-method", "psci")?;
        // Set the field to first 24 bits of the MPIDR - Multiprocessor Affinity Register.
        // See http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0488c/BABHBJCI.html.
        fdt.property_u64("reg", mpidr & 0x7FFFFF)?;

        for cache in l1_caches.iter() {
            // Please check out
            // https://github.com/devicetree-org/devicetree-specification/releases/download/v0.3/devicetree-specification-v0.3.pdf,
            // section 3.8.
            if let Some(size) = cache.size_ {
                fdt.property_u32(cache.type_.of_cache_size(), size)?;
            }
            if let Some(line_size) = cache.line_size {
                fdt.property_u32(cache.type_.of_cache_line_size(), u32::from(line_size))?;
            }
            if let Some(number_of_sets) = cache.number_of_sets {
                fdt.property_u32(cache.type_.of_cache_sets(), u32::from(number_of_sets))?;
            }
        }

        // Some of the non-l1 caches can be shared amongst CPUs. You can see an example of a shared
        // scenario in https://github.com/devicetree-org/devicetree-specification/releases/download/v0.3/devicetree-specification-v0.3.pdf,
        // 3.8.1 Example.
        let mut prev_level = 1;
        let mut cache_node: Option<FdtWriterNode> = None;
        for cache in non_l1_caches.iter() {
            // We append the next-level-cache node (the node that specifies the cache hierarchy)
            // in the next iteration. For example,
            // L2-cache {
            //      cache-size = <0x8000> ----> first iteration
            //      next-level-cache = <&l3-cache> ---> second iteration
            // }
            // The cpus per unit cannot be 0 since the sysfs will also include the current cpu
            // in the list of shared cpus so it needs to be at least 1. Firecracker trusts the host.
            // The operation is safe since we already checked when creating cache attributes that
            // cpus_per_unit is not 0 (.e look for mask_str2bit_count function).
            let cache_phandle = LAST_CACHE_PHANDLE
                - u32::try_from(
                    num_cpus * (cache.level - 2) as usize
                        + cpu_index / cache.cpus_per_unit as usize,
                )
                .unwrap(); // Safe because the number of CPUs is bounded

            if prev_level != cache.level {
                fdt.property_u32("next-level-cache", cache_phandle)?;
                if prev_level > 1 && cache_node.is_some() {
                    fdt.end_node(cache_node.take().unwrap())?;
                }
            }

            if cpu_index % cache.cpus_per_unit as usize == 0 {
                cache_node = Some(fdt.begin_node(&format!(
                    "l{}-{}-cache",
                    cache.level,
                    cpu_index / cache.cpus_per_unit as usize
                ))?);
                fdt.property_u32("phandle", cache_phandle)?;
                fdt.property_string("compatible", "cache")?;
                fdt.property_u32("cache-level", u32::from(cache.level))?;
                if let Some(size) = cache.size_ {
                    fdt.property_u32(cache.type_.of_cache_size(), size)?;
                }
                if let Some(line_size) = cache.line_size {
                    fdt.property_u32(cache.type_.of_cache_line_size(), u32::from(line_size))?;
                }
                if let Some(number_of_sets) = cache.number_of_sets {
                    fdt.property_u32(cache.type_.of_cache_sets(), u32::from(number_of_sets))?;
                }
                if let Some(cache_type) = cache.type_.of_cache_type() {
                    fdt.property_null(cache_type)?;
                }
                prev_level = cache.level;
            }
        }
        if let Some(node) = cache_node {
            fdt.end_node(node)?;
        }

        fdt.end_node(cpu)?;
    }
    fdt.end_node(cpus)?;

    Ok(())
}

fn create_memory_node(fdt: &mut FdtWriter, guest_mem: &GuestMemoryMmap) -> Result<(), FdtError> {
    // See https://github.com/torvalds/linux/blob/master/Documentation/devicetree/booting-without-of.txt#L960
    // for an explanation of this.

    // On ARM we reserve some memory so that it can be utilized for devices like VMGenID to send
    // data to kernel drivers. The range of this memory is:
    //
    // [layout::DRAM_MEM_START, layout::DRAM_MEM_START + layout::SYSTEM_MEM_SIZE)
    //
    // The reason we do this is that Linux does not allow remapping system memory. However, without
    // remap, kernel drivers cannot get virtual addresses to read data from device memory. Leaving
    // this memory region out allows Linux kernel modules to remap and thus read this region.
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

fn create_chosen_node(
    fdt: &mut FdtWriter,
    cmdline: CString,
    initrd: &Option<InitrdConfig>,
) -> Result<(), FdtError> {
    let chosen = fdt.begin_node("chosen")?;
    // Workaround to be able to reuse an existing property_*() method; in property_string() method,
    // the cmdline is reconverted to a CString to be written in memory as a null terminated string.
    let cmdline_string = cmdline
        .into_string()
        .map_err(|_| vm_fdt::Error::InvalidString)?;
    fdt.property_string("bootargs", cmdline_string.as_str())?;

    if let Some(initrd_config) = initrd {
        fdt.property_u64("linux,initrd-start", initrd_config.address.raw_value())?;
        fdt.property_u64(
            "linux,initrd-end",
            initrd_config.address.raw_value() + initrd_config.size as u64,
        )?;
    }

    fdt.end_node(chosen)?;

    Ok(())
}

fn create_vmgenid_node(fdt: &mut FdtWriter, vmgenid: &Option<VmGenId>) -> Result<(), FdtError> {
    if let Some(vmgenid_info) = vmgenid {
        let vmgenid = fdt.begin_node("vmgenid")?;
        fdt.property_string("compatible", "microsoft,vmgenid")?;
        fdt.property_array_u64("reg", &[vmgenid_info.guest_address.0, VMGENID_MEM_SIZE])?;
        fdt.property_array_u32(
            "interrupts",
            &[GIC_FDT_IRQ_TYPE_SPI, vmgenid_info.gsi, IRQ_TYPE_EDGE_RISING],
        )?;
        fdt.end_node(vmgenid)?;
    }
    Ok(())
}

fn create_gic_node(fdt: &mut FdtWriter, gic_device: &GICDevice) -> Result<(), FdtError> {
    let interrupt = fdt.begin_node("intc")?;
    fdt.property_string("compatible", gic_device.fdt_compatibility())?;
    fdt.property_null("interrupt-controller")?;
    // "interrupt-cells" field specifies the number of cells needed to encode an
    // interrupt source. The type shall be a <u32> and the value shall be 3 if no PPI affinity
    // description is required.
    fdt.property_u32("#interrupt-cells", 3)?;
    fdt.property_array_u64("reg", gic_device.device_properties())?;
    fdt.property_u32("phandle", GIC_PHANDLE)?;
    fdt.property_u32("#address-cells", 2)?;
    fdt.property_u32("#size-cells", 2)?;
    fdt.property_null("ranges")?;

    let gic_intr = [
        GIC_FDT_IRQ_TYPE_PPI,
        gic_device.fdt_maint_irq(),
        IRQ_TYPE_LEVEL_HI,
    ];

    fdt.property_array_u32("interrupts", &gic_intr)?;
    fdt.end_node(interrupt)?;

    Ok(())
}

fn create_clock_node(fdt: &mut FdtWriter) -> Result<(), FdtError> {
    // The Advanced Peripheral Bus (APB) is part of the Advanced Microcontroller Bus Architecture
    // (AMBA) protocol family. It defines a low-cost interface that is optimized for minimal power
    // consumption and reduced interface complexity.
    // PCLK is the clock source and this node defines exactly the clock for the APB.
    let clock = fdt.begin_node("apb-pclk")?;
    fdt.property_string("compatible", "fixed-clock")?;
    fdt.property_u32("#clock-cells", 0x0)?;
    fdt.property_u32("clock-frequency", 24_000_000)?;
    fdt.property_string("clock-output-names", "clk24mhz")?;
    fdt.property_u32("phandle", CLOCK_PHANDLE)?;
    fdt.end_node(clock)?;
    Ok(())
}

fn create_timer_node(fdt: &mut FdtWriter) -> Result<(), FdtError> {
    // See
    // https://github.com/torvalds/linux/blob/master/Documentation/devicetree/bindings/interrupt-controller/arch_timer.txt
    // These are fixed interrupt numbers for the timer device.
    let irqs = [13, 14, 11, 10];
    let compatible = "arm,armv8-timer";

    let mut timer_reg_cells: Vec<u32> = Vec::new();
    for &irq in irqs.iter() {
        timer_reg_cells.push(GIC_FDT_IRQ_TYPE_PPI);
        timer_reg_cells.push(irq);
        timer_reg_cells.push(IRQ_TYPE_LEVEL_HI);
    }

    let timer = fdt.begin_node("timer")?;
    fdt.property_string("compatible", compatible)?;
    fdt.property_null("always-on")?;
    fdt.property_array_u32("interrupts", &timer_reg_cells)?;
    fdt.end_node(timer)?;
    Ok(())
}

fn create_psci_node(fdt: &mut FdtWriter) -> Result<(), FdtError> {
    let compatible = "arm,psci-0.2";

    let psci = fdt.begin_node("psci")?;
    fdt.property_string("compatible", compatible)?;
    // Two methods available: hvc and smc.
    // As per documentation, PSCI calls between a guest and hypervisor may use the HVC conduit
    // instead of SMC. So, since we are using kvm, we need to use hvc.
    fdt.property_string("method", "hvc")?;
    fdt.end_node(psci)?;

    Ok(())
}

fn create_virtio_node<T: DeviceInfoForFDT + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &T,
) -> Result<(), FdtError> {
    let virtio_mmio = fdt.begin_node(&format!("virtio_mmio@{:x}", dev_info.addr()))?;

    fdt.property_string("compatible", "virtio,mmio")?;
    fdt.property_array_u64("reg", &[dev_info.addr(), dev_info.length()])?;
    fdt.property_array_u32(
        "interrupts",
        &[GIC_FDT_IRQ_TYPE_SPI, dev_info.irq(), IRQ_TYPE_EDGE_RISING],
    )?;
    fdt.property_u32("interrupt-parent", GIC_PHANDLE)?;
    fdt.end_node(virtio_mmio)?;

    Ok(())
}

fn create_serial_node<T: DeviceInfoForFDT + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &T,
) -> Result<(), FdtError> {
    let serial = fdt.begin_node(&format!("uart@{:x}", dev_info.addr()))?;

    fdt.property_string("compatible", "ns16550a")?;
    fdt.property_array_u64("reg", &[dev_info.addr(), dev_info.length()])?;
    fdt.property_u32("clocks", CLOCK_PHANDLE)?;
    fdt.property_string("clock-names", "apb_pclk")?;
    fdt.property_array_u32(
        "interrupts",
        &[GIC_FDT_IRQ_TYPE_SPI, dev_info.irq(), IRQ_TYPE_EDGE_RISING],
    )?;
    fdt.end_node(serial)?;

    Ok(())
}

fn create_rtc_node<T: DeviceInfoForFDT + Clone + Debug>(
    fdt: &mut FdtWriter,
    dev_info: &T,
) -> Result<(), FdtError> {
    // Driver requirements:
    // https://elixir.bootlin.com/linux/latest/source/Documentation/devicetree/bindings/rtc/arm,pl031.yaml
    // We do not offer the `interrupt` property because the device
    // does not implement interrupt support.
    let compatible = b"arm,pl031\0arm,primecell\0";

    let rtc = fdt.begin_node(&format!("rtc@{:x}", dev_info.addr()))?;
    fdt.property("compatible", compatible)?;
    fdt.property_array_u64("reg", &[dev_info.addr(), dev_info.length()])?;
    fdt.property_u32("clocks", CLOCK_PHANDLE)?;
    fdt.property_string("clock-names", "apb_pclk")?;
    fdt.end_node(rtc)?;

    Ok(())
}

fn create_devices_node<T: DeviceInfoForFDT + Clone + Debug, S: std::hash::BuildHasher>(
    fdt: &mut FdtWriter,
    dev_info: &HashMap<(DeviceType, String), T, S>,
) -> Result<(), FdtError> {
    // Create one temp Vec to store all virtio devices
    let mut ordered_virtio_device: Vec<&T> = Vec::new();

    for ((device_type, _device_id), info) in dev_info {
        match device_type {
            DeviceType::BootTimer => (), // since it's not a real device
            DeviceType::Rtc => create_rtc_node(fdt, info)?,
            DeviceType::Serial => create_serial_node(fdt, info)?,
            DeviceType::Virtio(_) => {
                ordered_virtio_device.push(info);
            }
        }
    }

    // Sort out virtio devices by address from low to high and insert them into fdt table.
    ordered_virtio_device.sort_by_key(|&a| a.addr());
    for ordered_device_info in ordered_virtio_device.drain(..) {
        create_virtio_node(fdt, ordered_device_info)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use kvm_ioctls::Kvm;

    use super::*;
    use crate::arch::aarch64::gic::create_gic;
    use crate::arch::aarch64::layout;
    use crate::device_manager::resources::ResourceAllocator;
    use crate::utilities::test_utils::arch_mem;

    const LEN: u64 = 4096;

    #[derive(Clone, Debug)]
    pub struct MMIODeviceInfo {
        addr: u64,
        irq: u32,
    }

    impl DeviceInfoForFDT for MMIODeviceInfo {
        fn addr(&self) -> u64 {
            self.addr
        }
        fn irq(&self) -> u32 {
            self.irq
        }
        fn length(&self) -> u64 {
            LEN
        }
    }
    // The `load` function from the `device_tree` will mistakenly check the actual size
    // of the buffer with the allocated size. This works around that.
    fn set_size(buf: &mut [u8], pos: usize, val: u32) {
        buf[pos] = ((val >> 24) & 0xff) as u8;
        buf[pos + 1] = ((val >> 16) & 0xff) as u8;
        buf[pos + 2] = ((val >> 8) & 0xff) as u8;
        buf[pos + 3] = (val & 0xff) as u8;
    }

    #[test]
    fn test_create_fdt_with_devices() {
        let mem = arch_mem(layout::FDT_MAX_SIZE + 0x1000);

        let dev_info: HashMap<(DeviceType, std::string::String), MMIODeviceInfo> = [
            (
                (DeviceType::Serial, DeviceType::Serial.to_string()),
                MMIODeviceInfo { addr: 0x00, irq: 1 },
            ),
            (
                (DeviceType::Virtio(1), "virtio".to_string()),
                MMIODeviceInfo { addr: LEN, irq: 2 },
            ),
            (
                (DeviceType::Rtc, "rtc".to_string()),
                MMIODeviceInfo {
                    addr: 2 * LEN,
                    irq: 3,
                },
            ),
        ]
        .iter()
        .cloned()
        .collect();
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let gic = create_gic(&vm, 1, None).unwrap();
        create_fdt(
            &mem,
            vec![0],
            CString::new("console=tty0").unwrap(),
            &dev_info,
            &gic,
            &None,
            &None,
        )
        .unwrap();
    }

    #[test]
    fn test_create_fdt_with_vmgenid() {
        let mem = arch_mem(layout::FDT_MAX_SIZE + 0x1000);
        let mut resource_allocator = ResourceAllocator::new().unwrap();
        let vmgenid = VmGenId::new(&mem, &mut resource_allocator).unwrap();
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let gic = create_gic(&vm, 1, None).unwrap();
        create_fdt(
            &mem,
            vec![0],
            CString::new("console=tty0").unwrap(),
            &HashMap::<(DeviceType, std::string::String), MMIODeviceInfo>::new(),
            &gic,
            &Some(vmgenid),
            &None,
        )
        .unwrap();
    }

    #[test]
    fn test_create_fdt() {
        let mem = arch_mem(layout::FDT_MAX_SIZE + 0x1000);
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let gic = create_gic(&vm, 1, None).unwrap();

        let saved_dtb_bytes = match gic.fdt_compatibility() {
            "arm,gic-v3" => include_bytes!("output_GICv3.dtb"),
            "arm,gic-400" => include_bytes!("output_GICv2.dtb"),
            _ => panic!("Unexpected gic version!"),
        };

        let current_dtb_bytes = create_fdt(
            &mem,
            vec![0],
            CString::new("console=tty0").unwrap(),
            &HashMap::<(DeviceType, std::string::String), MMIODeviceInfo>::new(),
            &gic,
            &None,
            &None,
        )
        .unwrap();

        // Use this code when wanting to generate a new DTB sample.
        // {
        // use std::fs;
        // use std::io::Write;
        // use std::path::PathBuf;
        // let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        // let dtb_path = match gic.fdt_compatibility() {
        // "arm,gic-v3" => "output_GICv3.dtb",
        // "arm,gic-400" => ("output_GICv2.dtb"),
        // _ => panic!("Unexpected gic version!"),
        // };
        // let mut output = fs::OpenOptions::new()
        // .write(true)
        // .create(true)
        // .open(path.join(format!("src/arch/aarch64/{}", dtb_path)))
        // .unwrap();
        // output.write_all(&current_dtb_bytes).unwrap();
        // }

        let pos = 4;
        let val = u32::try_from(layout::FDT_MAX_SIZE).unwrap();
        let mut buf = vec![];
        buf.extend_from_slice(saved_dtb_bytes);

        set_size(&mut buf, pos, val);
        let original_fdt = device_tree::DeviceTree::load(&buf).unwrap();
        let generated_fdt = device_tree::DeviceTree::load(&current_dtb_bytes).unwrap();
        assert_eq!(
            format!("{:?}", original_fdt),
            format!("{:?}", generated_fdt)
        );
    }

    #[test]
    fn test_create_fdt_with_initrd() {
        let mem = arch_mem(layout::FDT_MAX_SIZE + 0x1000);
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let gic = create_gic(&vm, 1, None).unwrap();

        let saved_dtb_bytes = match gic.fdt_compatibility() {
            "arm,gic-v3" => include_bytes!("output_initrd_GICv3.dtb"),
            "arm,gic-400" => include_bytes!("output_initrd_GICv2.dtb"),
            _ => panic!("Unexpected gic version!"),
        };

        let initrd = InitrdConfig {
            address: GuestAddress(0x1000_0000),
            size: 0x1000,
        };

        let current_dtb_bytes = create_fdt(
            &mem,
            vec![0],
            CString::new("console=tty0").unwrap(),
            &HashMap::<(DeviceType, std::string::String), MMIODeviceInfo>::new(),
            &gic,
            &None,
            &Some(initrd),
        )
        .unwrap();

        // Use this code when wanting to generate a new DTB sample.
        // {
        // use std::fs;
        // use std::io::Write;
        // use std::path::PathBuf;
        // let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        // let dtb_path = match gic.fdt_compatibility() {
        // "arm,gic-v3" => "output_initrd_GICv3.dtb",
        // "arm,gic-400" => ("output_initrd_GICv2.dtb"),
        // _ => panic!("Unexpected gic version!"),
        // };
        // let mut output = fs::OpenOptions::new()
        // .write(true)
        // .create(true)
        // .open(path.join(format!("src/arch/aarch64/{}", dtb_path)))
        // .unwrap();
        // output.write_all(&current_dtb_bytes).unwrap();
        // }

        let pos = 4;
        let val = u32::try_from(layout::FDT_MAX_SIZE).unwrap();
        let mut buf = vec![];
        buf.extend_from_slice(saved_dtb_bytes);

        set_size(&mut buf, pos, val);
        let original_fdt = device_tree::DeviceTree::load(&buf).unwrap();
        let generated_fdt = device_tree::DeviceTree::load(&current_dtb_bytes).unwrap();
        assert_eq!(
            format!("{:?}", original_fdt),
            format!("{:?}", generated_fdt)
        );
    }
}
