// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::mem::{self, size_of};

use libc::c_char;
use vm_allocator::AllocPolicy;
use vm_memory::GuestMemoryBackend;

use crate::arch::GSI_LEGACY_END;
use crate::arch::x86_64::generated::mpspec;
use crate::logger::debug;
use crate::vstate::memory::{Address, ByteValued, Bytes, GuestAddress, GuestMemoryMmap};
use crate::vstate::resources::ResourceAllocator;

// These `mpspec` wrapper types are only data, reading them from data is a safe initialization.
// SAFETY: POD
unsafe impl ByteValued for mpspec::mpc_bus {}
// SAFETY: POD
unsafe impl ByteValued for mpspec::mpc_cpu {}
// SAFETY: POD
unsafe impl ByteValued for mpspec::mpc_intsrc {}
// SAFETY: POD
unsafe impl ByteValued for mpspec::mpc_ioapic {}
// SAFETY: POD
unsafe impl ByteValued for mpspec::mpc_table {}
// SAFETY: POD
unsafe impl ByteValued for mpspec::mpc_lintsrc {}
// SAFETY: POD
unsafe impl ByteValued for mpspec::mpf_intel {}

#[derive(Debug, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
pub enum MptableError {
    /// There was too little guest memory to store the entire MP table.
    NotEnoughMemory,
    /// The MP table has too little address space to be stored.
    AddressOverflow,
    /// Failure while zeroing out the memory for the MP table.
    Clear,
    /// Number of CPUs exceeds the maximum supported CPUs
    TooManyCpus,
    /// Number of IRQs exceeds the maximum supported IRQs
    TooManyIrqs,
    /// Failure to write the MP floating pointer.
    WriteMpfIntel,
    /// Failure to write MP CPU entry.
    WriteMpcCpu,
    /// Failure to write MP ioapic entry.
    WriteMpcIoapic,
    /// Failure to write MP bus entry.
    WriteMpcBus,
    /// Failure to write MP interrupt source entry.
    WriteMpcIntsrc,
    /// Failure to write MP local interrupt source entry.
    WriteMpcLintsrc,
    /// Failure to write MP table header.
    WriteMpcTable,
    /// Failure to allocate memory for MPTable
    AllocateMemory(#[from] vm_allocator::Error),
    /// Invalid PCI interrupt route from slot {0} to IOAPIC input {1}
    InvalidPciIntxRoute(u8, u32),
}

// With APIC/xAPIC, there are only 255 APIC IDs available. And IOAPIC occupies
// one APIC ID, so only 254 CPUs at maximum may be supported. Actually it's
// a large number for FC usecases.
pub const MAX_SUPPORTED_CPUS: u8 = 254;

// Convenience macro for making arrays of diverse character types.
macro_rules! char_array {
    ($t:ty; $( $c:expr ),*) => ( [ $( $c as $t ),* ] )
}

// Most of these variables are sourced from the Intel MP Spec 1.4.
const SMP_MAGIC_IDENT: [c_char; 4] = char_array!(c_char; '_', 'M', 'P', '_');
const MPC_SIGNATURE: [c_char; 4] = char_array!(c_char; 'P', 'C', 'M', 'P');
const MPC_SPEC: i8 = 4;
const MPC_OEM: [c_char; 8] = char_array!(c_char; 'F', 'C', ' ', ' ', ' ', ' ', ' ', ' ');
const MPC_PRODUCT_ID: [c_char; 12] = ['0' as c_char; 12];
const BUS_TYPE_ISA: [u8; 6] = *b"ISA   ";
const BUS_TYPE_PCI: [u8; 6] = *b"PCI   ";
/// MP bus id of the PCI bus. Linux looks PCI interrupts up by PCI bus number in the MP table
/// (`IO_APIC_get_PCI_irq_vector`), so it must be the PCI bus number: 0.
const PCI_BUS_ID: u8 = 0;
const IO_APIC_DEFAULT_PHYS_BASE: u32 = 0xfec0_0000; // source: linux/arch/x86/include/asm/apicdef.h
const APIC_DEFAULT_PHYS_BASE: u32 = 0xfee0_0000; // source: linux/arch/x86/include/asm/apicdef.h
const APIC_VERSION: u8 = 0x14;
const CPU_STEPPING: u32 = 0x600;
const CPU_FEATURE_APIC: u32 = 0x200;
const CPU_FEATURE_FPU: u32 = 0x001;

fn compute_checksum<T: ByteValued>(v: &T) -> u8 {
    let mut checksum: u8 = 0;
    for i in v.as_slice() {
        checksum = checksum.wrapping_add(*i);
    }
    checksum
}

fn mpf_intel_compute_checksum(v: &mpspec::mpf_intel) -> u8 {
    let checksum = compute_checksum(v).wrapping_sub(v.checksum);
    (!checksum).wrapping_add(1)
}

/// The IOAPIC inputs PCI interrupts are routed to.
fn routed_pins(pci_intx_routes: &[(u8, u32)]) -> BTreeSet<u32> {
    pci_intx_routes.iter().map(|&(_, gsi)| gsi).collect()
}

fn compute_mp_size(num_cpus: u8, pci_intx_routes: &[(u8, u32)]) -> usize {
    let buses = if pci_intx_routes.is_empty() { 1 } else { 2 };
    let isa_irqs = GSI_LEGACY_END as usize + 1 - routed_pins(pci_intx_routes).len();
    mem::size_of::<mpspec::mpf_intel>()
        + mem::size_of::<mpspec::mpc_table>()
        + mem::size_of::<mpspec::mpc_cpu>() * (num_cpus as usize)
        + mem::size_of::<mpspec::mpc_ioapic>()
        + mem::size_of::<mpspec::mpc_bus>() * buses
        + mem::size_of::<mpspec::mpc_intsrc>() * (isa_irqs + pci_intx_routes.len())
        + mem::size_of::<mpspec::mpc_lintsrc>() * 2
}

/// Performs setup of the MP table for the given `num_cpus`, with the INTA pins of the PCI slots
/// in `pci_intx_routes` routed to the given IOAPIC inputs, as `(slot, IOAPIC input)`.
pub fn setup_mptable(
    mem: &GuestMemoryMmap,
    resource_allocator: &mut ResourceAllocator,
    num_cpus: u8,
    pci_intx_routes: &[(u8, u32)],
) -> Result<(), MptableError> {
    if num_cpus > MAX_SUPPORTED_CPUS {
        return Err(MptableError::TooManyCpus);
    }
    if let Some(&(slot, gsi)) = pci_intx_routes
        .iter()
        .find(|&&(slot, gsi)| slot >= 32 || gsi > GSI_LEGACY_END)
    {
        return Err(MptableError::InvalidPciIntxRoute(slot, gsi));
    }
    let routed_pins = routed_pins(pci_intx_routes);
    // With PCI interrupts, the PCI bus takes MP bus id 0 (see `PCI_BUS_ID`) and the ISA bus id 1.
    let isa_bus_id: u8 = if pci_intx_routes.is_empty() { 0 } else { 1 };

    let mp_size = compute_mp_size(num_cpus, pci_intx_routes);
    let mptable_addr = resource_allocator
        .system_memory
        .allocate(mp_size as u64, 1, AllocPolicy::FirstMatch)?
        .start();
    debug!(
        "mptable: Allocated {mp_size} bytes for MPTable {num_cpus} vCPUs at address {:#010x}",
        mptable_addr
    );

    // Used to keep track of the next base pointer into the MP table.
    let mut base_mp = GuestAddress(mptable_addr);
    let mut mp_num_entries: u16 = 0;

    let mut checksum: u8 = 0;
    let ioapicid: u8 = num_cpus + 1;

    // The checked_add here ensures the all of the following base_mp.unchecked_add's will be without
    // overflow.
    if let Some(end_mp) = base_mp.checked_add((mp_size - 1) as u64) {
        if !mem.address_in_range(end_mp) {
            return Err(MptableError::NotEnoughMemory);
        }
    } else {
        return Err(MptableError::AddressOverflow);
    }

    mem.write_slice(&vec![0; mp_size], base_mp)
        .map_err(|_| MptableError::Clear)?;

    {
        let size = mem::size_of::<mpspec::mpf_intel>() as u64;
        let mut mpf_intel = mpspec::mpf_intel {
            signature: SMP_MAGIC_IDENT,
            physptr: u32::try_from(base_mp.raw_value() + size).unwrap(),
            length: 1,
            specification: 4,
            ..mpspec::mpf_intel::default()
        };
        mpf_intel.checksum = mpf_intel_compute_checksum(&mpf_intel);
        mem.write_obj(mpf_intel, base_mp)
            .map_err(|_| MptableError::WriteMpfIntel)?;
        base_mp = base_mp.unchecked_add(size);
        mp_num_entries += 1;
    }

    // We set the location of the mpc_table here but we can't fill it out until we have the length
    // of the entire table later.
    let table_base = base_mp;
    base_mp = base_mp.unchecked_add(mem::size_of::<mpspec::mpc_table>() as u64);

    {
        let size = mem::size_of::<mpspec::mpc_cpu>() as u64;
        for cpu_id in 0..num_cpus {
            let mpc_cpu = mpspec::mpc_cpu {
                type_: mpspec::MP_PROCESSOR.try_into().unwrap(),
                apicid: cpu_id,
                apicver: APIC_VERSION,
                cpuflag: u8::try_from(mpspec::CPU_ENABLED).unwrap()
                    | if cpu_id == 0 {
                        u8::try_from(mpspec::CPU_BOOTPROCESSOR).unwrap()
                    } else {
                        0
                    },
                cpufeature: CPU_STEPPING,
                featureflag: CPU_FEATURE_APIC | CPU_FEATURE_FPU,
                ..Default::default()
            };
            mem.write_obj(mpc_cpu, base_mp)
                .map_err(|_| MptableError::WriteMpcCpu)?;
            base_mp = base_mp.unchecked_add(size);
            checksum = checksum.wrapping_add(compute_checksum(&mpc_cpu));
            mp_num_entries += 1;
        }
    }
    let mut buses = vec![(isa_bus_id, BUS_TYPE_ISA)];
    if !pci_intx_routes.is_empty() {
        buses.insert(0, (PCI_BUS_ID, BUS_TYPE_PCI));
    }
    for (busid, bustype) in buses {
        let size = mem::size_of::<mpspec::mpc_bus>() as u64;
        let mpc_bus = mpspec::mpc_bus {
            type_: mpspec::MP_BUS.try_into().unwrap(),
            busid,
            bustype,
        };
        mem.write_obj(mpc_bus, base_mp)
            .map_err(|_| MptableError::WriteMpcBus)?;
        base_mp = base_mp.unchecked_add(size);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_bus));
        mp_num_entries += 1;
    }
    {
        let size = mem::size_of::<mpspec::mpc_ioapic>() as u64;
        let mpc_ioapic = mpspec::mpc_ioapic {
            type_: mpspec::MP_IOAPIC.try_into().unwrap(),
            apicid: ioapicid,
            apicver: APIC_VERSION,
            flags: mpspec::MPC_APIC_USABLE.try_into().unwrap(),
            apicaddr: IO_APIC_DEFAULT_PHYS_BASE,
        };
        mem.write_obj(mpc_ioapic, base_mp)
            .map_err(|_| MptableError::WriteMpcIoapic)?;
        base_mp = base_mp.unchecked_add(size);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_ioapic));
        mp_num_entries += 1;
    }
    // Per kvm_setup_default_irq_routing() in kernel. The IOAPIC inputs PCI interrupts are routed
    // to are only described by their PCI entries.
    let isa_irqs = (0..=u8::try_from(GSI_LEGACY_END).map_err(|_| MptableError::TooManyIrqs)?)
        .filter(|&irq| !routed_pins.contains(&u32::from(irq)))
        .map(|irq| (isa_bus_id, irq, irq));
    // A PCI interrupt source is INTA (0) of a slot: `(slot << 2) | pin`. Its flags conform to the
    // PCI bus: level-triggered and active low.
    let pci_irqs = pci_intx_routes.iter().map(|&(slot, gsi)| {
        (
            PCI_BUS_ID,
            slot << 2,
            u8::try_from(gsi).expect("checked against GSI_LEGACY_END"),
        )
    });
    for (srcbus, srcbusirq, dstirq) in isa_irqs.chain(pci_irqs) {
        let size = mem::size_of::<mpspec::mpc_intsrc>() as u64;
        let mpc_intsrc = mpspec::mpc_intsrc {
            type_: mpspec::MP_INTSRC.try_into().unwrap(),
            irqtype: mpspec::mp_irq_source_types::mp_INT.try_into().unwrap(),
            irqflag: mpspec::MP_IRQPOL_DEFAULT.try_into().unwrap(),
            srcbus,
            srcbusirq,
            dstapic: ioapicid,
            dstirq,
        };
        mem.write_obj(mpc_intsrc, base_mp)
            .map_err(|_| MptableError::WriteMpcIntsrc)?;
        base_mp = base_mp.unchecked_add(size);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_intsrc));
        mp_num_entries += 1;
    }
    {
        let size = mem::size_of::<mpspec::mpc_lintsrc>() as u64;
        let mpc_lintsrc = mpspec::mpc_lintsrc {
            type_: mpspec::MP_LINTSRC.try_into().unwrap(),
            irqtype: mpspec::mp_irq_source_types::mp_ExtINT.try_into().unwrap(),
            irqflag: mpspec::MP_IRQPOL_DEFAULT.try_into().unwrap(),
            srcbusid: isa_bus_id,
            srcbusirq: 0,
            destapic: 0,
            destapiclint: 0,
        };
        mem.write_obj(mpc_lintsrc, base_mp)
            .map_err(|_| MptableError::WriteMpcLintsrc)?;
        base_mp = base_mp.unchecked_add(size);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_lintsrc));
        mp_num_entries += 1;
    }
    {
        let size = mem::size_of::<mpspec::mpc_lintsrc>() as u64;
        let mpc_lintsrc = mpspec::mpc_lintsrc {
            type_: mpspec::MP_LINTSRC.try_into().unwrap(),
            irqtype: mpspec::mp_irq_source_types::mp_NMI.try_into().unwrap(),
            irqflag: mpspec::MP_IRQPOL_DEFAULT.try_into().unwrap(),
            srcbusid: isa_bus_id,
            srcbusirq: 0,
            destapic: 0xFF,
            destapiclint: 1,
        };
        mem.write_obj(mpc_lintsrc, base_mp)
            .map_err(|_| MptableError::WriteMpcLintsrc)?;
        base_mp = base_mp.unchecked_add(size);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_lintsrc));
        mp_num_entries += 1;
    }

    // At this point we know the size of the mp_table.
    let table_end = base_mp;

    {
        let mut mpc_table = mpspec::mpc_table {
            signature: MPC_SIGNATURE,
            // it's safe to use unchecked_offset_from because
            // table_end > table_base
            length: table_end
                .unchecked_offset_from(table_base)
                .try_into()
                .unwrap(),
            spec: MPC_SPEC,
            oem: MPC_OEM,
            oemcount: mp_num_entries,
            productid: MPC_PRODUCT_ID,
            lapic: APIC_DEFAULT_PHYS_BASE,
            ..Default::default()
        };
        debug_assert_eq!(
            mpc_table.length as usize + size_of::<mpspec::mpf_intel>(),
            mp_size
        );
        checksum = checksum.wrapping_add(compute_checksum(&mpc_table));
        #[allow(clippy::cast_possible_wrap)]
        let checksum_final = (!checksum).wrapping_add(1) as i8;
        mpc_table.checksum = checksum_final;
        mem.write_obj(mpc_table, table_base)
            .map_err(|_| MptableError::WriteMpcTable)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::arch::SYSTEM_MEM_START;
    use crate::test_utils::single_region_mem_at;
    use crate::vstate::memory::Bytes;

    fn table_entry_size(type_: u8) -> usize {
        match u32::from(type_) {
            mpspec::MP_PROCESSOR => mem::size_of::<mpspec::mpc_cpu>(),
            mpspec::MP_BUS => mem::size_of::<mpspec::mpc_bus>(),
            mpspec::MP_IOAPIC => mem::size_of::<mpspec::mpc_ioapic>(),
            mpspec::MP_INTSRC => mem::size_of::<mpspec::mpc_intsrc>(),
            mpspec::MP_LINTSRC => mem::size_of::<mpspec::mpc_lintsrc>(),
            _ => panic!("unrecognized mpc table entry type: {}", type_),
        }
    }

    #[test]
    fn bounds_check() {
        let num_cpus = 4;
        let mem = single_region_mem_at(SYSTEM_MEM_START, compute_mp_size(num_cpus, &[]));
        let mut resource_allocator = ResourceAllocator::new();

        setup_mptable(&mem, &mut resource_allocator, num_cpus, &[]).unwrap();
    }

    #[test]
    fn bounds_check_fails() {
        let num_cpus = 4;
        let mem = single_region_mem_at(SYSTEM_MEM_START, compute_mp_size(num_cpus, &[]) - 1);
        let mut resource_allocator = ResourceAllocator::new();

        setup_mptable(&mem, &mut resource_allocator, num_cpus, &[]).unwrap_err();
    }

    #[test]
    fn mpf_intel_checksum() {
        let num_cpus = 1;
        let mem = single_region_mem_at(SYSTEM_MEM_START, compute_mp_size(num_cpus, &[]));
        let mut resource_allocator = ResourceAllocator::new();

        setup_mptable(&mem, &mut resource_allocator, num_cpus, &[]).unwrap();

        let mpf_intel: mpspec::mpf_intel = mem.read_obj(GuestAddress(SYSTEM_MEM_START)).unwrap();

        assert_eq!(mpf_intel_compute_checksum(&mpf_intel), mpf_intel.checksum);
    }

    #[test]
    fn mpc_table_checksum() {
        let num_cpus = 4;
        let mem = single_region_mem_at(SYSTEM_MEM_START, compute_mp_size(num_cpus, &[]));
        let mut resource_allocator = ResourceAllocator::new();

        setup_mptable(&mem, &mut resource_allocator, num_cpus, &[]).unwrap();

        let mpf_intel: mpspec::mpf_intel = mem.read_obj(GuestAddress(SYSTEM_MEM_START)).unwrap();
        let mpc_offset = GuestAddress(u64::from(mpf_intel.physptr));
        let mpc_table: mpspec::mpc_table = mem.read_obj(mpc_offset).unwrap();

        let mut buffer = Vec::new();
        mem.write_volatile_to(mpc_offset, &mut buffer, mpc_table.length as usize)
            .unwrap();
        assert_eq!(
            buffer
                .iter()
                .fold(0u8, |accum, &item| accum.wrapping_add(item)),
            0
        );
    }

    #[test]
    fn mpc_entry_count() {
        let num_cpus = 1;
        let mem = single_region_mem_at(SYSTEM_MEM_START, compute_mp_size(num_cpus, &[]));
        let mut resource_allocator = ResourceAllocator::new();

        setup_mptable(&mem, &mut resource_allocator, num_cpus, &[]).unwrap();

        let mpf_intel: mpspec::mpf_intel = mem.read_obj(GuestAddress(SYSTEM_MEM_START)).unwrap();
        let mpc_offset = GuestAddress(u64::from(mpf_intel.physptr));
        let mpc_table: mpspec::mpc_table = mem.read_obj(mpc_offset).unwrap();

        let expected_entry_count =
            // Intel floating point
            1
            // CPU
            + u16::from(num_cpus)
            // IOAPIC
            + 1
            // ISA Bus
            + 1
            // IRQ
            + u16::try_from(GSI_LEGACY_END).unwrap() + 1
            // Interrupt source ExtINT
            + 1
            // Interrupt source NMI
            + 1;
        assert_eq!(mpc_table.oemcount, expected_entry_count);
    }

    #[test]
    fn cpu_entry_count() {
        let mem = single_region_mem_at(SYSTEM_MEM_START, compute_mp_size(MAX_SUPPORTED_CPUS, &[]));

        for i in 0..MAX_SUPPORTED_CPUS {
            let mut resource_allocator = ResourceAllocator::new();

            setup_mptable(&mem, &mut resource_allocator, i, &[]).unwrap();

            let mpf_intel: mpspec::mpf_intel =
                mem.read_obj(GuestAddress(SYSTEM_MEM_START)).unwrap();
            let mpc_offset = GuestAddress(u64::from(mpf_intel.physptr));
            let mpc_table: mpspec::mpc_table = mem.read_obj(mpc_offset).unwrap();
            let mpc_end = mpc_offset.checked_add(u64::from(mpc_table.length)).unwrap();

            let mut entry_offset = mpc_offset
                .checked_add(mem::size_of::<mpspec::mpc_table>() as u64)
                .unwrap();
            let mut cpu_count = 0;
            while entry_offset < mpc_end {
                let entry_type: u8 = mem.read_obj(entry_offset).unwrap();
                entry_offset = entry_offset
                    .checked_add(table_entry_size(entry_type) as u64)
                    .unwrap();
                assert!(entry_offset <= mpc_end);
                if u32::from(entry_type) == mpspec::MP_PROCESSOR {
                    cpu_count += 1;
                }
            }
            assert_eq!(cpu_count, i);
        }
    }

    #[test]
    fn cpu_entry_count_max() {
        let cpus = MAX_SUPPORTED_CPUS + 1;
        let mem = single_region_mem_at(SYSTEM_MEM_START, compute_mp_size(cpus, &[]));
        let mut resource_allocator = ResourceAllocator::new();

        let result = setup_mptable(&mem, &mut resource_allocator, cpus, &[]).unwrap_err();
        assert_eq!(result, MptableError::TooManyCpus);
    }

    /// The bus and interrupt source entries of the MP table written at `SYSTEM_MEM_START`.
    fn read_buses_and_irqs(
        mem: &GuestMemoryMmap,
    ) -> (Vec<mpspec::mpc_bus>, Vec<mpspec::mpc_intsrc>, Vec<u8>) {
        let mpf_intel: mpspec::mpf_intel = mem.read_obj(GuestAddress(SYSTEM_MEM_START)).unwrap();
        let mpc_offset = GuestAddress(u64::from(mpf_intel.physptr));
        let mpc_table: mpspec::mpc_table = mem.read_obj(mpc_offset).unwrap();
        let mpc_end = mpc_offset.checked_add(u64::from(mpc_table.length)).unwrap();
        let mut entry_offset = mpc_offset
            .checked_add(mem::size_of::<mpspec::mpc_table>() as u64)
            .unwrap();
        let (mut buses, mut irqs, mut lint_buses) = (Vec::new(), Vec::new(), Vec::new());
        while entry_offset < mpc_end {
            let entry_type: u8 = mem.read_obj(entry_offset).unwrap();
            match u32::from(entry_type) {
                mpspec::MP_BUS => buses.push(mem.read_obj(entry_offset).unwrap()),
                mpspec::MP_INTSRC => irqs.push(mem.read_obj(entry_offset).unwrap()),
                mpspec::MP_LINTSRC => lint_buses.push(
                    mem.read_obj::<mpspec::mpc_lintsrc>(entry_offset)
                        .unwrap()
                        .srcbusid,
                ),
                _ => {}
            }
            entry_offset = entry_offset
                .checked_add(table_entry_size(entry_type) as u64)
                .unwrap();
        }
        assert_eq!(entry_offset, mpc_end);
        (buses, irqs, lint_buses)
    }

    #[test]
    fn pci_interrupt_routes() {
        let num_cpus = 2;

        // Without PCI interrupt routes, there is only the ISA bus, with id 0.
        let mem = single_region_mem_at(SYSTEM_MEM_START, compute_mp_size(num_cpus, &[]));
        setup_mptable(&mem, &mut ResourceAllocator::new(), num_cpus, &[]).unwrap();
        let (buses, irqs, lint_buses) = read_buses_and_irqs(&mem);
        assert_eq!(buses.len(), 1);
        assert_eq!((buses[0].busid, buses[0].bustype), (0, BUS_TYPE_ISA));
        assert_eq!(irqs.len(), GSI_LEGACY_END as usize + 1);
        assert!(
            irqs.iter()
                .all(|irq| irq.srcbus == 0 && irq.srcbusirq == irq.dstirq)
        );
        assert_eq!(lint_buses, [0, 0]);

        // Slots 3 and 4 share IOAPIC input 20, slot 5 has input 21.
        let routes = [(3, 20), (4, 20), (5, 21)];
        let mem = single_region_mem_at(SYSTEM_MEM_START, compute_mp_size(num_cpus, &routes));
        setup_mptable(&mem, &mut ResourceAllocator::new(), num_cpus, &routes).unwrap();
        let (buses, irqs, lint_buses) = read_buses_and_irqs(&mem);
        let buses: Vec<_> = buses.iter().map(|bus| (bus.busid, bus.bustype)).collect();
        assert_eq!(buses, [(0, BUS_TYPE_PCI), (1, BUS_TYPE_ISA)]);
        let isa: Vec<_> = irqs.iter().filter(|irq| irq.srcbus == 1).collect();
        assert_eq!(isa.len(), GSI_LEGACY_END as usize + 1 - 2);
        assert!(
            isa.iter()
                .all(|irq| irq.srcbusirq == irq.dstirq && irq.dstirq != 20 && irq.dstirq != 21)
        );
        let pci: Vec<_> = irqs
            .iter()
            .filter(|irq| irq.srcbus == 0)
            .map(|irq| (irq.srcbusirq, irq.dstirq, irq.irqflag))
            .collect();
        assert_eq!(pci, [(3 << 2, 20, 0), (4 << 2, 20, 0), (5 << 2, 21, 0)]);
        assert_eq!(lint_buses, [1, 1]);

        // Routes must be to a slot of the bus and to an IOAPIC input.
        let mut resource_allocator = ResourceAllocator::new();
        assert_eq!(
            setup_mptable(&mem, &mut resource_allocator, num_cpus, &[(32, 20)]),
            Err(MptableError::InvalidPciIntxRoute(32, 20))
        );
        assert_eq!(
            setup_mptable(&mem, &mut resource_allocator, num_cpus, &[(3, 24)]),
            Err(MptableError::InvalidPciIntxRoute(3, 24))
        );
    }
}
