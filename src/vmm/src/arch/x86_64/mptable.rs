// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::convert::TryFrom;
use std::fmt::Debug;
use std::mem::{self, size_of};

use libc::c_char;
use log::debug;
use vm_allocator::AllocPolicy;

use crate::arch::IRQ_MAX;
use crate::arch_gen::x86::mpspec;
use crate::device_manager::resources::ResourceAllocator;
use crate::vstate::memory::{
    Address, ByteValued, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap,
};

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
const BUS_TYPE_ISA: [u8; 6] = [b'I', b'S', b'A', b' ', b' ', b' '];
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

fn compute_mp_size(num_cpus: u8) -> usize {
    mem::size_of::<mpspec::mpf_intel>()
        + mem::size_of::<mpspec::mpc_table>()
        + mem::size_of::<mpspec::mpc_cpu>() * (num_cpus as usize)
        + mem::size_of::<mpspec::mpc_ioapic>()
        + mem::size_of::<mpspec::mpc_bus>()
        + mem::size_of::<mpspec::mpc_intsrc>() * (IRQ_MAX as usize + 1)
        + mem::size_of::<mpspec::mpc_lintsrc>() * 2
}

/// Performs setup of the MP table for the given `num_cpus`.
pub fn setup_mptable(
    mem: &GuestMemoryMmap,
    resource_allocator: &mut ResourceAllocator,
    num_cpus: u8,
) -> Result<(), MptableError> {
    if num_cpus > MAX_SUPPORTED_CPUS {
        return Err(MptableError::TooManyCpus);
    }

    let mp_size = compute_mp_size(num_cpus);
    let mptable_addr =
        resource_allocator.allocate_system_memory(mp_size as u64, 1, AllocPolicy::FirstMatch)?;
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
    {
        let size = mem::size_of::<mpspec::mpc_bus>() as u64;
        let mpc_bus = mpspec::mpc_bus {
            type_: mpspec::MP_BUS.try_into().unwrap(),
            busid: 0,
            bustype: BUS_TYPE_ISA,
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
    // Per kvm_setup_default_irq_routing() in kernel
    for i in 0..=u8::try_from(IRQ_MAX).map_err(|_| MptableError::TooManyIrqs)? {
        let size = mem::size_of::<mpspec::mpc_intsrc>() as u64;
        let mpc_intsrc = mpspec::mpc_intsrc {
            type_: mpspec::MP_INTSRC.try_into().unwrap(),
            irqtype: mpspec::mp_irq_source_types_mp_INT.try_into().unwrap(),
            irqflag: mpspec::MP_IRQPOL_DEFAULT.try_into().unwrap(),
            srcbus: 0,
            srcbusirq: i,
            dstapic: ioapicid,
            dstirq: i,
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
            irqtype: mpspec::mp_irq_source_types_mp_ExtINT.try_into().unwrap(),
            irqflag: mpspec::MP_IRQPOL_DEFAULT.try_into().unwrap(),
            srcbusid: 0,
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
            irqtype: mpspec::mp_irq_source_types_mp_NMI.try_into().unwrap(),
            irqflag: mpspec::MP_IRQPOL_DEFAULT.try_into().unwrap(),
            srcbusid: 0,
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
    use crate::utilities::test_utils::single_region_mem_at;
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
        let mem = single_region_mem_at(SYSTEM_MEM_START, compute_mp_size(num_cpus));
        let mut resource_allocator = ResourceAllocator::new().unwrap();

        setup_mptable(&mem, &mut resource_allocator, num_cpus).unwrap();
    }

    #[test]
    fn bounds_check_fails() {
        let num_cpus = 4;
        let mem = single_region_mem_at(SYSTEM_MEM_START, compute_mp_size(num_cpus) - 1);
        let mut resource_allocator = ResourceAllocator::new().unwrap();

        setup_mptable(&mem, &mut resource_allocator, num_cpus).unwrap_err();
    }

    #[test]
    fn mpf_intel_checksum() {
        let num_cpus = 1;
        let mem = single_region_mem_at(SYSTEM_MEM_START, compute_mp_size(num_cpus));
        let mut resource_allocator = ResourceAllocator::new().unwrap();

        setup_mptable(&mem, &mut resource_allocator, num_cpus).unwrap();

        let mpf_intel: mpspec::mpf_intel = mem.read_obj(GuestAddress(SYSTEM_MEM_START)).unwrap();

        assert_eq!(mpf_intel_compute_checksum(&mpf_intel), mpf_intel.checksum);
    }

    #[test]
    fn mpc_table_checksum() {
        let num_cpus = 4;
        let mem = single_region_mem_at(SYSTEM_MEM_START, compute_mp_size(num_cpus));
        let mut resource_allocator = ResourceAllocator::new().unwrap();

        setup_mptable(&mem, &mut resource_allocator, num_cpus).unwrap();

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
        let mem = single_region_mem_at(SYSTEM_MEM_START, compute_mp_size(num_cpus));
        let mut resource_allocator = ResourceAllocator::new().unwrap();

        setup_mptable(&mem, &mut resource_allocator, num_cpus).unwrap();

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
            + u16::try_from(IRQ_MAX).unwrap() + 1
            // Interrupt source ExtINT
            + 1
            // Interrupt source NMI
            + 1;
        assert_eq!(mpc_table.oemcount, expected_entry_count);
    }

    #[test]
    fn cpu_entry_count() {
        let mem = single_region_mem_at(SYSTEM_MEM_START, compute_mp_size(MAX_SUPPORTED_CPUS));

        for i in 0..MAX_SUPPORTED_CPUS {
            let mut resource_allocator = ResourceAllocator::new().unwrap();
            setup_mptable(&mem, &mut resource_allocator, i).unwrap();

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
        let mem = single_region_mem_at(SYSTEM_MEM_START, compute_mp_size(cpus));
        let mut resource_allocator = ResourceAllocator::new().unwrap();

        let result = setup_mptable(&mem, &mut resource_allocator, cpus).unwrap_err();
        assert_eq!(result, MptableError::TooManyCpus);
    }
}
