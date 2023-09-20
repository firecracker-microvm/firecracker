// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::convert::TryFrom;
use std::fmt::Debug;
use std::{io, mem};

use libc::c_char;
use utils::vm_memory::{Address, ByteValued, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

use crate::arch::IRQ_MAX;
use crate::arch_gen::x86::mpspec;

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

// MPTABLE, describing VCPUS.
const MPTABLE_START: u64 = 0x9fc00;

#[derive(Debug, PartialEq, Eq)]
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
}

// With APIC/xAPIC, there are only 255 APIC IDs available. And IOAPIC occupies
// one APIC ID, so only 254 CPUs at maximum may be supported. Actually it's
// a large number for FC usecases.
pub const MAX_SUPPORTED_CPUS: u32 = 254;

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
const BUS_TYPE_ISA: [u8; 6] = char_array!(u8; 'I', 'S', 'A', ' ', ' ', ' ');
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
pub fn setup_mptable(mem: &GuestMemoryMmap, num_cpus: u8) -> Result<(), MptableError> {
    if u32::from(num_cpus) > MAX_SUPPORTED_CPUS {
        return Err(MptableError::TooManyCpus);
    }

    // Used to keep track of the next base pointer into the MP table.
    let mut base_mp = GuestAddress(MPTABLE_START);

    let mp_size = compute_mp_size(num_cpus);

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

    mem.read_from(base_mp, &mut io::repeat(0), mp_size)
        .map_err(|_| MptableError::Clear)?;

    {
        let size = mem::size_of::<mpspec::mpf_intel>() as u64;
        let mut mpf_intel = mpspec::mpf_intel {
            signature: SMP_MAGIC_IDENT,
            physptr: (base_mp.raw_value() + size) as u32,
            length: 1,
            specification: 4,
            ..mpspec::mpf_intel::default()
        };
        mpf_intel.checksum = mpf_intel_compute_checksum(&mpf_intel);
        mem.write_obj(mpf_intel, base_mp)
            .map_err(|_| MptableError::WriteMpfIntel)?;
        base_mp = base_mp.unchecked_add(size);
    }

    // We set the location of the mpc_table here but we can't fill it out until we have the length
    // of the entire table later.
    let table_base = base_mp;
    base_mp = base_mp.unchecked_add(mem::size_of::<mpspec::mpc_table>() as u64);

    {
        let size = mem::size_of::<mpspec::mpc_cpu>() as u64;
        for cpu_id in 0..num_cpus {
            let mpc_cpu = mpspec::mpc_cpu {
                type_: mpspec::MP_PROCESSOR as u8,
                apicid: cpu_id,
                apicver: APIC_VERSION,
                cpuflag: mpspec::CPU_ENABLED as u8
                    | if cpu_id == 0 {
                        mpspec::CPU_BOOTPROCESSOR as u8
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
        }
    }
    {
        let size = mem::size_of::<mpspec::mpc_bus>() as u64;
        let mpc_bus = mpspec::mpc_bus {
            type_: mpspec::MP_BUS as u8,
            busid: 0,
            bustype: BUS_TYPE_ISA,
        };
        mem.write_obj(mpc_bus, base_mp)
            .map_err(|_| MptableError::WriteMpcBus)?;
        base_mp = base_mp.unchecked_add(size);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_bus));
    }
    {
        let size = mem::size_of::<mpspec::mpc_ioapic>() as u64;
        let mpc_ioapic = mpspec::mpc_ioapic {
            type_: mpspec::MP_IOAPIC as u8,
            apicid: ioapicid,
            apicver: APIC_VERSION,
            flags: mpspec::MPC_APIC_USABLE as u8,
            apicaddr: IO_APIC_DEFAULT_PHYS_BASE,
        };
        mem.write_obj(mpc_ioapic, base_mp)
            .map_err(|_| MptableError::WriteMpcIoapic)?;
        base_mp = base_mp.unchecked_add(size);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_ioapic));
    }
    // Per kvm_setup_default_irq_routing() in kernel
    for i in 0..=u8::try_from(IRQ_MAX).map_err(|_| MptableError::TooManyIrqs)? {
        let size = mem::size_of::<mpspec::mpc_intsrc>() as u64;
        let mpc_intsrc = mpspec::mpc_intsrc {
            type_: mpspec::MP_INTSRC as u8,
            irqtype: mpspec::mp_irq_source_types_mp_INT as u8,
            irqflag: mpspec::MP_IRQPOL_DEFAULT as u16,
            srcbus: 0,
            srcbusirq: i,
            dstapic: ioapicid,
            dstirq: i,
        };
        mem.write_obj(mpc_intsrc, base_mp)
            .map_err(|_| MptableError::WriteMpcIntsrc)?;
        base_mp = base_mp.unchecked_add(size);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_intsrc));
    }
    {
        let size = mem::size_of::<mpspec::mpc_lintsrc>() as u64;
        let mpc_lintsrc = mpspec::mpc_lintsrc {
            type_: mpspec::MP_LINTSRC as u8,
            irqtype: mpspec::mp_irq_source_types_mp_ExtINT as u8,
            irqflag: mpspec::MP_IRQPOL_DEFAULT as u16,
            srcbusid: 0,
            srcbusirq: 0,
            destapic: 0,
            destapiclint: 0,
        };
        mem.write_obj(mpc_lintsrc, base_mp)
            .map_err(|_| MptableError::WriteMpcLintsrc)?;
        base_mp = base_mp.unchecked_add(size);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_lintsrc));
    }
    {
        let size = mem::size_of::<mpspec::mpc_lintsrc>() as u64;
        let mpc_lintsrc = mpspec::mpc_lintsrc {
            type_: mpspec::MP_LINTSRC as u8,
            irqtype: mpspec::mp_irq_source_types_mp_NMI as u8,
            irqflag: mpspec::MP_IRQPOL_DEFAULT as u16,
            srcbusid: 0,
            srcbusirq: 0,
            destapic: 0xFF,
            destapiclint: 1,
        };
        mem.write_obj(mpc_lintsrc, base_mp)
            .map_err(|_| MptableError::WriteMpcLintsrc)?;
        base_mp = base_mp.unchecked_add(size);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_lintsrc));
    }

    // At this point we know the size of the mp_table.
    let table_end = base_mp;

    {
        let mut mpc_table = mpspec::mpc_table {
            signature: MPC_SIGNATURE,
            // it's safe to use unchecked_offset_from because
            // table_end > table_base
            length: table_end.unchecked_offset_from(table_base) as u16,
            spec: MPC_SPEC,
            oem: MPC_OEM,
            productid: MPC_PRODUCT_ID,
            lapic: APIC_DEFAULT_PHYS_BASE,
            ..Default::default()
        };
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
    use utils::vm_memory::Bytes;

    use super::*;

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
        let mem = utils::vm_memory::test_utils::create_guest_memory_unguarded(
            &[(GuestAddress(MPTABLE_START), compute_mp_size(num_cpus))],
            false,
        )
        .unwrap();

        setup_mptable(&mem, num_cpus).unwrap();
    }

    #[test]
    fn bounds_check_fails() {
        let num_cpus = 4;
        let mem = utils::vm_memory::test_utils::create_guest_memory_unguarded(
            &[(GuestAddress(MPTABLE_START), compute_mp_size(num_cpus) - 1)],
            false,
        )
        .unwrap();

        assert!(setup_mptable(&mem, num_cpus).is_err());
    }

    #[test]
    fn mpf_intel_checksum() {
        let num_cpus = 1;
        let mem = utils::vm_memory::test_utils::create_guest_memory_unguarded(
            &[(GuestAddress(MPTABLE_START), compute_mp_size(num_cpus))],
            false,
        )
        .unwrap();

        setup_mptable(&mem, num_cpus).unwrap();

        let mpf_intel: mpspec::mpf_intel = mem.read_obj(GuestAddress(MPTABLE_START)).unwrap();

        assert_eq!(mpf_intel_compute_checksum(&mpf_intel), mpf_intel.checksum);
    }

    #[test]
    fn mpc_table_checksum() {
        let num_cpus = 4;
        let mem = utils::vm_memory::test_utils::create_guest_memory_unguarded(
            &[(GuestAddress(MPTABLE_START), compute_mp_size(num_cpus))],
            false,
        )
        .unwrap();

        setup_mptable(&mem, num_cpus).unwrap();

        let mpf_intel: mpspec::mpf_intel = mem.read_obj(GuestAddress(MPTABLE_START)).unwrap();
        let mpc_offset = GuestAddress(u64::from(mpf_intel.physptr));
        let mpc_table: mpspec::mpc_table = mem.read_obj(mpc_offset).unwrap();

        #[derive(Debug)]
        struct Sum(u8);
        impl io::Write for Sum {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                for v in buf.iter() {
                    self.0 = self.0.wrapping_add(*v);
                }
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let mut sum = Sum(0);
        mem.write_to(mpc_offset, &mut sum, mpc_table.length as usize)
            .unwrap();
        assert_eq!(sum.0, 0);
    }

    #[test]
    fn cpu_entry_count() {
        let mem = utils::vm_memory::test_utils::create_guest_memory_unguarded(
            &[(
                GuestAddress(MPTABLE_START),
                compute_mp_size(MAX_SUPPORTED_CPUS as u8),
            )],
            false,
        )
        .unwrap();

        for i in 0..MAX_SUPPORTED_CPUS as u8 {
            setup_mptable(&mem, i).unwrap();

            let mpf_intel: mpspec::mpf_intel = mem.read_obj(GuestAddress(MPTABLE_START)).unwrap();
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
        let mem = utils::vm_memory::test_utils::create_guest_memory_unguarded(
            &[(GuestAddress(MPTABLE_START), compute_mp_size(cpus as u8))],
            false,
        )
        .unwrap();

        let result = setup_mptable(&mem, cpus as u8).unwrap_err();
        assert_eq!(result, MptableError::TooManyCpus);
    }
}
