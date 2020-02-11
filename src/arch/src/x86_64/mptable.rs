// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::io;
use std::mem;
use std::result;
use std::slice;

use libc::c_char;

use arch_gen::x86::mpspec;
use vm_memory::{Address, ByteValued, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

// This is a workaround to the Rust enforcement specifying that any implementation of a foreign
// trait (in this case `ByteValued`) where:
// *    the type that is implementing the trait is foreign or
// *    all of the parameters being passed to the trait (if there are any) are also foreign
// is prohibited.
#[derive(Copy, Clone, Default)]
struct MpcBusWrapper(mpspec::mpc_bus);
#[derive(Copy, Clone, Default)]
struct MpcCpuWrapper(mpspec::mpc_cpu);
#[derive(Copy, Clone, Default)]
struct MpcIntsrcWrapper(mpspec::mpc_intsrc);
#[derive(Copy, Clone, Default)]
struct MpcIoapicWrapper(mpspec::mpc_ioapic);
#[derive(Copy, Clone, Default)]
struct MpcTableWrapper(mpspec::mpc_table);
#[derive(Copy, Clone, Default)]
struct MpcLintsrcWrapper(mpspec::mpc_lintsrc);
#[derive(Copy, Clone, Default)]
struct MpfIntelWrapper(mpspec::mpf_intel);

// These `mpspec` wrapper types are only data, reading them from data is a safe initialization.
unsafe impl ByteValued for MpcBusWrapper {}
unsafe impl ByteValued for MpcCpuWrapper {}
unsafe impl ByteValued for MpcIntsrcWrapper {}
unsafe impl ByteValued for MpcIoapicWrapper {}
unsafe impl ByteValued for MpcTableWrapper {}
unsafe impl ByteValued for MpcLintsrcWrapper {}
unsafe impl ByteValued for MpfIntelWrapper {}

// MPTABLE, describing VCPUS.
const MPTABLE_START: u64 = 0x9fc00;

#[derive(Debug, PartialEq)]
pub enum Error {
    /// There was too little guest memory to store the entire MP table.
    NotEnoughMemory,
    /// The MP table has too little address space to be stored.
    AddressOverflow,
    /// Failure while zeroing out the memory for the MP table.
    Clear,
    /// Number of CPUs exceeds the maximum supported CPUs
    TooManyCpus,
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

pub type Result<T> = result::Result<T, Error>;

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

fn compute_checksum<T: Copy>(v: &T) -> u8 {
    // Safe because we are only reading the bytes within the size of the `T` reference `v`.
    let v_slice = unsafe { slice::from_raw_parts(v as *const T as *const u8, mem::size_of::<T>()) };
    let mut checksum: u8 = 0;
    for i in v_slice.iter() {
        checksum = checksum.wrapping_add(*i);
    }
    checksum
}

fn mpf_intel_compute_checksum(v: &mpspec::mpf_intel) -> u8 {
    let checksum = compute_checksum(v).wrapping_sub(v.checksum);
    (!checksum).wrapping_add(1)
}

fn compute_mp_size(num_cpus: u8) -> usize {
    mem::size_of::<MpfIntelWrapper>()
        + mem::size_of::<MpcTableWrapper>()
        + mem::size_of::<MpcCpuWrapper>() * (num_cpus as usize)
        + mem::size_of::<MpcIoapicWrapper>()
        + mem::size_of::<MpcBusWrapper>()
        + mem::size_of::<MpcIntsrcWrapper>() * 16
        + mem::size_of::<MpcLintsrcWrapper>() * 2
}

/// Performs setup of the MP table for the given `num_cpus`.
pub fn setup_mptable(mem: &GuestMemoryMmap, num_cpus: u8) -> Result<()> {
    if u32::from(num_cpus) > MAX_SUPPORTED_CPUS {
        return Err(Error::TooManyCpus);
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
            return Err(Error::NotEnoughMemory);
        }
    } else {
        return Err(Error::AddressOverflow);
    }

    mem.read_from(base_mp, &mut io::repeat(0), mp_size)
        .map_err(|_| Error::Clear)?;

    {
        let mut mpf_intel = MpfIntelWrapper(mpspec::mpf_intel::default());
        let size = mem::size_of::<MpfIntelWrapper>() as u64;
        mpf_intel.0.signature = SMP_MAGIC_IDENT;
        mpf_intel.0.length = 1;
        mpf_intel.0.specification = 4;
        mpf_intel.0.physptr = (base_mp.raw_value() + size) as u32;
        mpf_intel.0.checksum = mpf_intel_compute_checksum(&mpf_intel.0);
        mem.write_obj(mpf_intel, base_mp)
            .map_err(|_| Error::WriteMpfIntel)?;
        base_mp = base_mp.unchecked_add(size);
    }

    // We set the location of the mpc_table here but we can't fill it out until we have the length
    // of the entire table later.
    let table_base = base_mp;
    base_mp = base_mp.unchecked_add(mem::size_of::<MpcTableWrapper>() as u64);

    {
        let size = mem::size_of::<MpcCpuWrapper>() as u64;
        for cpu_id in 0..num_cpus {
            let mut mpc_cpu = MpcCpuWrapper(mpspec::mpc_cpu::default());
            mpc_cpu.0.type_ = mpspec::MP_PROCESSOR as u8;
            mpc_cpu.0.apicid = cpu_id;
            mpc_cpu.0.apicver = APIC_VERSION;
            mpc_cpu.0.cpuflag = mpspec::CPU_ENABLED as u8
                | if cpu_id == 0 {
                    mpspec::CPU_BOOTPROCESSOR as u8
                } else {
                    0
                };
            mpc_cpu.0.cpufeature = CPU_STEPPING;
            mpc_cpu.0.featureflag = CPU_FEATURE_APIC | CPU_FEATURE_FPU;
            mem.write_obj(mpc_cpu, base_mp)
                .map_err(|_| Error::WriteMpcCpu)?;
            base_mp = base_mp.unchecked_add(size);
            checksum = checksum.wrapping_add(compute_checksum(&mpc_cpu.0));
        }
    }
    {
        let size = mem::size_of::<MpcBusWrapper>() as u64;
        let mut mpc_bus = MpcBusWrapper(mpspec::mpc_bus::default());
        mpc_bus.0.type_ = mpspec::MP_BUS as u8;
        mpc_bus.0.busid = 0;
        mpc_bus.0.bustype = BUS_TYPE_ISA;
        mem.write_obj(mpc_bus, base_mp)
            .map_err(|_| Error::WriteMpcBus)?;
        base_mp = base_mp.unchecked_add(size);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_bus.0));
    }
    {
        let size = mem::size_of::<MpcIoapicWrapper>() as u64;
        let mut mpc_ioapic = MpcIoapicWrapper(mpspec::mpc_ioapic::default());
        mpc_ioapic.0.type_ = mpspec::MP_IOAPIC as u8;
        mpc_ioapic.0.apicid = ioapicid;
        mpc_ioapic.0.apicver = APIC_VERSION;
        mpc_ioapic.0.flags = mpspec::MPC_APIC_USABLE as u8;
        mpc_ioapic.0.apicaddr = IO_APIC_DEFAULT_PHYS_BASE;
        mem.write_obj(mpc_ioapic, base_mp)
            .map_err(|_| Error::WriteMpcIoapic)?;
        base_mp = base_mp.unchecked_add(size);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_ioapic.0));
    }
    // Per kvm_setup_default_irq_routing() in kernel
    for i in 0..16 {
        let size = mem::size_of::<MpcIntsrcWrapper>() as u64;
        let mut mpc_intsrc = MpcIntsrcWrapper(mpspec::mpc_intsrc::default());
        mpc_intsrc.0.type_ = mpspec::MP_INTSRC as u8;
        mpc_intsrc.0.irqtype = mpspec::mp_irq_source_types_mp_INT as u8;
        mpc_intsrc.0.irqflag = mpspec::MP_IRQDIR_DEFAULT as u16;
        mpc_intsrc.0.srcbus = 0;
        mpc_intsrc.0.srcbusirq = i;
        mpc_intsrc.0.dstapic = ioapicid;
        mpc_intsrc.0.dstirq = i;
        mem.write_obj(mpc_intsrc, base_mp)
            .map_err(|_| Error::WriteMpcIntsrc)?;
        base_mp = base_mp.unchecked_add(size);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_intsrc.0));
    }
    {
        let size = mem::size_of::<MpcLintsrcWrapper>() as u64;
        let mut mpc_lintsrc = MpcLintsrcWrapper(mpspec::mpc_lintsrc::default());
        mpc_lintsrc.0.type_ = mpspec::MP_LINTSRC as u8;
        mpc_lintsrc.0.irqtype = mpspec::mp_irq_source_types_mp_ExtINT as u8;
        mpc_lintsrc.0.irqflag = mpspec::MP_IRQDIR_DEFAULT as u16;
        mpc_lintsrc.0.srcbusid = 0;
        mpc_lintsrc.0.srcbusirq = 0;
        mpc_lintsrc.0.destapic = 0;
        mpc_lintsrc.0.destapiclint = 0;
        mem.write_obj(mpc_lintsrc, base_mp)
            .map_err(|_| Error::WriteMpcLintsrc)?;
        base_mp = base_mp.unchecked_add(size);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_lintsrc.0));
    }
    {
        let size = mem::size_of::<MpcLintsrcWrapper>() as u64;
        let mut mpc_lintsrc = MpcLintsrcWrapper(mpspec::mpc_lintsrc::default());
        mpc_lintsrc.0.type_ = mpspec::MP_LINTSRC as u8;
        mpc_lintsrc.0.irqtype = mpspec::mp_irq_source_types_mp_NMI as u8;
        mpc_lintsrc.0.irqflag = mpspec::MP_IRQDIR_DEFAULT as u16;
        mpc_lintsrc.0.srcbusid = 0;
        mpc_lintsrc.0.srcbusirq = 0;
        mpc_lintsrc.0.destapic = 0xFF; /* to all local APICs */
        mpc_lintsrc.0.destapiclint = 1;
        mem.write_obj(mpc_lintsrc, base_mp)
            .map_err(|_| Error::WriteMpcLintsrc)?;
        base_mp = base_mp.unchecked_add(size);
        checksum = checksum.wrapping_add(compute_checksum(&mpc_lintsrc.0));
    }

    // At this point we know the size of the mp_table.
    let table_end = base_mp;

    {
        let mut mpc_table = MpcTableWrapper(mpspec::mpc_table::default());
        mpc_table.0.signature = MPC_SIGNATURE;
        // it's safe to use unchecked_offset_from because
        // table_end > table_base
        mpc_table.0.length = table_end.unchecked_offset_from(table_base) as u16;
        mpc_table.0.spec = MPC_SPEC;
        mpc_table.0.oem = MPC_OEM;
        mpc_table.0.productid = MPC_PRODUCT_ID;
        mpc_table.0.lapic = APIC_DEFAULT_PHYS_BASE;
        checksum = checksum.wrapping_add(compute_checksum(&mpc_table.0));
        mpc_table.0.checksum = (!checksum).wrapping_add(1) as i8;
        mem.write_obj(mpc_table, table_base)
            .map_err(|_| Error::WriteMpcTable)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vm_memory::Bytes;

    fn table_entry_size(type_: u8) -> usize {
        match u32::from(type_) {
            mpspec::MP_PROCESSOR => mem::size_of::<MpcCpuWrapper>(),
            mpspec::MP_BUS => mem::size_of::<MpcBusWrapper>(),
            mpspec::MP_IOAPIC => mem::size_of::<MpcIoapicWrapper>(),
            mpspec::MP_INTSRC => mem::size_of::<MpcIntsrcWrapper>(),
            mpspec::MP_LINTSRC => mem::size_of::<MpcLintsrcWrapper>(),
            _ => panic!("unrecognized mpc table entry type: {}", type_),
        }
    }

    #[test]
    fn bounds_check() {
        let num_cpus = 4;
        let mem = GuestMemoryMmap::from_ranges(&[(
            GuestAddress(MPTABLE_START),
            compute_mp_size(num_cpus),
        )])
        .unwrap();

        setup_mptable(&mem, num_cpus).unwrap();
    }

    #[test]
    fn bounds_check_fails() {
        let num_cpus = 4;
        let mem = GuestMemoryMmap::from_ranges(&[(
            GuestAddress(MPTABLE_START),
            compute_mp_size(num_cpus) - 1,
        )])
        .unwrap();

        assert!(setup_mptable(&mem, num_cpus).is_err());
    }

    #[test]
    fn mpf_intel_checksum() {
        let num_cpus = 1;
        let mem = GuestMemoryMmap::from_ranges(&[(
            GuestAddress(MPTABLE_START),
            compute_mp_size(num_cpus),
        )])
        .unwrap();

        setup_mptable(&mem, num_cpus).unwrap();

        let mpf_intel: MpfIntelWrapper = mem.read_obj(GuestAddress(MPTABLE_START)).unwrap();

        assert_eq!(
            mpf_intel_compute_checksum(&mpf_intel.0),
            mpf_intel.0.checksum
        );
    }

    #[test]
    fn mpc_table_checksum() {
        let num_cpus = 4;
        let mem = GuestMemoryMmap::from_ranges(&[(
            GuestAddress(MPTABLE_START),
            compute_mp_size(num_cpus),
        )])
        .unwrap();

        setup_mptable(&mem, num_cpus).unwrap();

        let mpf_intel: MpfIntelWrapper = mem.read_obj(GuestAddress(MPTABLE_START)).unwrap();
        let mpc_offset = GuestAddress(u64::from(mpf_intel.0.physptr));
        let mpc_table: MpcTableWrapper = mem.read_obj(mpc_offset).unwrap();

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
        mem.write_to(mpc_offset, &mut sum, mpc_table.0.length as usize)
            .unwrap();
        assert_eq!(sum.0, 0);
    }

    #[test]
    fn cpu_entry_count() {
        let mem = GuestMemoryMmap::from_ranges(&[(
            GuestAddress(MPTABLE_START),
            compute_mp_size(MAX_SUPPORTED_CPUS as u8),
        )])
        .unwrap();

        for i in 0..MAX_SUPPORTED_CPUS as u8 {
            setup_mptable(&mem, i).unwrap();

            let mpf_intel: MpfIntelWrapper = mem.read_obj(GuestAddress(MPTABLE_START)).unwrap();
            let mpc_offset = GuestAddress(u64::from(mpf_intel.0.physptr));
            let mpc_table: MpcTableWrapper = mem.read_obj(mpc_offset).unwrap();
            let mpc_end = mpc_offset
                .checked_add(u64::from(mpc_table.0.length))
                .unwrap();

            let mut entry_offset = mpc_offset
                .checked_add(mem::size_of::<MpcTableWrapper>() as u64)
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
        let mem = GuestMemoryMmap::from_ranges(&[(
            GuestAddress(MPTABLE_START),
            compute_mp_size(cpus as u8),
        )])
        .unwrap();

        let result = setup_mptable(&mem, cpus as u8).unwrap_err();
        assert_eq!(result, Error::TooManyCpus);
    }
}
