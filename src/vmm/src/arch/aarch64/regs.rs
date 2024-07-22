// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::mem::offset_of;

use kvm_bindings::*;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[allow(non_upper_case_globals)]
/// PSR (Processor State Register) bits.
/// Taken from arch/arm64/include/uapi/asm/ptrace.h.
const PSR_MODE_EL1h: u64 = 0x0000_0005;
const PSR_F_BIT: u64 = 0x0000_0040;
const PSR_I_BIT: u64 = 0x0000_0080;
const PSR_A_BIT: u64 = 0x0000_0100;
const PSR_D_BIT: u64 = 0x0000_0200;
/// Taken from arch/arm64/kvm/inject_fault.c.
pub const PSTATE_FAULT_BITS_64: u64 = PSR_MODE_EL1h | PSR_A_BIT | PSR_F_BIT | PSR_I_BIT | PSR_D_BIT;

/// Gets a core id.
macro_rules! arm64_core_reg_id {
    ($size: ident, $offset: expr) => {
        // The core registers of an arm64 machine are represented
        // in kernel by the `kvm_regs` structure. This structure is a
        // mix of 32, 64 and 128 bit fields:
        // struct kvm_regs {
        //     struct user_pt_regs      regs;
        //
        //     __u64                    sp_el1;
        //     __u64                    elr_el1;
        //
        //     __u64                    spsr[KVM_NR_SPSR];
        //
        //     struct user_fpsimd_state fp_regs;
        // };
        // struct user_pt_regs {
        //     __u64 regs[31];
        //     __u64 sp;
        //     __u64 pc;
        //     __u64 pstate;
        // };
        // The id of a core register can be obtained like this:
        // offset = id & ~(KVM_REG_ARCH_MASK | KVM_REG_SIZE_MASK | KVM_REG_ARM_CORE). Thus,
        // id = KVM_REG_ARM64 | KVM_REG_SIZE_U64/KVM_REG_SIZE_U32/KVM_REG_SIZE_U128 |
        // KVM_REG_ARM_CORE | offset
        KVM_REG_ARM64 as u64
            | KVM_REG_ARM_CORE as u64
            | $size
            | ($offset / std::mem::size_of::<u32>()) as u64
    };
}
pub(crate) use arm64_core_reg_id;

/// This macro computes the ID of a specific ARM64 system register similar to how
/// the kernel C macro does.
/// https://elixir.bootlin.com/linux/v4.20.17/source/arch/arm64/include/uapi/asm/kvm.h#L203
macro_rules! arm64_sys_reg {
    ($name: tt, $op0: tt, $op1: tt, $crn: tt, $crm: tt, $op2: tt) => {
        /// System register constant
        pub const $name: u64 = KVM_REG_ARM64 as u64
            | KVM_REG_SIZE_U64 as u64
            | KVM_REG_ARM64_SYSREG as u64
            | ((($op0 as u64) << KVM_REG_ARM64_SYSREG_OP0_SHIFT)
                & KVM_REG_ARM64_SYSREG_OP0_MASK as u64)
            | ((($op1 as u64) << KVM_REG_ARM64_SYSREG_OP1_SHIFT)
                & KVM_REG_ARM64_SYSREG_OP1_MASK as u64)
            | ((($crn as u64) << KVM_REG_ARM64_SYSREG_CRN_SHIFT)
                & KVM_REG_ARM64_SYSREG_CRN_MASK as u64)
            | ((($crm as u64) << KVM_REG_ARM64_SYSREG_CRM_SHIFT)
                & KVM_REG_ARM64_SYSREG_CRM_MASK as u64)
            | ((($op2 as u64) << KVM_REG_ARM64_SYSREG_OP2_SHIFT)
                & KVM_REG_ARM64_SYSREG_OP2_MASK as u64);
    };
}

// Constants imported from the Linux kernel:
// https://elixir.bootlin.com/linux/v4.20.17/source/arch/arm64/include/asm/sysreg.h#L135
arm64_sys_reg!(MPIDR_EL1, 3, 0, 0, 0, 5);
arm64_sys_reg!(MIDR_EL1, 3, 0, 0, 0, 0);

// ID registers that represent cpu capabilities.
// Needed for static cpu templates.
arm64_sys_reg!(ID_AA64PFR0_EL1, 3, 0, 0, 4, 0);
arm64_sys_reg!(ID_AA64ISAR0_EL1, 3, 0, 0, 6, 0);
arm64_sys_reg!(ID_AA64ISAR1_EL1, 3, 0, 0, 6, 1);
arm64_sys_reg!(ID_AA64MMFR2_EL1, 3, 0, 0, 7, 2);

// Counter-timer Virtual Timer CompareValue register.
// https://developer.arm.com/documentation/ddi0595/2021-12/AArch64-Registers/CNTV-CVAL-EL0--Counter-timer-Virtual-Timer-CompareValue-register
// https://elixir.bootlin.com/linux/v6.8/source/arch/arm64/include/asm/sysreg.h#L468
arm64_sys_reg!(SYS_CNTV_CVAL_EL0, 3, 3, 14, 3, 2);

// Counter-timer Physical Count Register
// https://developer.arm.com/documentation/ddi0601/2023-12/AArch64-Registers/CNTPCT-EL0--Counter-timer-Physical-Count-Register
// https://elixir.bootlin.com/linux/v6.8/source/arch/arm64/include/asm/sysreg.h#L459
arm64_sys_reg!(SYS_CNTPCT_EL0, 3, 3, 14, 0, 1);

/// Vector lengths pseudo-register
/// TODO: this can be removed after https://github.com/rust-vmm/kvm-bindings/pull/89
/// is merged and new version is used in Firecracker.
pub const KVM_REG_ARM64_SVE_VLS: u64 =
    KVM_REG_ARM64 | KVM_REG_ARM64_SVE as u64 | KVM_REG_SIZE_U512 | 0xffff;

/// Program Counter
/// The offset value (0x100 = 32 * 8) is calcuated as follows:
/// - `kvm_regs` includes `regs` field of type `user_pt_regs` at the beginning (i.e., at offset 0).
/// - `pc` follows `regs[31]` and `sp` within `user_pt_regs` and they are 8 bytes each (i.e. the
///   offset is (31 + 1) * 8 = 256).
///
/// https://github.com/torvalds/linux/blob/master/Documentation/virt/kvm/api.rst#L2578
/// > 0x6030 0000 0010 0040 PC          64  regs.pc
pub const PC: u64 = {
    let kreg_off = offset_of!(kvm_regs, regs);
    let pc_off = offset_of!(user_pt_regs, pc);
    arm64_core_reg_id!(KVM_REG_SIZE_U64, kreg_off + pc_off)
};

/// Different aarch64 registers sizes
#[derive(Debug)]
pub enum RegSize {
    /// 8 bit register
    U8,
    /// 16 bit register
    U16,
    /// 32 bit register
    U32,
    /// 64 bit register
    U64,
    /// 128 bit register
    U128,
    /// 256 bit register
    U256,
    /// 512 bit register
    U512,
    /// 1024 bit register
    U1024,
    /// 2048 bit register
    U2048,
}

impl RegSize {
    /// Size of u8 register in bytes
    pub const U8_SIZE: usize = 1;
    /// Size of u16 register in bytes
    pub const U16_SIZE: usize = 2;
    /// Size of u32 register in bytes
    pub const U32_SIZE: usize = 4;
    /// Size of u64 register in bytes
    pub const U64_SIZE: usize = 8;
    /// Size of u128 register in bytes
    pub const U128_SIZE: usize = 16;
    /// Size of u256 register in bytes
    pub const U256_SIZE: usize = 32;
    /// Size of u512 register in bytes
    pub const U512_SIZE: usize = 64;
    /// Size of u1024 register in bytes
    pub const U1024_SIZE: usize = 128;
    /// Size of u2048 register in bytes
    pub const U2048_SIZE: usize = 256;
}

impl From<usize> for RegSize {
    fn from(value: usize) -> Self {
        match value {
            RegSize::U8_SIZE => RegSize::U8,
            RegSize::U16_SIZE => RegSize::U16,
            RegSize::U32_SIZE => RegSize::U32,
            RegSize::U64_SIZE => RegSize::U64,
            RegSize::U128_SIZE => RegSize::U128,
            RegSize::U256_SIZE => RegSize::U256,
            RegSize::U512_SIZE => RegSize::U512,
            RegSize::U1024_SIZE => RegSize::U1024,
            RegSize::U2048_SIZE => RegSize::U2048,
            _ => unreachable!("Registers bigger then 2048 bits are not supported"),
        }
    }
}

impl From<RegSize> for usize {
    fn from(value: RegSize) -> Self {
        match value {
            RegSize::U8 => RegSize::U8_SIZE,
            RegSize::U16 => RegSize::U16_SIZE,
            RegSize::U32 => RegSize::U32_SIZE,
            RegSize::U64 => RegSize::U64_SIZE,
            RegSize::U128 => RegSize::U128_SIZE,
            RegSize::U256 => RegSize::U256_SIZE,
            RegSize::U512 => RegSize::U512_SIZE,
            RegSize::U1024 => RegSize::U1024_SIZE,
            RegSize::U2048 => RegSize::U2048_SIZE,
        }
    }
}

/// Returns register size in bytes
pub fn reg_size(reg_id: u64) -> usize {
    2_usize.pow(((reg_id & KVM_REG_SIZE_MASK) >> KVM_REG_SIZE_SHIFT) as u32)
}

/// Storage for aarch64 registers with different sizes.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Aarch64RegisterVec {
    ids: Vec<u64>,
    data: Vec<u8>,
}

impl Aarch64RegisterVec {
    /// Returns the number of elements in the vector.
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// Returns true if the vector contains no elements.
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// Appends a register to the vector, copying register data.
    pub fn push(&mut self, reg: Aarch64RegisterRef<'_>) {
        self.ids.push(reg.id);
        self.data.extend_from_slice(reg.data);
    }

    /// Returns an iterator over stored registers.
    pub fn iter(&self) -> impl Iterator<Item = Aarch64RegisterRef> {
        Aarch64RegisterVecIterator {
            index: 0,
            offset: 0,
            ids: &self.ids,
            data: &self.data,
        }
    }

    /// Returns an iterator over stored registers that allows register modifications.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = Aarch64RegisterRefMut> {
        Aarch64RegisterVecIteratorMut {
            index: 0,
            offset: 0,
            ids: &self.ids,
            data: &mut self.data,
        }
    }
}

impl Serialize for Aarch64RegisterVec {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Serialize::serialize(&(&self.ids, &self.data), serializer)
    }
}

impl<'de> Deserialize<'de> for Aarch64RegisterVec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (ids, data): (Vec<u64>, Vec<u8>) = Deserialize::deserialize(deserializer)?;

        let mut total_size: usize = 0;
        for id in ids.iter() {
            let reg_size = reg_size(*id);
            if reg_size > RegSize::U2048_SIZE {
                return Err(serde::de::Error::custom(
                    "Failed to deserialize aarch64 registers. Registers bigger than 2048 bits are \
                     not supported",
                ));
            }
            total_size += reg_size;
        }

        if total_size != data.len() {
            return Err(serde::de::Error::custom(
                "Failed to deserialize aarch64 registers. Sum of register sizes is not equal to \
                 registers data length",
            ));
        }

        Ok(Aarch64RegisterVec { ids, data })
    }
}

/// Iterator over `Aarch64RegisterVec`.
#[derive(Debug)]
pub struct Aarch64RegisterVecIterator<'a> {
    index: usize,
    offset: usize,
    ids: &'a [u64],
    data: &'a [u8],
}

impl<'a> Iterator for Aarch64RegisterVecIterator<'a> {
    type Item = Aarch64RegisterRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.ids.len() {
            let id = self.ids[self.index];
            let reg_size = reg_size(id);
            let reg_ref = Aarch64RegisterRef {
                id,
                data: &self.data[self.offset..self.offset + reg_size],
            };
            self.index += 1;
            self.offset += reg_size;
            Some(reg_ref)
        } else {
            None
        }
    }
}

/// Iterator over `Aarch64RegisterVec` with mutable values.
#[derive(Debug)]
pub struct Aarch64RegisterVecIteratorMut<'a> {
    index: usize,
    offset: usize,
    ids: &'a [u64],
    data: &'a mut [u8],
}

impl<'a> Iterator for Aarch64RegisterVecIteratorMut<'a> {
    type Item = Aarch64RegisterRefMut<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.ids.len() {
            let id = self.ids[self.index];
            let reg_size = reg_size(id);

            let data = std::mem::take(&mut self.data);
            let (head, tail) = data.split_at_mut(reg_size);

            self.index += 1;
            self.offset += reg_size;
            self.data = tail;
            Some(Aarch64RegisterRefMut { id, data: head })
        } else {
            None
        }
    }
}

/// Reference to the aarch64 register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aarch64RegisterRef<'a> {
    /// ID of the register
    pub id: u64,
    data: &'a [u8],
}

impl<'a> Aarch64RegisterRef<'a> {
    /// Creates new register reference with provided id and data.
    /// Register size in `id` should be equal to the
    /// length of the slice. Otherwise this method
    /// will panic.
    pub fn new(id: u64, data: &'a [u8]) -> Self {
        assert_eq!(
            reg_size(id),
            data.len(),
            "Attempt to create a register reference with incompatible id and data length"
        );

        Self { id, data }
    }

    /// Returns register size in bytes
    pub fn size(&self) -> RegSize {
        reg_size(self.id).into()
    }

    /// Returns a register value.
    /// Type `T` must be of the same length as an
    /// underlying data slice. Otherwise this method
    /// will panic.
    pub fn value<T: Aarch64RegisterData<N>, const N: usize>(&self) -> T {
        T::from_slice(self.data)
    }

    /// Returns register data as a byte slice
    pub fn as_slice(&self) -> &[u8] {
        self.data
    }
}

/// Reference to the aarch64 register.
#[derive(Debug, PartialEq, Eq)]
pub struct Aarch64RegisterRefMut<'a> {
    /// ID of the register
    pub id: u64,
    data: &'a mut [u8],
}

impl<'a> Aarch64RegisterRefMut<'a> {
    /// Creates new register reference with provided id and data.
    /// Register size in `id` should be equal to the
    /// length of the slice. Otherwise this method
    /// will panic.
    pub fn new(id: u64, data: &'a mut [u8]) -> Self {
        assert_eq!(
            reg_size(id),
            data.len(),
            "Attempt to create a register reference with incompatible id and data length"
        );

        Self { id, data }
    }

    /// Returns register size in bytes
    pub fn size(&self) -> RegSize {
        reg_size(self.id).into()
    }

    /// Returns a register value.
    /// Type `T` must be of the same length as an
    /// underlying data slice. Otherwise this method
    /// will panic.
    pub fn value<T: Aarch64RegisterData<N>, const N: usize>(&self) -> T {
        T::from_slice(self.data)
    }

    /// Sets the register value.
    /// Type `T` must be of the same length as an
    /// underlying data slice. Otherwise this method
    /// will panic.
    pub fn set_value<T: Aarch64RegisterData<N>, const N: usize>(&mut self, value: T) {
        self.data.copy_from_slice(&value.to_bytes())
    }
}

/// Trait for data types that can represent aarch64
/// register data.
pub trait Aarch64RegisterData<const N: usize> {
    /// Create data type from slice
    fn from_slice(slice: &[u8]) -> Self;
    /// Convert data type to array of bytes
    fn to_bytes(&self) -> [u8; N];
}

macro_rules! reg_data {
    ($t:ty, $bytes: expr) => {
        impl Aarch64RegisterData<$bytes> for $t {
            fn from_slice(slice: &[u8]) -> Self {
                let mut bytes = [0_u8; $bytes];
                bytes.copy_from_slice(slice);
                <$t>::from_le_bytes(bytes)
            }

            fn to_bytes(&self) -> [u8; $bytes] {
                self.to_le_bytes()
            }
        }
    };
}

macro_rules! reg_data_array {
    ($t:ty, $bytes: expr) => {
        impl Aarch64RegisterData<$bytes> for $t {
            fn from_slice(slice: &[u8]) -> Self {
                let mut bytes = [0_u8; $bytes];
                bytes.copy_from_slice(slice);
                bytes
            }

            fn to_bytes(&self) -> [u8; $bytes] {
                *self
            }
        }
    };
}

reg_data!(u8, 1);
reg_data!(u16, 2);
reg_data!(u32, 4);
reg_data!(u64, 8);
reg_data!(u128, 16);
// 256
reg_data_array!([u8; 32], 32);
// 512
reg_data_array!([u8; 64], 64);
// 1024
reg_data_array!([u8; 128], 128);
// 2048
reg_data_array!([u8; 256], 256);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::Snapshot;

    #[test]
    fn test_reg_size() {
        assert_eq!(reg_size(KVM_REG_SIZE_U32), 4);
        // ID_AA64PFR0_EL1 is 64 bit register
        assert_eq!(reg_size(ID_AA64PFR0_EL1), 8);
    }

    #[test]
    fn test_aarch64_register_vec_serde() {
        let mut v = Aarch64RegisterVec::default();

        let reg1_bytes = 1_u8.to_le_bytes();
        let reg1 = Aarch64RegisterRef::new(u64::from(KVM_REG_SIZE_U8), &reg1_bytes);
        let reg2_bytes = 2_u16.to_le_bytes();
        let reg2 = Aarch64RegisterRef::new(KVM_REG_SIZE_U16, &reg2_bytes);

        v.push(reg1);
        v.push(reg2);

        let mut buf = vec![0; 10000];

        Snapshot::serialize(&mut buf.as_mut_slice(), &v).unwrap();
        let restored: Aarch64RegisterVec = Snapshot::deserialize(&mut buf.as_slice()).unwrap();

        for (old, new) in v.iter().zip(restored.iter()) {
            assert_eq!(old, new);
        }
    }

    #[test]
    fn test_aarch64_register_vec_serde_invalid_regs_size_sum() {
        let mut v = Aarch64RegisterVec::default();

        let reg1_bytes = 1_u8.to_le_bytes();
        // Creating invalid register with incompatible ID and reg size.
        let reg1 = Aarch64RegisterRef {
            id: KVM_REG_SIZE_U16,
            data: &reg1_bytes,
        };
        let reg2_bytes = 2_u16.to_le_bytes();
        let reg2 = Aarch64RegisterRef::new(KVM_REG_SIZE_U16, &reg2_bytes);

        v.push(reg1);
        v.push(reg2);

        let mut buf = vec![0; 10000];

        Snapshot::serialize(&mut buf.as_mut_slice(), &v).unwrap();

        // Total size of registers according IDs are 16 + 16 = 32,
        // but actual data size is 8 + 16 = 24.
        Snapshot::deserialize::<_, Aarch64RegisterVec>(&mut buf.as_slice()).unwrap_err();
    }

    #[test]
    fn test_aarch64_register_vec_serde_invalid_reg_size() {
        let mut v = Aarch64RegisterVec::default();

        let reg_bytes = [0_u8; 512];
        // Creating invalid register with incompatible size.
        // 512 bytes for 4096 bit wide register.
        let reg = Aarch64RegisterRef {
            id: 0x0090000000000000,
            data: &reg_bytes,
        };

        v.push(reg);

        let mut buf = vec![0; 10000];

        Snapshot::serialize(&mut buf.as_mut_slice(), &v).unwrap();

        // 4096 bit wide registers are not supported.
        Snapshot::deserialize::<_, Aarch64RegisterVec>(&mut buf.as_slice()).unwrap_err();
    }

    #[test]
    fn test_aarch64_register_vec() {
        let mut v = Aarch64RegisterVec::default();

        let reg1_bytes = 1_u8.to_le_bytes();
        let reg1 = Aarch64RegisterRef::new(u64::from(KVM_REG_SIZE_U8), &reg1_bytes);
        let reg2_bytes = 2_u16.to_le_bytes();
        let reg2 = Aarch64RegisterRef::new(KVM_REG_SIZE_U16, &reg2_bytes);
        let reg3_bytes = 3_u32.to_le_bytes();
        let reg3 = Aarch64RegisterRef::new(KVM_REG_SIZE_U32, &reg3_bytes);
        let reg4_bytes = 4_u64.to_le_bytes();
        let reg4 = Aarch64RegisterRef::new(KVM_REG_SIZE_U64, &reg4_bytes);
        let reg5_bytes = 5_u128.to_le_bytes();
        let reg5 = Aarch64RegisterRef::new(KVM_REG_SIZE_U128, &reg5_bytes);
        let reg6 = Aarch64RegisterRef::new(KVM_REG_SIZE_U256, &[6; 32]);
        let reg7 = Aarch64RegisterRef::new(KVM_REG_SIZE_U512, &[7; 64]);
        let reg8 = Aarch64RegisterRef::new(KVM_REG_SIZE_U1024, &[8; 128]);
        let reg9 = Aarch64RegisterRef::new(KVM_REG_SIZE_U2048, &[9; 256]);

        v.push(reg1);
        v.push(reg2);
        v.push(reg3);
        v.push(reg4);
        v.push(reg5);
        v.push(reg6);
        v.push(reg7);
        v.push(reg8);
        v.push(reg9);

        assert!(!v.is_empty());
        assert_eq!(v.len(), 9);

        // Test iter
        {
            macro_rules! test_iter {
                ($iter:expr, $size: expr, $t:ty, $bytes:expr, $value:expr) => {
                    let reg_ref = $iter.next().unwrap();
                    assert_eq!(reg_ref.id, u64::from($size));
                    assert_eq!(reg_ref.value::<$t, $bytes>(), $value);
                };
            }

            let mut regs_iter = v.iter();

            test_iter!(regs_iter, KVM_REG_SIZE_U8, u8, 1, 1);
            test_iter!(regs_iter, KVM_REG_SIZE_U16, u16, 2, 2);
            test_iter!(regs_iter, KVM_REG_SIZE_U32, u32, 4, 3);
            test_iter!(regs_iter, KVM_REG_SIZE_U64, u64, 8, 4);
            test_iter!(regs_iter, KVM_REG_SIZE_U128, u128, 16, 5);
            test_iter!(regs_iter, KVM_REG_SIZE_U256, [u8; 32], 32, [6; 32]);
            test_iter!(regs_iter, KVM_REG_SIZE_U512, [u8; 64], 64, [7; 64]);
            test_iter!(regs_iter, KVM_REG_SIZE_U1024, [u8; 128], 128, [8; 128]);
            test_iter!(regs_iter, KVM_REG_SIZE_U2048, [u8; 256], 256, [9; 256]);

            assert!(regs_iter.next().is_none());
        }

        // Test iter mut
        {
            {
                macro_rules! update_value {
                    ($iter:expr, $t:ty, $bytes:expr) => {
                        let mut reg_ref = $iter.next().unwrap();
                        reg_ref.set_value(reg_ref.value::<$t, $bytes>() - 1);
                    };
                }

                let mut regs_iter_mut = v.iter_mut();

                update_value!(regs_iter_mut, u8, 1);
                update_value!(regs_iter_mut, u16, 2);
                update_value!(regs_iter_mut, u32, 4);
                update_value!(regs_iter_mut, u64, 8);
                update_value!(regs_iter_mut, u128, 16);
            }

            {
                macro_rules! test_iter {
                    ($iter:expr, $t:ty, $bytes:expr, $value:expr) => {
                        let reg_ref = $iter.next().unwrap();
                        assert_eq!(reg_ref.value::<$t, $bytes>(), $value);
                    };
                }

                let mut regs_iter = v.iter();

                test_iter!(regs_iter, u8, 1, 0);
                test_iter!(regs_iter, u16, 2, 1);
                test_iter!(regs_iter, u32, 4, 2);
                test_iter!(regs_iter, u64, 8, 3);
                test_iter!(regs_iter, u128, 16, 4);
            }
        }
    }

    #[test]
    fn test_reg_ref() {
        let bytes = 69_u64.to_le_bytes();
        let reg_ref = Aarch64RegisterRef::new(KVM_REG_SIZE_U64, &bytes);

        assert_eq!(usize::from(reg_ref.size()), 8);
        assert_eq!(reg_ref.value::<u64, 8>(), 69);
    }

    /// Should panic because ID has different size from a slice length.
    /// - Size in ID: 128
    /// - Length of slice: 1
    #[test]
    #[should_panic]
    fn test_reg_ref_new_must_panic() {
        let _ = Aarch64RegisterRef::new(KVM_REG_SIZE_U128, &[0; 1]);
    }

    /// Should panic because of incorrect cast to value.
    /// - Reference contains 64 bit register
    /// - Casting to 128 bits.
    #[test]
    #[should_panic]
    fn test_reg_ref_value_must_panic() {
        let bytes = 69_u64.to_le_bytes();
        let reg_ref = Aarch64RegisterRef::new(KVM_REG_SIZE_U64, &bytes);
        assert_eq!(reg_ref.value::<u128, 16>(), 69);
    }

    #[test]
    fn test_reg_ref_mut() {
        let mut bytes = 69_u64.to_le_bytes();
        let mut reg_ref = Aarch64RegisterRefMut::new(KVM_REG_SIZE_U64, &mut bytes);

        assert_eq!(usize::from(reg_ref.size()), 8);
        assert_eq!(reg_ref.value::<u64, 8>(), 69);
        reg_ref.set_value(reg_ref.value::<u64, 8>() + 1);
        assert_eq!(reg_ref.value::<u64, 8>(), 70);
    }

    /// Should panic because ID has different size from a slice length.
    /// - Size in ID: 128
    /// - Length of slice: 1
    #[test]
    #[should_panic]
    fn test_reg_ref_mut_new_must_panic() {
        let _ = Aarch64RegisterRefMut::new(KVM_REG_SIZE_U128, &mut [0; 1]);
    }

    /// Should panic because of incorrect cast to value.
    /// - Reference contains 64 bit register
    /// - Casting to 128 bits.
    #[test]
    #[should_panic]
    fn test_reg_ref_mut_must_panic() {
        let mut bytes = 69_u64.to_le_bytes();
        let reg_ref = Aarch64RegisterRefMut::new(KVM_REG_SIZE_U64, &mut bytes);
        assert_eq!(reg_ref.value::<u128, 16>(), 69);
    }
}
