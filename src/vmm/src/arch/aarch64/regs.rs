// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use kvm_bindings::*;
use versionize::*;
use versionize_derive::Versionize;

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

// Following are macros that help with getting the ID of a aarch64 core register.
// The core register are represented by the user_pt_regs structure. Look for it in
// arch/arm64/include/uapi/asm/ptrace.h.

/// Gets offset of a member (`field`) within a struct (`container`).
/// Same as bindgen offset tests.
macro_rules! offset__of {
    ($container:ty, $field:ident) => {
        // SAFETY: The implementation closely matches that of the memoffset crate,
        // which have been under extensive review.
        unsafe {
            let uninit = std::mem::MaybeUninit::<$container>::uninit();
            let ptr = uninit.as_ptr();
            std::ptr::addr_of!((*ptr).$field) as usize - ptr as usize
        }
    };
}
pub(crate) use offset__of;

/// Gets a core id.
macro_rules! arm64_core_reg_id {
    ($size: tt, $offset: tt) => {
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
            | u64::from(KVM_REG_ARM_CORE)
            | $size
            | (($offset / std::mem::size_of::<u32>()) as u64)
    };
}
pub(crate) use arm64_core_reg_id;
use utils::vm_memory::ByteValued;

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

// EL0 Virtual Timer Registers
arm64_sys_reg!(KVM_REG_ARM_TIMER_CNT, 3, 3, 14, 3, 2);

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
    pub const U8_SIZE: u64 = 1;
    /// Size of u16 register in bytes
    pub const U16_SIZE: u64 = 2;
    /// Size of u32 register in bytes
    pub const U32_SIZE: u64 = 4;
    /// Size of u64 register in bytes
    pub const U64_SIZE: u64 = 8;
    /// Size of u128 register in bytes
    pub const U128_SIZE: u64 = 16;
    /// Size of u256 register in bytes
    pub const U256_SIZE: u64 = 32;
    /// Size of u512 register in bytes
    pub const U512_SIZE: u64 = 64;
    /// Size of u1024 register in bytes
    pub const U1024_SIZE: u64 = 128;
    /// Size of u2048 register in bytes
    pub const U2048_SIZE: u64 = 256;
}

impl From<u64> for RegSize {
    fn from(value: u64) -> Self {
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

impl From<RegSize> for u64 {
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
pub fn reg_size(reg_id: u64) -> u64 {
    2_u64.pow(((reg_id & KVM_REG_SIZE_MASK) >> KVM_REG_SIZE_SHIFT) as u32)
}

/// Storage for aarch64 registers with different sizes.
/// For public usage it is wrapped into `Aarch64RegisterVec`
/// which ensures correctness after deserialization.
#[derive(Default, Debug, Clone, PartialEq, Eq, Versionize)]
struct Aarch64RegisterVecInner {
    ids: Vec<u64>,
    data: Vec<u8>,
}

impl Aarch64RegisterVecInner {
    /// Returns the number of elements in the vector.
    fn len(&self) -> usize {
        self.ids.len()
    }

    /// Returns true if the vector contains no elements.
    fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// Appends a register to the vector, copying register data.
    fn push(&mut self, reg: Aarch64RegisterRef<'_>) {
        self.ids.push(reg.id);
        self.data.extend_from_slice(reg.data);
    }

    /// Returns an iterator over stored registers.
    fn iter(&self) -> impl Iterator<Item = Aarch64RegisterRef> {
        Aarch64RegisterVecIterator {
            index: 0,
            offset: 0,
            ids: &self.ids,
            data: &self.data,
        }
    }

    /// Returns an iterator over stored registers that allows register modifications.
    fn iter_mut(&mut self) -> impl Iterator<Item = Aarch64RegisterRefMut> {
        Aarch64RegisterVecIteratorMut {
            index: 0,
            offset: 0,
            ids: &self.ids,
            data: &mut self.data,
        }
    }
}

/// Wrapper type around `Aarch64RegisterVecInner`.
/// Needed to ensure correctness of inner state after
/// deserialization.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Aarch64RegisterVec {
    inner: Aarch64RegisterVecInner,
}

impl Aarch64RegisterVec {
    /// Returns the number of elements in the vector.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if the vector contains no elements.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Appends a register to the vector, copying register data.
    pub fn push(&mut self, reg: Aarch64RegisterRef<'_>) {
        self.inner.push(reg);
    }

    /// Returns an iterator over stored registers.
    pub fn iter(&self) -> impl Iterator<Item = Aarch64RegisterRef> {
        self.inner.iter()
    }

    /// Returns an iterator over stored registers that allows register modifications.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = Aarch64RegisterRefMut> {
        self.inner.iter_mut()
    }
}

impl Versionize for Aarch64RegisterVec {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
        version_map: &VersionMap,
        target_version: u16,
    ) -> VersionizeResult<()> {
        self.inner.serialize(writer, version_map, target_version)
    }

    fn deserialize<R: std::io::Read>(
        reader: &mut R,
        version_map: &VersionMap,
        source_version: u16,
    ) -> VersionizeResult<Self>
    where
        Self: Sized,
    {
        let inner = Aarch64RegisterVecInner::deserialize(reader, version_map, source_version)?;
        let mut total_size: u64 = 0;
        for id in inner.ids.iter() {
            let reg_size = reg_size(*id);
            if RegSize::U2048_SIZE < reg_size {
                return Err(VersionizeError::Deserialize(
                    "Failed to deserialize aarch64 registers. Registers bigger then 2048 bits are \
                     not supported"
                        .to_string(),
                ));
            }
            total_size += reg_size;
        }
        if total_size as usize != inner.data.len() {
            Err(VersionizeError::Deserialize(
                "Failed to deserialize aarch64 registers. Sum of registers sizes is not equal to \
                 registers data length"
                    .to_string(),
            ))
        } else {
            Ok(Self { inner })
        }
    }

    fn version() -> u16 {
        Aarch64RegisterVecInner::version()
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
            let reg_size = reg_size(id) as usize;
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
            let reg_size = reg_size(id) as usize;

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
            reg_size(id) as usize,
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
            reg_size(id) as usize,
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

/// Old definition of a struct describing an aarch64 register.
/// This type is only used to have a backward compatibility
/// with old snapshot versions and should not be used anywhere
/// else.
#[derive(Debug, Clone, Copy, Versionize)]
pub struct Aarch64RegisterOld {
    /// ID of the register.
    pub id: u64,
    /// Register data.
    pub data: u128,
}

impl<'a> TryFrom<Aarch64RegisterRef<'a>> for Aarch64RegisterOld {
    type Error = &'static str;

    fn try_from(value: Aarch64RegisterRef) -> Result<Self, Self::Error> {
        let reg = match value.size() {
            RegSize::U32 => Self {
                id: value.id,
                data: u128::from(value.value::<u32, 4>()),
            },
            RegSize::U64 => Self {
                id: value.id,
                data: u128::from(value.value::<u64, 8>()),
            },
            RegSize::U128 => Self {
                id: value.id,
                data: value.value::<u128, 16>(),
            },
            _ => return Err("Only 32, 64 and 128 bit wide registers are supported"),
        };
        Ok(reg)
    }
}

impl<'a> TryFrom<&'a Aarch64RegisterOld> for Aarch64RegisterRef<'a> {
    type Error = &'static str;

    fn try_from(value: &'a Aarch64RegisterOld) -> Result<Self, Self::Error> {
        // # Safety:
        // `self.data` is a valid memory and slice size is valid for this type.
        let data_ref = value.data.as_slice();
        let reg_size = reg_size(value.id);
        if RegSize::U2048_SIZE < reg_size {
            return Err("Registers bigger then 2048 bits are not supported");
        }
        match RegSize::from(reg_size) {
            RegSize::U32 => Ok(Self::new(value.id, &data_ref[..std::mem::size_of::<u32>()])),
            RegSize::U64 => Ok(Self::new(value.id, &data_ref[..std::mem::size_of::<u64>()])),
            RegSize::U128 => Ok(Self::new(value.id, data_ref)),
            _ => Err("Only 32, 64 and 128 bit wide registers are supported"),
        }
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
        let version_map = VersionMap::new();

        assert!(v
            .serialize(&mut buf.as_mut_slice(), &version_map, 1)
            .is_ok());
        let restored =
            <Aarch64RegisterVec as Versionize>::deserialize(&mut buf.as_slice(), &version_map, 1)
                .unwrap();

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
        let version_map = VersionMap::new();

        assert!(v
            .serialize(&mut buf.as_mut_slice(), &version_map, 1)
            .is_ok());

        // Total size of registers according IDs are 16 + 16 = 32,
        // but actual data size is 8 + 16 = 24.
        assert!(<Aarch64RegisterVec as Versionize>::deserialize(
            &mut buf.as_slice(),
            &version_map,
            1
        )
        .is_err());
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
        let version_map = VersionMap::new();

        assert!(v
            .serialize(&mut buf.as_mut_slice(), &version_map, 1)
            .is_ok());

        // 4096 bit wide registers are not supported.
        assert!(<Aarch64RegisterVec as Versionize>::deserialize(
            &mut buf.as_slice(),
            &version_map,
            1
        )
        .is_err());
    }

    #[test]
    fn test_aarch64_register_vec_inner() {
        let mut v = Aarch64RegisterVecInner::default();

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

        assert_eq!(u64::from(reg_ref.size()), 8);
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

        assert_eq!(u64::from(reg_ref.size()), 8);
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

    #[test]
    fn test_old_reg_to_reg_ref() {
        let old_reg = Aarch64RegisterOld {
            id: KVM_REG_SIZE_U64,
            data: 69,
        };

        let reg_ref: Aarch64RegisterRef = (&old_reg).try_into().unwrap();
        assert_eq!(old_reg.id, reg_ref.id);
        assert_eq!(old_reg.data as u64, reg_ref.value::<u64, 8>());

        let old_reg = Aarch64RegisterOld {
            id: KVM_REG_SIZE_U256,
            data: 69,
        };

        let reg_ref: Result<Aarch64RegisterRef, _> = (&old_reg).try_into();
        assert!(reg_ref.is_err());

        // 4096 bit wide reg ID.
        let old_reg = Aarch64RegisterOld {
            id: 0x0090000000000000,
            data: 69,
        };

        let reg_ref: Result<Aarch64RegisterRef, _> = (&old_reg).try_into();
        assert!(reg_ref.is_err());
    }

    #[test]
    fn test_reg_ref_to_old_reg() {
        let reg_bytes = 69_u64.to_le_bytes();
        let reg_ref = Aarch64RegisterRef::new(KVM_REG_SIZE_U64, &reg_bytes);

        let reg: Aarch64RegisterOld = reg_ref.try_into().unwrap();
        assert_eq!(reg.id, reg_ref.id);
        assert_eq!(reg.data as u64, reg_ref.value::<u64, 8>());

        let reg_ref = Aarch64RegisterRef::new(KVM_REG_SIZE_U256, &[0_u8; 32]);

        let reg: Result<Aarch64RegisterOld, _> = reg_ref.try_into();
        assert!(reg.is_err());
    }
}
