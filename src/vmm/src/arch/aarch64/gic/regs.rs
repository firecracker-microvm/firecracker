// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::iter::StepBy;
use std::ops::Range;

use kvm_bindings::kvm_device_attr;
use kvm_ioctls::DeviceFd;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;

use crate::arch::aarch64::gic::GicError;

#[derive(Debug)]
pub struct GicRegState<T: Versionize> {
    pub(crate) chunks: Vec<T>,
}

/// Structure for serializing the state of the Vgic ICC regs
#[derive(Debug, Default, Versionize)]
pub struct VgicSysRegsState {
    pub main_icc_regs: Vec<GicRegState<u64>>,
    pub ap_icc_regs: Vec<Option<GicRegState<u64>>>,
}

/// Structure used for serializing the state of the GIC registers.
#[derive(Debug, Default, Versionize)]
pub struct GicState {
    /// The state of the distributor registers.
    pub dist: Vec<GicRegState<u32>>,
    /// The state of the vcpu interfaces.
    pub gic_vcpu_states: Vec<GicVcpuState>,
}

/// Structure used for serializing the state of the GIC registers for a specific vCPU.
#[derive(Debug, Default, Versionize)]
pub struct GicVcpuState {
    pub rdist: Vec<GicRegState<u32>>,
    pub icc: VgicSysRegsState,
}

impl<T: Versionize> Versionize for GicRegState<T> {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
        version_map: &VersionMap,
        app_version: u16,
    ) -> VersionizeResult<()> {
        let chunks = &self.chunks;
        assert_eq!(std::mem::size_of_val(chunks), std::mem::size_of::<Self>());
        Versionize::serialize(chunks, writer, version_map, app_version)
    }

    fn deserialize<R: std::io::Read>(
        reader: &mut R,
        version_map: &VersionMap,
        app_version: u16,
    ) -> VersionizeResult<Self> {
        let chunks = Versionize::deserialize(reader, version_map, app_version)?;
        assert_eq!(std::mem::size_of_val(&chunks), std::mem::size_of::<Self>());
        Ok(Self { chunks })
    }

    fn version() -> u16 {
        1
    }
}

pub(crate) trait MmioReg {
    fn range(&self) -> Range<u64>;

    fn iter<T>(&self) -> StepBy<Range<u64>>
    where
        Self: Sized,
    {
        self.range().step_by(std::mem::size_of::<T>())
    }
}

pub(crate) trait VgicRegEngine {
    type Reg: MmioReg;
    type RegChunk: Clone + Default + Versionize;

    fn group() -> u32;

    fn mpidr_mask() -> u64 {
        0
    }

    fn kvm_device_attr(offset: u64, val: &mut Self::RegChunk, mpidr: u64) -> kvm_device_attr {
        kvm_device_attr {
            group: Self::group(),
            attr: (mpidr & Self::mpidr_mask()) | offset,
            addr: val as *mut Self::RegChunk as u64,
            flags: 0,
        }
    }

    #[inline]
    fn get_reg_data(
        fd: &DeviceFd,
        reg: &Self::Reg,
        mpidr: u64,
    ) -> Result<GicRegState<Self::RegChunk>, GicError>
    where
        Self: Sized,
    {
        let mut data = Vec::with_capacity(reg.iter::<Self::RegChunk>().count());
        for offset in reg.iter::<Self::RegChunk>() {
            let mut val = Self::RegChunk::default();
            fd.get_device_attr(&mut Self::kvm_device_attr(offset, &mut val, mpidr))
                .map_err(|err| GicError::DeviceAttribute(err, false, Self::group()))?;
            data.push(val);
        }

        Ok(GicRegState { chunks: data })
    }

    fn get_regs_data(
        fd: &DeviceFd,
        regs: Box<dyn Iterator<Item = &Self::Reg>>,
        mpidr: u64,
    ) -> Result<Vec<GicRegState<Self::RegChunk>>, GicError>
    where
        Self: Sized,
    {
        let mut data = Vec::new();
        for reg in regs {
            data.push(Self::get_reg_data(fd, reg, mpidr)?);
        }

        Ok(data)
    }

    #[inline]
    fn set_reg_data(
        fd: &DeviceFd,
        reg: &Self::Reg,
        data: &GicRegState<Self::RegChunk>,
        mpidr: u64,
    ) -> Result<(), GicError>
    where
        Self: Sized,
    {
        for (offset, val) in reg.iter::<Self::RegChunk>().zip(&data.chunks) {
            fd.set_device_attr(&Self::kvm_device_attr(offset, &mut val.clone(), mpidr))
                .map_err(|err| GicError::DeviceAttribute(err, true, Self::group()))?;
        }

        Ok(())
    }

    fn set_regs_data(
        fd: &DeviceFd,
        regs: Box<dyn Iterator<Item = &Self::Reg>>,
        data: &[GicRegState<Self::RegChunk>],
        mpidr: u64,
    ) -> Result<(), GicError>
    where
        Self: Sized,
    {
        for (reg, reg_data) in regs.zip(data) {
            Self::set_reg_data(fd, reg, reg_data, mpidr)?;
        }

        Ok(())
    }
}

/// Structure representing a simple register.
#[derive(PartialEq)]
pub(crate) struct SimpleReg {
    /// The offset from the component address. The register is memory mapped here.
    offset: u64,
    /// Size in bytes.
    size: u16,
}

impl SimpleReg {
    pub const fn new(offset: u64, size: u16) -> SimpleReg {
        SimpleReg { offset, size }
    }
}

impl MmioReg for SimpleReg {
    fn range(&self) -> Range<u64> {
        self.offset..self.offset + u64::from(self.size)
    }
}
