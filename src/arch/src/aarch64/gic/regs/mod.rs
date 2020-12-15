mod dist_regs;
mod icc_regs;
mod redist_regs;

use crate::aarch64::gic::{Error, Result};
use kvm_bindings::kvm_device_attr;
use kvm_ioctls::DeviceFd;
use std::fmt::Debug;
use std::iter::StepBy;
use std::ops::Range;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;

#[derive(Debug)]
pub struct GicRegState<T: Versionize> {
    pub(crate) chunks: Vec<T>,
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

    fn mpidr_mask() -> u64;

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
    ) -> Result<GicRegState<Self::RegChunk>>
    where
        Self: Sized,
    {
        let mut data = Vec::with_capacity(reg.iter::<Self::RegChunk>().count());
        for offset in reg.iter::<Self::RegChunk>() {
            let mut val = Self::RegChunk::default();
            fd.get_device_attr(&mut Self::kvm_device_attr(offset, &mut val, mpidr))
                .map_err(|e| Error::DeviceAttribute(e, false, Self::group()))?;
            data.push(val);
        }

        Ok(GicRegState { chunks: data })
    }

    fn get_regs_data(
        fd: &DeviceFd,
        regs: Box<dyn Iterator<Item = &Self::Reg>>,
        mpidr: u64,
    ) -> Result<Vec<GicRegState<Self::RegChunk>>>
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
    ) -> Result<()>
    where
        Self: Sized,
    {
        for (offset, val) in reg.iter::<Self::RegChunk>().zip(&data.chunks) {
            fd.set_device_attr(&Self::kvm_device_attr(offset, &mut val.clone(), mpidr))
                .map_err(|e| Error::DeviceAttribute(e, true, Self::group()))?;
        }

        Ok(())
    }

    fn set_regs_data(
        fd: &DeviceFd,
        regs: Box<dyn Iterator<Item = &Self::Reg>>,
        data: &[GicRegState<Self::RegChunk>],
        mpidr: u64,
    ) -> Result<()>
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
    const fn new(offset: u64, size: u16) -> SimpleReg {
        SimpleReg { offset, size }
    }
}

impl MmioReg for SimpleReg {
    fn range(&self) -> Range<u64> {
        self.offset..self.offset + u64::from(self.size)
    }
}

/// Structure used for serializing the state of the GIC registers
#[derive(Debug, Default, Versionize)]
pub struct GicState {
    dist: Vec<GicRegState<u32>>,
    gic_vcpu_states: Vec<GicVcpuState>,
}

/// Structure used for serializing the state of the GIC registers for a specific vCPU
#[derive(Debug, Default, Versionize)]
pub struct GicVcpuState {
    rdist: Vec<GicRegState<u32>>,
    icc: icc_regs::VgicSysRegsState,
}

/// Save the state of the GIC device.
pub fn save_state(fd: &DeviceFd, mpidrs: &[u64]) -> Result<GicState> {
    // Flush redistributors pending tables to guest RAM.
    super::save_pending_tables(fd)?;

    let mut vcpu_states = Vec::with_capacity(mpidrs.len());
    for mpidr in mpidrs {
        vcpu_states.push(GicVcpuState {
            rdist: redist_regs::get_redist_regs(fd, *mpidr)?,
            icc: icc_regs::get_icc_regs(fd, *mpidr)?,
        })
    }

    Ok(GicState {
        dist: dist_regs::get_dist_regs(fd)?,
        gic_vcpu_states: vcpu_states,
    })
}

/// Restore the state of the GIC device.
pub fn restore_state(fd: &DeviceFd, mpidrs: &[u64], state: &GicState) -> Result<()> {
    dist_regs::set_dist_regs(fd, &state.dist)?;

    if mpidrs.len() != state.gic_vcpu_states.len() {
        return Err(Error::InconsistentVcpuCount);
    }
    for (mpidr, vcpu_state) in mpidrs.iter().zip(&state.gic_vcpu_states) {
        redist_regs::set_redist_regs(fd, *mpidr, &vcpu_state.rdist)?;
        icc_regs::set_icc_regs(fd, *mpidr, &vcpu_state.icc)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::gic::create_gic;
    use kvm_ioctls::Kvm;

    #[test]
    fn test_vm_save_restore_state() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let gic = create_gic(&vm, 1).expect("Cannot create gic");
        let gic_fd = gic.device_fd();

        let mpidr = vec![1];
        let res = save_state(gic_fd, &mpidr);
        // We will receive an error if trying to call before creating vcpu.
        assert!(res.is_err());
        assert_eq!(
            format!("{:?}", res.unwrap_err()),
            "DeviceAttribute(Error(22), false, 5)"
        );

        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let _vcpu = vm.create_vcpu(0).unwrap();
        let gic = create_gic(&vm, 1).expect("Cannot create gic");
        let gic_fd = gic.device_fd();

        let vm_state = save_state(gic_fd, &mpidr).unwrap();
        let val: u32 = 0;
        let gicd_statusr_off = 0x0010;
        let mut gic_dist_attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_DIST_REGS,
            attr: gicd_statusr_off as u64,
            addr: &val as *const u32 as u64,
            flags: 0,
        };
        gic_fd.get_device_attr(&mut gic_dist_attr).unwrap();

        // The second value from the list of distributor registers is the value of the GICD_STATUSR register.
        // We assert that the one saved in the bitmap is the same with the one we obtain
        // with KVM_GET_DEVICE_ATTR.
        let gicd_statusr = &vm_state.dist[1];

        assert_eq!(gicd_statusr.chunks[0], val);
        assert_eq!(vm_state.dist.len(), 12);
        assert!(restore_state(gic_fd, &mpidr, &vm_state).is_ok());
    }
}
