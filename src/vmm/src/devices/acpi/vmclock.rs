// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::convert::Infallible;
use std::mem::offset_of;
use std::sync::atomic::{Ordering, fence};

use acpi_tables::{Aml, aml};
use log::{debug, error};
use serde::{Deserialize, Serialize};
use vm_allocator::AllocPolicy;
use vm_memory::{Address, ByteValued, Bytes, GuestAddress, GuestMemoryError};
use vm_superio::Trigger;
use vmm_sys_util::eventfd::EventFd;

use crate::Vm;
use crate::devices::acpi::generated::vmclock_abi::{
    VMCLOCK_COUNTER_INVALID, VMCLOCK_FLAG_NOTIFICATION_PRESENT,
    VMCLOCK_FLAG_VM_GEN_COUNTER_PRESENT, VMCLOCK_MAGIC, VMCLOCK_STATUS_UNKNOWN, vmclock_abi,
};
use crate::devices::legacy::EventFdTrigger;
use crate::snapshot::Persist;
use crate::vstate::memory::GuestMemoryMmap;
use crate::vstate::resources::ResourceAllocator;

// SAFETY: `vmclock_abi` is a POD
unsafe impl ByteValued for vmclock_abi {}

// We are reserving a physical page to expose the [`VmClock`] data
const VMCLOCK_SIZE: u32 = 0x1000;

// Write a value in `vmclock_abi` both in the Firecracker-managed state
// and inside guest memory address that corresponds to it.
macro_rules! write_vmclock_field {
    ($vmclock:expr, $mem:expr, $field:ident, $value:expr) => {
        $vmclock.inner.$field = $value;
        $mem.write_obj(
            $vmclock.inner.$field,
            $vmclock
                .guest_address
                .unchecked_add(offset_of!(vmclock_abi, $field) as u64),
        );
    };
}

/// VMclock device
///
/// This device emulates the VMclock device which allows passing information to the guest related
/// to the relation of the host CPU to real-time clock as well as information about disruptive
/// events, such as live-migration.
#[derive(Debug)]
pub struct VmClock {
    /// Guest address in which we will write the VMclock struct
    pub guest_address: GuestAddress,
    /// Interrupt line for notifying the device about changes
    pub interrupt_evt: EventFdTrigger,
    /// GSI number allocated for the device.
    pub gsi: u32,
    /// The [`VmClock`] state we are exposing to the guest
    inner: vmclock_abi,
}

impl VmClock {
    /// Create a new [`VmClock`] device for a newly booted VM
    pub fn new(resource_allocator: &mut ResourceAllocator) -> VmClock {
        let addr = resource_allocator
            .allocate_system_memory(
                VMCLOCK_SIZE as u64,
                VMCLOCK_SIZE as u64,
                AllocPolicy::LastMatch,
            )
            .expect("vmclock: could not allocate guest memory for device");

        let gsi = resource_allocator
            .allocate_gsi_legacy(1)
            .inspect_err(|err| error!("vmclock: Could not allocate GSI for VMClock: {err}"))
            .unwrap()[0];

        let interrupt_evt = EventFdTrigger::new(
            EventFd::new(libc::EFD_NONBLOCK)
                .inspect_err(|err| {
                    error!("vmclock: Could not create EventFd for VMClock device: {err}")
                })
                .unwrap(),
        );

        let mut inner = vmclock_abi {
            magic: VMCLOCK_MAGIC,
            size: VMCLOCK_SIZE,
            version: 1,
            clock_status: VMCLOCK_STATUS_UNKNOWN,
            counter_id: VMCLOCK_COUNTER_INVALID,
            flags: VMCLOCK_FLAG_VM_GEN_COUNTER_PRESENT | VMCLOCK_FLAG_NOTIFICATION_PRESENT,
            ..Default::default()
        };

        VmClock {
            guest_address: GuestAddress(addr),
            interrupt_evt,
            gsi,
            inner,
        }
    }

    /// Activate [`VmClock`] device
    pub fn activate(&self, mem: &GuestMemoryMmap) -> Result<(), GuestMemoryError> {
        mem.write_slice(self.inner.as_slice(), self.guest_address)?;
        Ok(())
    }

    /// Bump the VM generation counter
    pub fn post_load_update(&mut self, mem: &GuestMemoryMmap) {
        write_vmclock_field!(self, mem, seq_count, self.inner.seq_count | 1);

        // This fence ensures guest sees all previous writes. It is matched to a
        // read barrier in the guest.
        fence(Ordering::Release);

        write_vmclock_field!(
            self,
            mem,
            disruption_marker,
            self.inner.disruption_marker.wrapping_add(1)
        );

        write_vmclock_field!(
            self,
            mem,
            vm_generation_counter,
            self.inner.vm_generation_counter.wrapping_add(1)
        );

        // This fence ensures guest sees the `disruption_marker` and `vm_generation_counter`
        // updates. It is matched to a read barrier in the guest.
        fence(Ordering::Release);

        write_vmclock_field!(self, mem, seq_count, self.inner.seq_count.wrapping_add(1));
        self.interrupt_evt
            .trigger()
            .inspect_err(|err| error!("vmclock: could not send guest notification: {err}"))
            .unwrap();
        debug!("vmclock: notifying guest about VMClock updates");
    }
}

/// (De)serialize-able state of the [`VmClock`]
///
/// We could avoid this and reuse [`VmClock`] itself if `GuestAddress` was `Serialize`/`Deserialize`
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct VmClockState {
    /// Guest address in which we write the [`VmClock`] info
    pub guest_address: u64,
    /// GSI used for notifying the guest about device changes
    pub gsi: u32,
    /// Data we expose to the guest
    pub inner: vmclock_abi,
}

impl<'a> Persist<'a> for VmClock {
    type State = VmClockState;
    type ConstructorArgs = ();
    type Error = Infallible;

    fn save(&self) -> Self::State {
        VmClockState {
            guest_address: self.guest_address.0,
            gsi: self.gsi,
            inner: self.inner,
        }
    }

    fn restore(vm: Self::ConstructorArgs, state: &Self::State) -> Result<Self, Self::Error> {
        let interrupt_evt = EventFdTrigger::new(
            EventFd::new(libc::EFD_NONBLOCK)
                .inspect_err(|err| {
                    error!("vmclock: Could not create EventFd for VMClock device: {err}")
                })
                .unwrap(),
        );
        let mut vmclock = VmClock {
            guest_address: GuestAddress(state.guest_address),
            interrupt_evt,
            gsi: state.gsi,
            inner: state.inner,
        };
        Ok(vmclock)
    }
}

impl Aml for VmClock {
    fn append_aml_bytes(&self, v: &mut Vec<u8>) -> Result<(), aml::AmlError> {
        aml::Device::new(
            "_SB_.VCLK".try_into()?,
            vec![
                &aml::Name::new("_HID".try_into()?, &"AMZNC10C")?,
                &aml::Name::new("_CID".try_into()?, &"VMCLOCK")?,
                &aml::Name::new("_DDN".try_into()?, &"VMCLOCK")?,
                &aml::Method::new(
                    "_STA".try_into()?,
                    0,
                    false,
                    vec![&aml::Return::new(&0x0fu8)],
                ),
                &aml::Name::new(
                    "_CRS".try_into()?,
                    &aml::ResourceTemplate::new(vec![&aml::AddressSpace::new_memory(
                        aml::AddressSpaceCacheable::Cacheable,
                        false,
                        self.guest_address.0,
                        self.guest_address.0 + VMCLOCK_SIZE as u64 - 1,
                    )?]),
                )?,
            ],
        )
        .append_aml_bytes(v)
    }
}

#[cfg(test)]
mod tests {
    use vm_memory::{Bytes, GuestAddress};
    use vmm_sys_util::tempfile::TempFile;

    use crate::Vm;
    #[cfg(target_arch = "x86_64")]
    use crate::arch::x86_64::layout;
    use crate::arch::{self, Kvm};
    use crate::devices::acpi::generated::vmclock_abi::vmclock_abi;
    use crate::devices::acpi::vmclock::{VMCLOCK_SIZE, VmClock};
    use crate::devices::virtio::test_utils::default_mem;
    use crate::snapshot::{Persist, Snapshot};
    use crate::test_utils::single_region_mem;
    use crate::utils::u64_to_usize;
    use crate::vstate::resources::ResourceAllocator;
    use crate::vstate::vm::tests::setup_vm_with_memory;

    // We are allocating memory from the end of the system memory portion
    const VMCLOCK_TEST_GUEST_ADDR: GuestAddress =
        GuestAddress(arch::SYSTEM_MEM_START + arch::SYSTEM_MEM_SIZE - VMCLOCK_SIZE as u64);

    fn default_vmclock() -> VmClock {
        let mut resource_allocator = ResourceAllocator::new();
        VmClock::new(&mut resource_allocator)
    }

    #[test]
    fn test_new_device() {
        let vmclock = default_vmclock();
        let mem = single_region_mem(
            u64_to_usize(arch::SYSTEM_MEM_START) + u64_to_usize(arch::SYSTEM_MEM_SIZE),
        );

        let guest_data: vmclock_abi = mem.read_obj(VMCLOCK_TEST_GUEST_ADDR).unwrap();
        assert_ne!(guest_data, vmclock.inner);

        vmclock.activate(&mem);

        let guest_data: vmclock_abi = mem.read_obj(VMCLOCK_TEST_GUEST_ADDR).unwrap();
        assert_eq!(guest_data, vmclock.inner);
    }

    #[test]
    fn test_device_save_restore() {
        let vmclock = default_vmclock();
        // We're using memory inside the system memory portion of the guest RAM. So we need a
        // memory region that includes it.
        let mem = single_region_mem(
            u64_to_usize(arch::SYSTEM_MEM_START) + u64_to_usize(arch::SYSTEM_MEM_SIZE),
        );

        vmclock.activate(&mem).unwrap();

        let state = vmclock.save();
        let mut vmclock_new = VmClock::restore((), &state).unwrap();
        vmclock_new.post_load_update(&mem);

        let guest_data_new: vmclock_abi = mem.read_obj(VMCLOCK_TEST_GUEST_ADDR).unwrap();
        assert_ne!(guest_data_new, vmclock.inner);
        assert_eq!(guest_data_new, vmclock_new.inner);
        assert_eq!(
            vmclock.inner.disruption_marker + 1,
            vmclock_new.inner.disruption_marker
        );
        assert_eq!(
            vmclock.inner.vm_generation_counter + 1,
            vmclock_new.inner.vm_generation_counter
        );
    }
}
