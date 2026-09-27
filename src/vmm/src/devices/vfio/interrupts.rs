// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Interrupt emulation (INTx, MSI and MSI-X) for VFIO assigned devices.
//!
//! The host kernel owns the physical MSI and MSI-X configuration of an assigned device: vfio-pci
//! programs it when userspace routes the device interrupts to eventfds with
//! `VFIO_DEVICE_SET_IRQS`, and it ignores the guest's view of the capability registers. The guest
//! therefore sees a virtual MSI capability and a virtual MSI-X table maintained here, and every
//! physical interrupt is routed to an eventfd registered with KVM as an irqfd on the GSI whose route
//! holds the guest's message address and data. Delivery never exits to userspace.
//!
//! Masking is emulated by deassigning the irqfd of a masked vector: a message the device sends
//! while the vector is masked then stays pending in the eventfd, and assigning the irqfd again when
//! the vector is unmasked makes KVM deliver it (`kvm_irqfd_assign` polls the eventfd). This is
//! exactly the PCI masking semantics: a masked vector's message is held pending and sent once on
//! unmask. The pending bits the guest reads are computed from the same state.
//!
//! INTx is a level-triggered interrupt pin, routed to a legacy GSI of the guest; see [`Intx`].

use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;

use vmm_sys_util::eventfd::EventFd;

use super::generated::pci_regs::{
    PCI_MSI_ADDRESS_HI, PCI_MSI_ADDRESS_LO, PCI_MSI_DATA_32, PCI_MSI_DATA_64, PCI_MSI_FLAGS,
    PCI_MSI_FLAGS_64BIT, PCI_MSI_FLAGS_ENABLE, PCI_MSI_FLAGS_MASKBIT, PCI_MSI_FLAGS_QMASK,
    PCI_MSI_FLAGS_QSIZE, PCI_MSI_MASK_32, PCI_MSI_MASK_64, PCI_MSI_PENDING_32, PCI_MSI_PENDING_64,
    PCI_MSIX_ENTRY_CTRL_MASKBIT, PCI_MSIX_ENTRY_DATA, PCI_MSIX_ENTRY_LOWER_ADDR,
    PCI_MSIX_ENTRY_SIZE, PCI_MSIX_ENTRY_UPPER_ADDR, PCI_MSIX_ENTRY_VECTOR_CTRL,
    PCI_MSIX_FLAGS_ENABLE, PCI_MSIX_FLAGS_MASKALL, PCI_MSIX_FLAGS_QSIZE,
};
use super::generated::vfio::_bindgen_ty_2::{
    VFIO_PCI_INTX_IRQ_INDEX, VFIO_PCI_MSI_IRQ_INDEX, VFIO_PCI_MSIX_IRQ_INDEX,
};
use super::pci::VfioDeviceIo;
use super::sys::{SetIrqsError, VfioSysError};
use crate::logger::{debug, error, warn};
use crate::pci::PciSBDF;
use crate::pci::msix::MsixTableEntry;
use crate::vstate::interrupts::MsixVectorGroup;
use crate::vstate::vm::KvmVm;

/// Whether a message is waiting in `event`, checked without consuming it.
fn eventfd_pending(event: &EventFd) -> bool {
    let mut pollfd = libc::pollfd {
        fd: event.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let timeout = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `pollfd` describes an open eventfd, `timeout` is a valid zero timeout and no signal
    // mask is passed.
    let ret = unsafe { libc::ppoll(&mut pollfd, 1, &timeout, std::ptr::null()) };
    ret > 0 && pollfd.revents & libc::POLLIN != 0
}

/// The desired state of one interrupt vector: its message, masked or not, from device `sbdf`.
#[derive(Debug, Clone)]
struct VectorUpdate {
    index: usize,
    entry: MsixTableEntry,
    sbdf: PciSBDF,
}

impl VectorUpdate {
    fn new(index: usize, address: (u32, u32), data: u32, masked: bool, sbdf: PciSBDF) -> Self {
        let (address_lo, address_hi) = address;
        VectorUpdate {
            index,
            entry: MsixTableEntry {
                msg_addr_lo: address_lo,
                msg_addr_hi: address_hi,
                msg_data: data,
                // Bit 0 of Vector Control is the mask bit (PCI Local Bus specification 6.8.2.9).
                vector_ctl: u32::from(masked),
            },
            sbdf,
        }
    }

    fn masked(&self) -> bool {
        self.entry.masked()
    }
}

/// Program the KVM routes and irqfds of `updates`, with a single routing table update.
///
/// A masked vector has its irqfd deassigned before its route is removed, so a message sent while
/// masked stays in the eventfd instead of being injected through a missing route. An unmasked
/// vector has its route installed before its irqfd is assigned, as required by kernels without
/// commit a80ced6ea514 ("KVM: SVM: fix panic on out-of-bounds guest IRQ").
fn apply_vector_updates(vectors: &MsixVectorGroup, updates: &[VectorUpdate]) {
    let vmfd = &vectors.vm.common.fd;
    for update in updates.iter().filter(|update| update.masked()) {
        if let Err(err) = vectors.vectors[update.index].disable(vmfd) {
            error!(
                "vfio: failed to deassign irqfd of vector {}: {err}",
                update.index
            );
        }
    }
    for update in updates {
        if let Err(err) =
            vectors
                .vm
                .register_msi(&vectors.vectors[update.index], &update.entry, update.sbdf)
        {
            error!(
                "vfio: failed to register route of vector {}: {err}",
                update.index
            );
        }
    }
    if let Err(err) = vectors.vm.set_gsi_routes() {
        error!("vfio: failed to program interrupt routes: {err}");
        return;
    }
    for update in updates.iter().filter(|update| !update.masked()) {
        if let Err(err) = vectors.vectors[update.index].enable(vmfd) {
            error!(
                "vfio: failed to assign irqfd of vector {}: {err}",
                update.index
            );
        }
    }
}

/// Deassign the irqfds of `vectors[range]`.
fn deassign_irqfds(vectors: &MsixVectorGroup, range: std::ops::Range<usize>) {
    let vmfd = &vectors.vm.common.fd;
    for (index, vector) in vectors.vectors[range.clone()].iter().enumerate() {
        if let Err(err) = vector.disable(vmfd) {
            error!(
                "vfio: failed to deassign irqfd of vector {}: {err}",
                range.start + index
            );
        }
    }
}

fn eventfds(vectors: &MsixVectorGroup, range: std::ops::Range<usize>) -> Vec<RawFd> {
    vectors.vectors[range]
        .iter()
        .map(|vector| vector.event_fd.as_raw_fd())
        .collect()
}

/// Route the host interrupts `start..end` of VFIO index `index` to the vector eventfds. When the
/// host cannot allocate all of them, retry with the number it reported, as QEMU does. Returns the
/// new number of host vectors (0 if the index is disabled).
fn enable_host_vectors(
    device: &dyn VfioDeviceIo,
    index: u32,
    vectors: &MsixVectorGroup,
    start: usize,
    end: usize,
    name: &str,
) -> usize {
    let start_u32 = u32::try_from(start).expect("vector index fits in u32");
    match device.set_irq_eventfds(index, start_u32, &eventfds(vectors, start..end)) {
        Ok(()) => end,
        // A partial allocation can only happen when enabling the index (start == 0), in which
        // case the kernel leaves the index disabled and reports how many vectors it can provide.
        Err(SetIrqsError::Partial(available)) if start == 0 && available > 0 => {
            let available = (available as usize).min(end);
            warn!(
                "vfio: the host could only allocate {available} of the {end} {name} vectors the \
                 guest enabled; vectors {available} to {} will not be delivered",
                end - 1
            );
            match device.set_irq_eventfds(index, 0, &eventfds(vectors, 0..available)) {
                Ok(()) => available,
                Err(err) => {
                    error!("vfio: failed to enable {available} {name} vectors: {err}");
                    0
                }
            }
        }
        Err(err) => {
            error!(
                "vfio: failed to enable {name} vectors {start} to {}: {err}",
                end - 1
            );
            if start == 0 { 0 } else { start }
        }
    }
}

/// Emulation of the MSI capability of an assigned device.
#[derive(Debug)]
pub struct Msi {
    /// Offset of the capability in configuration space.
    cap: u16,
    /// Length of the capability in bytes (10, 14, 20 or 24).
    len: u16,
    /// The capability registers as seen by the guest. Bytes 0 and 1 (capability id and next
    /// pointer) are not used: they are read from the device.
    regs: [u8; Self::MAX_LEN],
    /// One vector per message the device can send.
    vectors: Arc<MsixVectorGroup>,
    /// Guest SBDF of the device, used as MSI device id where KVM needs one.
    sbdf: PciSBDF,
    /// Number of messages the guest enabled, when the host was last programmed.
    requested: usize,
    /// Number of host vectors routed to the eventfds (0 when MSI is disabled on the host).
    host_vectors: usize,
}

impl Msi {
    const MAX_LEN: usize = 24;
    /// Maximum number of messages of an MSI capability.
    pub const MAX_VECTORS: u32 = 32;

    /// Create the emulation of the MSI capability at `cap`, whose Message Control register reads
    /// `flags`, for a device that can send one message per vector of `vectors`: a power of two
    /// up to [`Msi::MAX_VECTORS`].
    pub fn new(cap: u16, flags: u16, vectors: Arc<MsixVectorGroup>, sbdf: PciSBDF) -> Self {
        let count = u32::try_from(vectors.vectors.len()).unwrap();
        assert!(count.is_power_of_two() && count <= Self::MAX_VECTORS);
        // Only the 64-bit address and per-vector masking capabilities are taken from the device,
        // and the Multiple Message Capable field encodes the number of vectors. The device powers
        // up with MSI disabled and a single message enabled, which is what the guest must see as
        // well.
        let flags = (u32::from(flags) & (PCI_MSI_FLAGS_64BIT | PCI_MSI_FLAGS_MASKBIT))
            | (count.trailing_zeros() << 1);
        // Capability length, as defined by the PCI Local Bus specification (6.8.1) and computed
        // by vfio-pci in `vfio_msi_cap_len`.
        let mut len = 10;
        if flags & PCI_MSI_FLAGS_64BIT != 0 {
            len += 4;
        }
        if flags & PCI_MSI_FLAGS_MASKBIT != 0 {
            len += 10;
        }
        let mut regs = [0u8; Self::MAX_LEN];
        regs[PCI_MSI_FLAGS as usize..PCI_MSI_FLAGS as usize + 2]
            .copy_from_slice(&u16::try_from(flags).unwrap().to_le_bytes());
        Msi {
            cap,
            len,
            regs,
            vectors,
            sbdf,
            requested: 0,
            host_vectors: 0,
        }
    }

    /// Offset of the capability in configuration space.
    pub fn cap(&self) -> u16 {
        self.cap
    }

    /// The eventfd of vector `index`.
    #[cfg(test)]
    pub fn vector_event(&self, index: usize) -> &EventFd {
        &self.vectors.vectors[index].event_fd
    }

    /// Number of host vectors routed to the eventfds.
    #[cfg(test)]
    pub fn host_vectors(&self) -> usize {
        self.host_vectors
    }

    /// Length of the capability in bytes.
    pub fn len(&self) -> u16 {
        self.len
    }

    fn flags(&self) -> u32 {
        u32::from(u16::from_le_bytes([
            self.regs[PCI_MSI_FLAGS as usize],
            self.regs[PCI_MSI_FLAGS as usize + 1],
        ]))
    }

    fn is_64bit(&self) -> bool {
        self.flags() & PCI_MSI_FLAGS_64BIT != 0
    }

    fn data_offset(&self) -> usize {
        if self.is_64bit() {
            PCI_MSI_DATA_64 as usize
        } else {
            PCI_MSI_DATA_32 as usize
        }
    }

    /// Offsets of the Mask Bits and Pending Bits registers, if the device supports per-vector
    /// masking.
    fn mask_and_pending_offsets(&self) -> Option<(usize, usize)> {
        if self.flags() & PCI_MSI_FLAGS_MASKBIT == 0 {
            return None;
        }
        Some(if self.is_64bit() {
            (PCI_MSI_MASK_64 as usize, PCI_MSI_PENDING_64 as usize)
        } else {
            (PCI_MSI_MASK_32 as usize, PCI_MSI_PENDING_32 as usize)
        })
    }

    fn read_u32(&self, offset: usize) -> u32 {
        u32::from_le_bytes(self.regs[offset..offset + 4].try_into().unwrap())
    }

    fn mask_bits(&self) -> u32 {
        self.mask_and_pending_offsets()
            .map_or(0, |(mask, _)| self.read_u32(mask))
    }

    /// Bits of the implemented vectors, in the Mask Bits and Pending Bits registers.
    fn implemented_vectors_mask(&self) -> u32 {
        let count = self.vectors.vectors.len();
        if count >= 32 {
            u32::MAX
        } else {
            (1u32 << count) - 1
        }
    }

    /// Mask of the bits the guest may write in byte `offset` of the capability.
    fn writable_mask(&self, offset: usize) -> u8 {
        let data = self.data_offset();
        match offset {
            // Message Control: MSI Enable and Multiple Message Enable.
            o if o == PCI_MSI_FLAGS as usize => {
                u8::try_from(PCI_MSI_FLAGS_ENABLE | PCI_MSI_FLAGS_QSIZE).unwrap()
            }
            // Message Address: dword aligned.
            o if o == PCI_MSI_ADDRESS_LO as usize => 0xfc,
            o if o > PCI_MSI_ADDRESS_LO as usize && o < PCI_MSI_ADDRESS_LO as usize + 4 => 0xff,
            o if self.is_64bit()
                && o >= PCI_MSI_ADDRESS_HI as usize
                && o < PCI_MSI_ADDRESS_HI as usize + 4 =>
            {
                0xff
            }
            // Message Data (the Extended Message Data field is not supported).
            o if o == data || o == data + 1 => 0xff,
            o => match self.mask_and_pending_offsets() {
                Some((mask, _)) if o >= mask && o < mask + 4 => {
                    self.implemented_vectors_mask().to_le_bytes()[o - mask]
                }
                _ => 0,
            },
        }
    }

    /// Read byte `offset` (at least 2) of the capability.
    pub fn read_byte(&self, offset: usize) -> u8 {
        if let Some((_, pending)) = self.mask_and_pending_offsets()
            && offset >= pending
            && offset < pending + 4
        {
            return self.pending_bits().to_le_bytes()[offset - pending];
        }
        self.regs[offset]
    }

    /// The Pending Bits register: a masked vector whose message the device already sent.
    fn pending_bits(&self) -> u32 {
        let mask = self.mask_bits();
        (0..self.host_vectors)
            .filter(|&index| mask & (1 << index) != 0)
            .filter(|&index| eventfd_pending(&self.vectors.vectors[index].event_fd))
            .fold(0, |bits, index| bits | (1 << index))
    }

    /// Whether the guest configuration enables MSI.
    pub fn guest_enabled(&self) -> bool {
        self.flags() & PCI_MSI_FLAGS_ENABLE != 0
    }

    /// Whether MSI is enabled on the host.
    pub fn host_enabled(&self) -> bool {
        self.host_vectors > 0
    }

    /// Write `data` at byte `offset` (at least 2) of the capability, honouring read-only bits.
    /// The host is not reprogrammed: call [`Msi::sync`] afterwards.
    pub fn write_bytes(&mut self, offset: usize, data: &[u8]) {
        for (i, byte) in data.iter().enumerate() {
            let offset = offset + i;
            let mask = self.writable_mask(offset);
            self.regs[offset] = (self.regs[offset] & !mask) | (byte & mask);
        }
    }

    /// Bring the host and KVM in line with the guest configuration.
    pub fn sync(&mut self, device: &dyn VfioDeviceIo) {
        if !self.guest_enabled() {
            self.disable_host(device);
            return;
        }

        let flags = self.flags();
        let enabled_log2 =
            ((flags & PCI_MSI_FLAGS_QSIZE) >> 4).min((flags & PCI_MSI_FLAGS_QMASK) >> 1);
        let count = 1usize << enabled_log2;
        let address_hi = if self.is_64bit() {
            self.read_u32(PCI_MSI_ADDRESS_HI as usize)
        } else {
            0
        };
        let address_lo = self.read_u32(PCI_MSI_ADDRESS_LO as usize);
        let data_offset = self.data_offset();
        let data = u32::from(u16::from_le_bytes([
            self.regs[data_offset],
            self.regs[data_offset + 1],
        ]));
        let mask = self.mask_bits();

        // With multiple messages enabled the device sends message `i` with the low log2(count)
        // bits of the data replaced by `i` (PCI Local Bus specification 6.8.3.2).
        let updates: Vec<VectorUpdate> = (0..count)
            .map(|index| {
                VectorUpdate::new(
                    index,
                    (address_lo, address_hi),
                    (data & !(u32::try_from(count).unwrap() - 1)) | u32::try_from(index).unwrap(),
                    mask & (1 << index) != 0,
                    self.sbdf,
                )
            })
            .collect();
        deassign_irqfds(&self.vectors, count..self.vectors.vectors.len());
        apply_vector_updates(&self.vectors, &updates);

        if self.requested != count {
            // The number of MSI vectors cannot change while MSI is enabled on the host.
            if self.host_enabled()
                && let Err(err) = device.disable_irqs(VFIO_PCI_MSI_IRQ_INDEX)
            {
                error!("vfio: failed to disable MSI on the host: {err}");
            }
            self.host_vectors = enable_host_vectors(
                device,
                VFIO_PCI_MSI_IRQ_INDEX,
                &self.vectors,
                0,
                count,
                "MSI",
            );
            self.requested = count;
            debug!(
                "vfio: {:?} MSI enabled with {} of {count} vectors",
                self.sbdf, self.host_vectors
            );
        }
    }

    /// Disable MSI on the host and in KVM, leaving the guest registers untouched.
    pub fn disable_host(&mut self, device: &dyn VfioDeviceIo) {
        deassign_irqfds(&self.vectors, 0..self.vectors.vectors.len());
        if self.host_enabled()
            && let Err(err) = device.disable_irqs(VFIO_PCI_MSI_IRQ_INDEX)
        {
            error!("vfio: failed to disable MSI on the host: {err}");
        }
        self.host_vectors = 0;
        self.requested = 0;
    }
}

/// A virtual MSI-X table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MsixEntry {
    address_lo: u32,
    address_hi: u32,
    data: u32,
    masked: bool,
}

impl Default for MsixEntry {
    // Every vector is masked after reset (PCI Local Bus specification 6.8.2.9).
    fn default() -> Self {
        MsixEntry {
            address_lo: 0,
            address_hi: 0,
            data: 0,
            masked: true,
        }
    }
}

/// Emulation of the MSI-X capability, table and pending bit array of an assigned device.
#[derive(Debug)]
pub struct Msix {
    /// Offset of the capability in configuration space.
    cap: u16,
    /// BAR holding the table, and offset of the table in that BAR.
    table: (u32, u64),
    /// BAR holding the PBA, and offset of the PBA in that BAR.
    pba: (u32, u64),
    entries: Vec<MsixEntry>,
    enabled: bool,
    function_masked: bool,
    /// One vector per table entry.
    vectors: Arc<MsixVectorGroup>,
    /// Guest SBDF of the device, used as MSI device id where KVM needs one.
    sbdf: PciSBDF,
    /// Number of host vectors routed to the eventfds (0 when MSI-X is disabled on the host).
    host_vectors: usize,
    /// Whether host vectors can be added while MSI-X is enabled (`VFIO_IRQ_INFO_NORESIZE`
    /// clear, Linux v6.5+ with a device supporting dynamic MSI-X allocation).
    dynamic: bool,
}

impl Msix {
    /// Number of table entries of an MSI-X capability whose Message Control register is `flags`.
    pub fn table_size(flags: u16) -> u16 {
        (u16::try_from(PCI_MSIX_FLAGS_QSIZE).unwrap() & flags) + 1
    }

    /// Create the emulation of the MSI-X capability at `cap`, with the physical Table and PBA
    /// registers `table` and `pba`. `vectors` holds one vector per table entry.
    pub fn new(
        cap: u16,
        table: u32,
        pba: u32,
        vectors: Arc<MsixVectorGroup>,
        sbdf: PciSBDF,
        dynamic: bool,
    ) -> Self {
        // The BAR Indicator Register is in bits 2:0, the offset in bits 31:3.
        let locate = |reg: u32| (reg & 0x7, u64::from(reg & !0x7));
        Msix {
            cap,
            table: locate(table),
            pba: locate(pba),
            entries: vec![MsixEntry::default(); vectors.vectors.len()],
            enabled: false,
            function_masked: false,
            vectors,
            sbdf,
            host_vectors: 0,
            dynamic,
        }
    }

    /// Offset of the capability in configuration space.
    pub fn cap(&self) -> u16 {
        self.cap
    }

    /// The eventfd of vector `index`.
    #[cfg(test)]
    pub fn vector_event(&self, index: usize) -> &EventFd {
        &self.vectors.vectors[index].event_fd
    }

    /// Number of host vectors routed to the eventfds.
    #[cfg(test)]
    pub fn host_vectors(&self) -> usize {
        self.host_vectors
    }

    /// `(bar, offset, size)` of the MSI-X table.
    pub fn table_location(&self) -> (u32, u64, u64) {
        (
            self.table.0,
            self.table.1,
            self.entries.len() as u64 * u64::from(PCI_MSIX_ENTRY_SIZE),
        )
    }

    /// `(bar, offset, size)` of the pending bit array: one bit per vector, in QWORDs.
    pub fn pba_location(&self) -> (u32, u64, u64) {
        (
            self.pba.0,
            self.pba.1,
            self.entries.len().div_ceil(64) as u64 * 8,
        )
    }

    /// The Message Control register as seen by the guest.
    pub fn control(&self) -> u16 {
        let mut control = u16::try_from(self.entries.len() - 1).unwrap();
        if self.enabled {
            control |= u16::try_from(PCI_MSIX_FLAGS_ENABLE).unwrap();
        }
        if self.function_masked {
            control |= u16::try_from(PCI_MSIX_FLAGS_MASKALL).unwrap();
        }
        control
    }

    /// Whether the guest configuration enables MSI-X.
    pub fn guest_enabled(&self) -> bool {
        self.enabled
    }

    /// Whether MSI-X is enabled on the host.
    pub fn host_enabled(&self) -> bool {
        self.host_vectors > 0
    }

    fn effectively_masked(&self, index: usize) -> bool {
        self.function_masked || self.entries[index].masked
    }

    fn update_for(&self, index: usize) -> VectorUpdate {
        let entry = &self.entries[index];
        VectorUpdate::new(
            index,
            (entry.address_lo, entry.address_hi),
            entry.data,
            self.effectively_masked(index),
            self.sbdf,
        )
    }

    /// Number of host vectors the guest configuration needs: every vector up to the highest
    /// unmasked one, and at least one so that the device is in MSI-X mode whenever the guest
    /// enabled it (as QEMU does).
    fn needed_host_vectors(&self) -> usize {
        self.entries
            .iter()
            .rposition(|entry| !entry.masked)
            .map_or(1, |index| index + 1)
    }

    /// Make sure at least `needed` host vectors are routed to the eventfds.
    fn ensure_host_vectors(&mut self, device: &dyn VfioDeviceIo, needed: usize) {
        if self.host_vectors >= needed {
            return;
        }
        if self.host_vectors == 0 {
            self.host_vectors = enable_host_vectors(
                device,
                VFIO_PCI_MSIX_IRQ_INDEX,
                &self.vectors,
                0,
                needed,
                "MSI-X",
            );
        } else if self.dynamic {
            self.host_vectors = enable_host_vectors(
                device,
                VFIO_PCI_MSIX_IRQ_INDEX,
                &self.vectors,
                self.host_vectors,
                needed,
                "MSI-X",
            );
        } else {
            // The kernel cannot add vectors to an enabled MSI-X index: disable and enable it again
            // with the larger count, as QEMU does.
            if let Err(err) = device.disable_irqs(VFIO_PCI_MSIX_IRQ_INDEX) {
                error!("vfio: failed to disable MSI-X on the host: {err}");
            }
            self.host_vectors = enable_host_vectors(
                device,
                VFIO_PCI_MSIX_IRQ_INDEX,
                &self.vectors,
                0,
                needed,
                "MSI-X",
            );
        }
        debug!(
            "vfio: {:?} MSI-X enabled with {} host vectors",
            self.sbdf, self.host_vectors
        );
    }

    /// Write the high byte of the Message Control register (MSI-X Enable and Function Mask);
    /// the low byte only holds the read-only table size.
    pub fn write_control_high(&mut self, device: &dyn VfioDeviceIo, value: u8) {
        let value = u32::from(value) << 8;
        let enabled = value & PCI_MSIX_FLAGS_ENABLE != 0;
        let function_masked = value & PCI_MSIX_FLAGS_MASKALL != 0;
        if enabled == self.enabled && function_masked == self.function_masked {
            return;
        }
        self.enabled = enabled;
        self.function_masked = function_masked;
        self.sync(device);
    }

    /// Bring the host and KVM in line with the whole guest configuration.
    pub fn sync(&mut self, device: &dyn VfioDeviceIo) {
        if !self.enabled {
            self.disable_host(device);
            return;
        }
        let updates: Vec<VectorUpdate> = (0..self.entries.len())
            .map(|index| self.update_for(index))
            .collect();
        apply_vector_updates(&self.vectors, &updates);
        self.ensure_host_vectors(device, self.needed_host_vectors());
    }

    /// Disable MSI-X on the host and in KVM, leaving the guest registers untouched.
    pub fn disable_host(&mut self, device: &dyn VfioDeviceIo) {
        deassign_irqfds(&self.vectors, 0..self.vectors.vectors.len());
        if self.host_enabled()
            && let Err(err) = device.disable_irqs(VFIO_PCI_MSIX_IRQ_INDEX)
        {
            error!("vfio: failed to disable MSI-X on the host: {err}");
        }
        self.host_vectors = 0;
    }

    /// Whether an access of `len` bytes at `offset` of the table or PBA is valid: software must
    /// use naturally aligned DWORD or QWORD accesses (PCI Local Bus specification 6.8.2).
    fn valid_access(offset: u64, len: usize) -> bool {
        matches!(len, 4 | 8) && offset.is_multiple_of(len as u64)
    }

    /// Read `data.len()` bytes at `offset` of the table.
    pub fn read_table(&self, offset: u64, data: &mut [u8]) {
        let index = usize::try_from(offset / u64::from(PCI_MSIX_ENTRY_SIZE)).unwrap_or(usize::MAX);
        if !Self::valid_access(offset, data.len()) || index >= self.entries.len() {
            data.fill(0xff);
            return;
        }
        let entry = &self.entries[index];
        let dwords = [
            entry.address_lo,
            entry.address_hi,
            entry.data,
            u32::from(entry.masked) * PCI_MSIX_ENTRY_CTRL_MASKBIT,
        ];
        let first = usize::try_from(offset % u64::from(PCI_MSIX_ENTRY_SIZE)).unwrap() / 4;
        for (i, chunk) in data.chunks_mut(4).enumerate() {
            chunk.copy_from_slice(&dwords[first + i].to_le_bytes());
        }
    }

    /// Write `data` at `offset` of the table.
    pub fn write_table(&mut self, device: &dyn VfioDeviceIo, offset: u64, data: &[u8]) {
        let index = usize::try_from(offset / u64::from(PCI_MSIX_ENTRY_SIZE)).unwrap_or(usize::MAX);
        if !Self::valid_access(offset, data.len()) || index >= self.entries.len() {
            warn!(
                "vfio: invalid MSI-X table write of {} bytes at {offset:#x}",
                data.len()
            );
            return;
        }
        let old = self.entries[index];
        let first = u32::try_from(offset % u64::from(PCI_MSIX_ENTRY_SIZE)).unwrap();
        for (i, chunk) in data.chunks(4).enumerate() {
            let value = u32::from_le_bytes(chunk.try_into().unwrap());
            let entry = &mut self.entries[index];
            match first + 4 * u32::try_from(i).unwrap() {
                PCI_MSIX_ENTRY_LOWER_ADDR => entry.address_lo = value,
                PCI_MSIX_ENTRY_UPPER_ADDR => entry.address_hi = value,
                PCI_MSIX_ENTRY_DATA => entry.data = value,
                // Only the Mask Bit is implemented in Vector Control.
                PCI_MSIX_ENTRY_VECTOR_CTRL => {
                    entry.masked = value & PCI_MSIX_ENTRY_CTRL_MASKBIT != 0
                }
                _ => unreachable!("an entry is four dwords"),
            }
        }
        if self.entries[index] == old || !self.enabled {
            return;
        }
        apply_vector_updates(&self.vectors, &[self.update_for(index)]);
        if !self.entries[index].masked {
            self.ensure_host_vectors(device, index + 1);
        }
    }

    /// Read `data.len()` bytes at `offset` of the pending bit array.
    ///
    /// A vector is pending when the device sent its message while it was masked: either the host
    /// holds it in the physical PBA (vectors without a host vector yet are masked in the physical
    /// table), or it waits in the eventfd of a vector the guest masked.
    pub fn read_pba(&self, device: &dyn VfioDeviceIo, offset: u64, data: &mut [u8]) {
        let (_, _, size) = self.pba_location();
        if !Self::valid_access(offset, data.len()) || offset + data.len() as u64 > size {
            data.fill(0xff);
            return;
        }
        let mut physical = [0u8; 8];
        if let Err(err) =
            device.read_region(self.pba.0, self.pba.1 + offset, &mut physical[..data.len()])
        {
            warn!("vfio: failed to read the physical MSI-X PBA: {err}");
            physical = [0; 8];
        }
        let mut bits = u64::from_le_bytes(physical);
        let first_vector = usize::try_from(offset * 8).unwrap();
        for bit in 0..data.len() * 8 {
            let index = first_vector + bit;
            if index < self.host_vectors
                && self.effectively_masked(index)
                && eventfd_pending(&self.vectors.vectors[index].event_fd)
            {
                bits |= 1 << bit;
            }
        }
        // Bits of vectors past the end of the table are reserved.
        let valid = self.entries.len().saturating_sub(first_vector).min(64);
        if valid < 64 {
            bits &= (1u64 << valid) - 1;
        }
        data.copy_from_slice(&bits.to_le_bytes()[..data.len()]);
    }
}

/// Errors of the INTx routing of an assigned device.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum IntxError {
    /// Failed to create an INTx eventfd: {0}
    EventFd(#[source] std::io::Error),
    /// Failed to register the INTx irqfd with KVM: {0}
    Irqfd(#[source] kvm_ioctls::Error),
    /// Failed to route the INTx of the device to an eventfd: {0}
    Trigger(#[source] SetIrqsError),
    /// Failed to set the INTx unmask eventfd: {0}
    Unmask(#[source] VfioSysError),
}

/// Routing of the INTx interrupt of an assigned device to a legacy GSI of the guest.
///
/// INTx is level-triggered. vfio-pci signals the trigger eventfd when the device asserts it, and
/// masks it on the host until it is unmasked. The trigger eventfd is a KVM irqfd with a resample
/// eventfd: KVM asserts the GSI when the trigger eventfd is signalled and, when the guest
/// acknowledges the interrupt, deasserts the GSI and signals the resample eventfd, which vfio-pci
/// takes as the unmask of the host interrupt. If the device still asserts INTx, the host interrupt
/// fires again and the cycle repeats, as with a level-triggered line.
///
/// The routing is enabled on the host only while the guest has neither MSI nor MSI-X enabled:
/// vfio-pci refuses to enable MSI or MSI-X while INTx is enabled, and a function that sends
/// messages does not signal INTx.
#[derive(Debug)]
pub struct Intx {
    gsi: u32,
    trigger: EventFd,
    resample: EventFd,
    vm: Arc<KvmVm>,
    host_enabled: bool,
}

impl Intx {
    /// Create the routing of an INTx to guest GSI `gsi`, disabled.
    pub fn new(vm: Arc<KvmVm>, gsi: u32) -> Result<Self, IntxError> {
        Ok(Intx {
            gsi,
            trigger: EventFd::new(libc::EFD_NONBLOCK).map_err(IntxError::EventFd)?,
            resample: EventFd::new(libc::EFD_NONBLOCK).map_err(IntxError::EventFd)?,
            vm,
            host_enabled: false,
        })
    }

    /// The guest GSI of the interrupt.
    pub fn gsi(&self) -> u32 {
        self.gsi
    }

    /// Whether the INTx of the device is routed to the guest.
    #[cfg(test)]
    pub fn host_enabled(&self) -> bool {
        self.host_enabled
    }

    /// The trigger eventfd.
    #[cfg(test)]
    pub fn trigger(&self) -> &EventFd {
        &self.trigger
    }

    /// Route the INTx of `device` to the guest GSI.
    pub fn enable_host(&mut self, device: &dyn VfioDeviceIo) -> Result<(), IntxError> {
        if self.host_enabled {
            return Ok(());
        }
        // An interrupt signalled before the irqfd is registered would stay in the trigger eventfd
        // and be injected on registration; registering it first keeps the order simple. The GSI
        // route to the interrupt controller pin is kept for good: KVM only acknowledges (and so
        // resamples) interrupts of pins that have a route.
        self.vm
            .register_irq_with_resample(&self.trigger, &self.resample, self.gsi)
            .map_err(IntxError::Irqfd)?;
        let result = device
            .set_irq_eventfds(VFIO_PCI_INTX_IRQ_INDEX, 0, &[self.trigger.as_raw_fd()])
            .map_err(IntxError::Trigger)
            .and_then(|()| {
                device
                    .set_irq_unmask_eventfd(VFIO_PCI_INTX_IRQ_INDEX, self.resample.as_raw_fd())
                    .map_err(|err| {
                        if let Err(err) = device.disable_irqs(VFIO_PCI_INTX_IRQ_INDEX) {
                            warn!("vfio: failed to disable INTx: {err}");
                        }
                        IntxError::Unmask(err)
                    })
            });
        if let Err(err) = result {
            if let Err(err) = self.vm.fd().unregister_irqfd(&self.trigger, self.gsi) {
                warn!("vfio: failed to unregister the INTx irqfd: {err}");
            }
            return Err(err);
        }
        self.host_enabled = true;
        Ok(())
    }

    /// Stop routing the INTx when the device goes away: deassign the irqfd, deasserting the guest
    /// GSI. The host INTx needs no VFIO call: closing the device file disables it
    /// (`vfio_pci_core_close_device` calls `vfio_pci_core_disable`, which disables the interrupts
    /// of the current type), as for MSI and MSI-X.
    pub fn release(&mut self) {
        if !self.host_enabled {
            return;
        }
        if let Err(err) = self.vm.fd().unregister_irqfd(&self.trigger, self.gsi) {
            warn!("vfio: failed to unregister the INTx irqfd: {err}");
        }
        self.host_enabled = false;
    }

    /// Stop routing the INTx of `device`, deasserting the guest GSI.
    pub fn disable_host(&mut self, device: &dyn VfioDeviceIo) {
        if !self.host_enabled {
            return;
        }
        if let Err(err) = device.disable_irqs(VFIO_PCI_INTX_IRQ_INDEX) {
            warn!("vfio: failed to disable INTx: {err}");
        }
        // Deassigning an irqfd with a resampler deasserts its GSI (`irqfd_resampler_shutdown`).
        // No event of the stopped routing is left to inject when it is enabled again: KVM
        // consumes every event of the trigger eventfd while the irqfd is assigned
        // (`irqfd_wakeup`), and vfio-pci no longer signals it once INTx is disabled above. An
        // event left in the resample eventfd only unmasks the host INTx when the routing is
        // enabled again, which does nothing unless it is masked, and then is a resample.
        if let Err(err) = self.vm.fd().unregister_irqfd(&self.trigger, self.gsi) {
            warn!("vfio: failed to unregister the INTx irqfd: {err}");
        }
        self.host_enabled = false;
    }
}
