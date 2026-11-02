// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Consumer side of KVM's coalesced I/O ring.
//!
//! For an address range registered with `KVM_REGISTER_COALESCED_MMIO`, KVM does not exit to
//! userspace when the guest writes to it. It appends the write to a ring buffer it shares with the
//! VMM and resumes the vCPU. The VMM has to replay the buffered writes before it handles any access
//! that did exit, so that devices observe the guest's accesses in the order it issued them.
//!
//! KVM keeps a single ring per VM, fills it on behalf of every vCPU, and exposes it through the
//! mmap of any vCPU file descriptor. KVM advances the producer index (`last`) and the VMM the
//! consumer index (`first`).
//!
//! The vCPUs replay the ring whenever they exit. A guest can also write to a coalesced range and
//! then not exit for a long time: an idle guest hardly exits to the VMM, and neither does one doing
//! virtio I/O over PCI. The VMM thread therefore drains the ring too, on a timer that runs while
//! the vCPUs exit, see [`CoalescedIoDrainTimer`].

use std::mem::{offset_of, size_of};
use std::os::fd::{AsRawFd, RawFd};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use event_manager::{EventOps, Events, MutEventSubscriber};
use kvm_bindings::{KVM_COALESCED_MMIO_PAGE_OFFSET, kvm_coalesced_mmio, kvm_coalesced_mmio_ring};
use kvm_ioctls::VcpuFd;
use utils::time::TimerFd;
use vmm_sys_util::epoll::EventSet;

use crate::arch::host_page_size;
use crate::logger::{error, warn};
use crate::vstate::bus::Bus;

/// The indices at the start of KVM's `kvm_coalesced_mmio_ring`, as atomics: KVM advances `last`
/// and reads `first` while vCPU threads do the opposite, so neither may be accessed as a plain
/// integer. `AtomicU32` has the size and alignment of `u32`, so this lies over KVM's layout exactly.
#[repr(C)]
#[derive(Debug)]
struct RingIndices {
    /// The oldest entry not yet handled; the VMM advances it.
    first: AtomicU32,
    /// The entry KVM fills next; KVM advances it.
    last: AtomicU32,
}

const _: () = assert!(offset_of!(RingIndices, first) == offset_of!(kvm_coalesced_mmio_ring, first));
const _: () = assert!(offset_of!(RingIndices, last) == offset_of!(kvm_coalesced_mmio_ring, last));
const _: () =
    assert!(size_of::<RingIndices>() == offset_of!(kvm_coalesced_mmio_ring, coalesced_mmio));

/// How often the VMM thread drains the ring while vCPUs exit. A write that no exit follows waits
/// in the ring for up to this long, provided that some vCPU exited less than a period before it.
pub const IDLE_DRAIN_PERIOD: Duration = Duration::from_millis(50);

/// The VMM's handle on a VM's coalesced I/O ring.
#[derive(Debug)]
pub struct CoalescedIoRing {
    /// The page the ring is mapped at, which starts with its indices.
    indices: NonNull<RingIndices>,
    /// Length of that mapping, in bytes.
    mapping_len: usize,
    /// Number of entries in the ring.
    capacity: u32,
    /// Held while consuming. The ring has a single consumer index, shared by every vCPU and the
    /// VMM thread.
    consumer: Mutex<()>,
    /// Decides when the VMM thread drains the ring.
    idle_drain: IdleDrain,
}

// JUSTIFICATION: `NonNull` is neither `Send` nor `Sync`, and the ring has to be shared by every
// vCPU thread and the VMM thread.
// SAFETY: The ring lives in memory shared with KVM rather than in the state of any one thread.
// Its indices are only ever accessed atomically and its entries are only read by the consumer that
// holds `consumer`, so the handle can be moved to and shared between threads.
unsafe impl Send for CoalescedIoRing {}
// JUSTIFICATION: See the `Send` implementation above.
// SAFETY: See the `Send` implementation above.
unsafe impl Sync for CoalescedIoRing {}

impl CoalescedIoRing {
    /// Maps the coalesced I/O ring of the VM that `vcpu` belongs to.
    pub fn new(vcpu: &VcpuFd) -> std::io::Result<Self> {
        let page_size = host_page_size();
        let offset = libc::off_t::try_from(page_size)
            .ok()
            .and_then(|page| page.checked_mul(libc::off_t::from(KVM_COALESCED_MMIO_PAGE_OFFSET)))
            .ok_or(std::io::ErrorKind::InvalidInput)?;

        // JUSTIFICATION: There is no safe alternative. kvm-ioctls maps the ring too, but ties
        // the mapping to one `VcpuFd` and reads the indices as plain integers, which does not
        // suit a ring that KVM fills while any vCPU thread reads it.
        // SAFETY: This maps one page of the vCPU file, which KVM backs with the ring of the VM at
        // that offset. The result is checked before it is used.
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                vcpu.as_raw_fd(),
                offset,
            )
        };
        if addr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }

        // The same formula KVM uses for `KVM_COALESCED_MMIO_MAX`.
        let capacity =
            (page_size - size_of::<kvm_coalesced_mmio_ring>()) / size_of::<kvm_coalesced_mmio>();
        Ok(Self {
            indices: NonNull::new(addr.cast()).expect("mmap returned a NULL mapping"),
            mapping_len: page_size,
            capacity: u32::try_from(capacity).expect("Coalesced I/O ring has too many entries"),
            consumer: Mutex::new(()),
            idle_drain: IdleDrain::new(TimerFd::new()),
        })
    }

    fn indices(&self) -> &RingIndices {
        // JUSTIFICATION: There is no safe way to refer to memory behind a raw mapping.
        // SAFETY: The mapping starts with KVM's ring indices, which `RingIndices` lies over, and
        // it stays mapped for as long as `self` exists. Atomics may be shared with KVM's writes.
        unsafe { self.indices.as_ref() }
    }

    /// Copies out the entry at `index`, which must be below `capacity`.
    fn entry(&self, index: u32) -> kvm_coalesced_mmio {
        // JUSTIFICATION: There is no safe way to read memory behind a raw mapping.
        // SAFETY: The entries follow the indices in the mapping and `index` is inside the ring.
        // KVM leaves an entry alone from publishing it until `first` moves past it.
        unsafe {
            self.indices
                .as_ptr()
                .add(1)
                .cast::<kvm_coalesced_mmio>()
                .add(index as usize)
                .read()
        }
    }

    /// Hands the writes buffered so far to `deliver`, oldest first, as whether each went to port
    /// I/O rather than MMIO space, its address and its data.
    ///
    /// Callers consume the ring one at a time, and an entry is released back to KVM only once
    /// `deliver` returns. A concurrent caller that finds the ring non-empty therefore waits for
    /// the writes in it to be handled rather than overtaking them. Writes added while a call runs
    /// are left to the next one, so one call handles at most a ring's worth.
    fn drain(&self, mut deliver: impl FnMut(bool, u64, &[u8])) {
        let indices = self.indices();
        // Fast path for the common case of an empty ring, taken without the lock.
        if indices.first.load(Ordering::Acquire) == indices.last.load(Ordering::Acquire) {
            return;
        }

        let _consumer = self.consumer.lock().expect("Poisoned lock");
        // Only the holder of `consumer` writes `first`.
        let mut first = indices.first.load(Ordering::Relaxed);
        // Pairs with KVM filling in an entry before it advances `last`. KVM published the writes
        // of the vCPU that exited before its KVM_RUN returned, so they all lie before this point.
        let last = indices.last.load(Ordering::Acquire);
        if first >= self.capacity || last >= self.capacity {
            error!("Coalesced I/O ring indices out of bounds: first {first}, last {last}");
            return;
        }

        while first != last {
            let entry = self.entry(first);
            // JUSTIFICATION: Reading a field of a bindgen union is unsafe; there is no safe
            // alternative.
            // SAFETY: Both members of the union are a `u32`, so reading either is sound. Kernels
            // that predate coalesced PIO leave the field zeroed, which reads as MMIO.
            let pio = unsafe { entry.__bindgen_anon_1.pio != 0 };
            let len = usize::try_from(entry.len)
                .map_or(entry.data.len(), |len| len.min(entry.data.len()));
            deliver(pio, entry.phys_addr, &entry.data[..len]);

            first = (first + 1) % self.capacity;
            // Pairs with KVM reading `first` to find free entries, so that it only reuses an entry
            // once it has been handled.
            indices.first.store(first, Ordering::Release);
        }
    }

    /// Replays the writes buffered so far, oldest first, onto `pio_bus` or `mmio_bus`, whichever
    /// address space each went to. Consecutive writes to one address are delivered to their device
    /// as one run.
    pub fn replay(&self, pio_bus: Option<&Bus>, mmio_bus: Option<&Bus>) {
        let bus = |pio: bool| if pio { pio_bus } else { mmio_bus };
        let end_run = |(pio, addr): (bool, u64)| {
            if let Some(bus) = bus(pio) {
                let _ = bus.coalesced_writes_done(addr);
            }
        };

        let mut run = None;
        self.drain(|pio, addr, data| {
            if let Some(previous) = run
                && previous != (pio, addr)
            {
                end_run(previous);
            }
            run = Some((pio, addr));
            if bus(pio).is_none_or(|bus| bus.write_coalesced(addr, data).is_err()) {
                warn!("Coalesced write to {addr:#x} reached no device");
            }
        });
        if let Some(previous) = run {
            end_run(previous);
        }
    }

    /// Tells the ring that a vCPU exited and replayed it, which keeps the VMM thread draining it
    /// for at least another [`IDLE_DRAIN_PERIOD`] in case the guest stops exiting.
    pub fn vcpu_exited(&self) {
        self.idle_drain.vcpu_exited();
    }
}

impl Drop for CoalescedIoRing {
    fn drop(&mut self) {
        // JUSTIFICATION: There is no safe alternative.
        // SAFETY: `indices` and `mapping_len` describe a mapping that this object owns.
        unsafe { libc::munmap(self.indices.as_ptr().cast(), self.mapping_len) };
    }
}

/// Decides when the VMM thread drains the ring: a timer fires every [`IDLE_DRAIN_PERIOD`] while
/// vCPUs exit, and stops after a period in which none did.
///
/// A write the guest makes within a period of an exit therefore reaches its device within about a
/// period even if no exit follows it, as does the last byte a UART driver sends after polling the
/// line status. A guest that does not exit costs no wake-ups.
#[derive(Debug)]
struct IdleDrain {
    /// Whether a vCPU exited since the timer last fired.
    exited: AtomicBool,
    /// Whether the timer is armed, or about to be.
    ticking: AtomicBool,
    /// Fires every period while `ticking` is set.
    timer: Mutex<TimerFd>,
}

impl IdleDrain {
    fn new(timer: TimerFd) -> Self {
        Self {
            exited: AtomicBool::new(false),
            ticking: AtomicBool::new(false),
            timer: Mutex::new(timer),
        }
    }

    /// Called by a vCPU after every exit. Starts the timer unless it is ticking already.
    fn vcpu_exited(&self) {
        // Whoever set `exited` makes sure that the timer runs, and the timer sees the flag the next
        // time it fires. Checking first spares the vCPUs a write to shared memory on most exits.
        if self.exited.load(Ordering::SeqCst) {
            return;
        }
        self.exited.store(true, Ordering::SeqCst);
        if !self.ticking.swap(true, Ordering::SeqCst) {
            self.start();
        }
    }

    /// Called on the VMM thread when the timer fires. Runs `drain`, then stops the timer if no vCPU
    /// exited since it last fired.
    fn tick(&self, drain: impl FnOnce()) {
        self.timer.lock().expect("Poisoned lock").read();
        drain();
        if self.exited.swap(false, Ordering::SeqCst) {
            return;
        }

        // Arming with a zero duration disarms the timer.
        self.timer
            .lock()
            .expect("Poisoned lock")
            .arm(Duration::ZERO, None);
        self.ticking.store(false, Ordering::SeqCst);
        // A vCPU that exited after the swap above may have found `ticking` still set and left the
        // timer running. The accesses are sequentially consistent, so either that vCPU sees
        // `ticking` cleared and restarts the timer itself, or this sees its exit.
        if self.exited.load(Ordering::SeqCst) && !self.ticking.swap(true, Ordering::SeqCst) {
            self.start();
        }
    }

    fn start(&self) {
        self.timer
            .lock()
            .expect("Poisoned lock")
            .arm(IDLE_DRAIN_PERIOD, Some(IDLE_DRAIN_PERIOD));
    }

    fn timer_fd(&self) -> RawFd {
        self.timer.lock().expect("Poisoned lock").as_raw_fd()
    }
}

/// Drains a VM's coalesced I/O ring from the VMM thread, onto the buses the vCPUs replay it onto,
/// for when the vCPUs stop exiting. It does so every [`IDLE_DRAIN_PERIOD`] while vCPUs exit, and
/// once more a period after the last exit.
#[derive(Debug)]
pub struct CoalescedIoDrainTimer {
    ring: Arc<CoalescedIoRing>,
    pio_bus: Arc<Bus>,
    mmio_bus: Arc<Bus>,
}

impl CoalescedIoDrainTimer {
    /// Drains `ring` onto `pio_bus` and `mmio_bus`.
    pub fn new(ring: Arc<CoalescedIoRing>, pio_bus: Arc<Bus>, mmio_bus: Arc<Bus>) -> Self {
        Self {
            ring,
            pio_bus,
            mmio_bus,
        }
    }
}

impl MutEventSubscriber for CoalescedIoDrainTimer {
    fn process(&mut self, _events: Events, _ops: &mut EventOps) {
        self.ring
            .idle_drain
            .tick(|| self.ring.replay(Some(&self.pio_bus), Some(&self.mmio_bus)));
    }

    fn init(&mut self, ops: &mut EventOps) {
        let timer = Events::new_raw(self.ring.idle_drain.timer_fd(), EventSet::IN);
        if let Err(err) = ops.add(timer) {
            error!("Failed to register the coalesced I/O drain timer: {err}");
        }
    }
}

#[cfg(test)]
mod tests {
    use utils::time::MockClock;

    use super::*;

    fn is_armed(idle: &IdleDrain) -> bool {
        idle.timer.lock().unwrap().is_armed()
    }

    #[test]
    fn test_idle_drain_runs_while_vcpus_exit() {
        let clock = MockClock::new();
        let idle = IdleDrain::new(TimerFd::new_mocked(&clock));
        assert!(!is_armed(&idle));

        idle.vcpu_exited();
        assert!(is_armed(&idle));
        idle.vcpu_exited();

        // Some vCPU exited during the last period, so the timer keeps going.
        let mut drains = 0;
        clock.advance(IDLE_DRAIN_PERIOD);
        idle.tick(|| drains += 1);
        assert_eq!(drains, 1);
        assert!(is_armed(&idle));

        // A period without exits ends with one more drain, then the timer stops.
        clock.advance(IDLE_DRAIN_PERIOD);
        idle.tick(|| drains += 1);
        assert_eq!(drains, 2);
        assert!(!is_armed(&idle));

        idle.vcpu_exited();
        assert!(is_armed(&idle));
    }

    #[test]
    fn test_idle_drain_counts_exits_during_a_drain() {
        let clock = MockClock::new();
        let idle = IdleDrain::new(TimerFd::new_mocked(&clock));
        idle.vcpu_exited();
        clock.advance(IDLE_DRAIN_PERIOD);
        idle.tick(|| ());

        clock.advance(IDLE_DRAIN_PERIOD);
        idle.tick(|| idle.vcpu_exited());
        assert!(is_armed(&idle));

        clock.advance(IDLE_DRAIN_PERIOD);
        idle.tick(|| ());
        assert!(!is_armed(&idle));
    }
}
