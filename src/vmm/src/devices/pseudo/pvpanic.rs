// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Pseudo device implementing the QEMU pvpanic MMIO interface.
//!
//! The byte register at offset 0 returns supported events on read and reports
//! panic events on write.

use std::sync::{Arc, Barrier};

use vmm_sys_util::eventfd::EventFd;

use crate::logger::{error, info};
use crate::vstate::bus::BusDevice;

/// The guest panicked and the host must process the event.
const PVPANIC_PANICKED: u8 = 1 << 0;

/// The guest is handling the crash through its crash kernel.
const PVPANIC_CRASH_LOADED: u8 = 1 << 1;

/// Advertise both events because the guest does not fall back when its
/// selected event is unsupported. Do not advertise `PVPANIC_SHUTDOWN`:
/// Firecracker does not handle guest power-off through pvpanic.
const SUPPORTED_EVENTS: u8 = PVPANIC_PANICKED | PVPANIC_CRASH_LOADED;

#[derive(Debug, PartialEq, Eq)]
enum PanicAction {
    Ignore,
    Panicked,
    CrashLoaded,
}

impl PanicAction {
    /// Match QEMU: handle at most one known event, in priority order.
    fn from_event(event: u8) -> Self {
        if event & PVPANIC_PANICKED != 0 {
            Self::Panicked
        } else if event & PVPANIC_CRASH_LOADED != 0 {
            Self::CrashLoaded
        } else {
            Self::Ignore
        }
    }
}

/// Pseudo device implementing the pvpanic MMIO register.
#[derive(Debug)]
pub struct PvPanic {
    /// Notifies the VMM event loop of `PVPANIC_PANICKED` events.
    panic_evt: EventFd,
}

impl BusDevice for PvPanic {
    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        if data.len() != 1 || offset != 0 {
            return None;
        }

        let event = data[0];
        match PanicAction::from_event(event) {
            PanicAction::Panicked => {
                info!("pvpanic: guest panicked (event={:#x})", event);
                // This runs on the vCPU thread, so VM actions belong in the VMM event
                // loop; pausing here would make the vCPU wait for itself.
                if let Err(err) = self.panic_evt.write(1) {
                    error!("pvpanic: failed to notify the VMM of the guest panic: {err}");
                }
            }
            PanicAction::CrashLoaded => {
                // The crash kernel handles the dump; do not stop or reset the VM.
                info!(
                    "pvpanic: guest panicked and is handling the crash itself (event={:#x})",
                    event
                );
            }
            PanicAction::Ignore => {}
        }

        None
    }

    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        if data.len() != 1 || offset != 0 {
            return;
        }

        data[0] = SUPPORTED_EVENTS;
    }
}

impl PvPanic {
    /// Create a device that signals `panic_evt` for `PVPANIC_PANICKED` events.
    pub fn new(panic_evt: EventFd) -> Self {
        Self { panic_evt }
    }

    /// Clone the eventfd used for VMM panic notifications.
    pub fn try_clone_panic_evt(&self) -> std::io::Result<EventFd> {
        self.panic_evt.try_clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A regular guest shutdown, which this device does not advertise.
    const PVPANIC_SHUTDOWN: u8 = 1 << 2;

    fn pvpanic_dev() -> (PvPanic, EventFd) {
        let dev = PvPanic::new(EventFd::new(libc::EFD_NONBLOCK).unwrap());
        let panic_evt = dev.try_clone_panic_evt().unwrap();
        (dev, panic_evt)
    }

    #[test]
    fn test_read_returns_supported_events() {
        let (mut dev, _panic_evt) = pvpanic_dev();
        let mut data = [0u8; 1];
        dev.read(0, 0, &mut data);
        assert_eq!(data[0], PVPANIC_PANICKED | PVPANIC_CRASH_LOADED);
    }

    #[test]
    fn test_shutdown_event_is_not_advertised() {
        let (mut dev, _panic_evt) = pvpanic_dev();
        let mut data = [0u8; 1];
        dev.read(0, 0, &mut data);
        assert_eq!(data[0] & PVPANIC_SHUTDOWN, 0);
    }

    #[test]
    fn test_read_ignores_non_byte_access() {
        let (mut dev, _panic_evt) = pvpanic_dev();
        let mut data = [0u8; 4];
        dev.read(0, 0, &mut data);
        assert_eq!(data, [0u8; 4]);

        let mut data = [0u8; 1];
        dev.read(0, 1, &mut data);
        assert_eq!(data[0], 0);
    }

    #[test]
    fn test_panicked_takes_priority_over_crash_loaded() {
        assert_eq!(
            PanicAction::from_event(PVPANIC_PANICKED | PVPANIC_CRASH_LOADED),
            PanicAction::Panicked
        );
    }

    #[test]
    fn test_crash_loaded_is_decoded_separately() {
        assert_eq!(
            PanicAction::from_event(PVPANIC_CRASH_LOADED),
            PanicAction::CrashLoaded
        );
    }

    #[test]
    fn test_unsupported_events_are_ignored() {
        assert_eq!(
            PanicAction::from_event(PVPANIC_SHUTDOWN),
            PanicAction::Ignore
        );
        assert_eq!(PanicAction::from_event(0), PanicAction::Ignore);
        assert_eq!(
            PanicAction::from_event(PVPANIC_PANICKED | 0x80),
            PanicAction::Panicked
        );
    }

    #[test]
    fn test_write_accepts_panic_events() {
        let (mut dev, _panic_evt) = pvpanic_dev();
        // Panic writes are handled inline, so no barrier is returned.
        assert!(dev.write(0, 0, &[PVPANIC_PANICKED]).is_none());
        assert!(dev.write(0, 0, &[PVPANIC_CRASH_LOADED]).is_none());
        assert!(dev.write(0, 0, &[PVPANIC_SHUTDOWN]).is_none());
        assert!(dev.write(0, 0, &[0]).is_none());
    }

    #[test]
    fn test_write_ignores_non_byte_access() {
        let (mut dev, _panic_evt) = pvpanic_dev();
        assert!(dev.write(0, 0, &[PVPANIC_PANICKED, 0]).is_none());
        assert!(dev.write(0, 1, &[PVPANIC_PANICKED]).is_none());
    }

    #[test]
    fn test_panicked_write_notifies_the_vmm() {
        let (mut dev, panic_evt) = pvpanic_dev();
        dev.write(0, 0, &[PVPANIC_PANICKED]);
        assert_eq!(panic_evt.read().unwrap(), 1);
    }

    #[test]
    fn test_crash_loaded_write_does_not_notify_the_vmm() {
        let (mut dev, panic_evt) = pvpanic_dev();
        dev.write(0, 0, &[PVPANIC_CRASH_LOADED]);
        panic_evt.read().unwrap_err();
    }

    #[test]
    fn test_ignored_writes_do_not_notify_the_vmm() {
        let (mut dev, panic_evt) = pvpanic_dev();
        dev.write(0, 0, &[PVPANIC_SHUTDOWN]);
        dev.write(0, 0, &[0]);
        dev.write(0, 1, &[PVPANIC_PANICKED]);
        dev.write(0, 0, &[PVPANIC_PANICKED, 0]);
        panic_evt.read().unwrap_err();
    }
}
