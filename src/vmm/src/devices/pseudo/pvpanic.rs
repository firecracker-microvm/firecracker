// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Implements the register interface from the QEMU pvpanic specification over MMIO.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use vmm_sys_util::eventfd::EventFd;

use crate::logger::{error, info};
use crate::snapshot::Persist;
use crate::vmm_config::pvpanic::PvPanicAction;
use crate::vstate::bus::{BusDevice, BusWriteAction};

/// The guest panicked and the host must process the event.
pub(crate) const PVPANIC_PANICKED: u8 = 1 << 0;
/// The guest is handling the crash through its crash kernel.
pub(crate) const PVPANIC_CRASH_LOADED: u8 = 1 << 1;

// The guest does not fall back if its selected event is unsupported. Advertise both panic
// events, but not SHUTDOWN: Firecracker does not handle power-off through this device.
const SUPPORTED_EVENTS: u8 = PVPANIC_PANICKED | PVPANIC_CRASH_LOADED;

#[derive(Debug)]
enum PvPanicEvent {
    Ignore,
    Panicked,
    CrashLoaded,
}

impl PvPanicEvent {
    fn from_event(event: u8) -> Self {
        // Match QEMU's priority when a write contains more than one known event.
        if event & PVPANIC_PANICKED != 0 {
            Self::Panicked
        } else if event & PVPANIC_CRASH_LOADED != 0 {
            Self::CrashLoaded
        } else {
            Self::Ignore
        }
    }
}

/// Serializable pvpanic state. Eventfds and the runtime reporting flag are not saved.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct PvPanicState {
    /// Action to request when the guest reports a panic.
    pub panic_action: PvPanicAction,
}

/// QEMU-compatible pvpanic device with a single byte register at offset zero.
#[derive(Debug)]
pub struct PvPanic {
    panic_evt: Arc<EventFd>,
    panic_action: PvPanicAction,
    panic_reported: bool,
}

impl PvPanic {
    /// Create an armed device that reports guest panics through `panic_evt`.
    pub fn new(panic_evt: Arc<EventFd>, panic_action: PvPanicAction) -> Self {
        Self {
            panic_evt,
            panic_action,
            panic_reported: false,
        }
    }

    /// Action requested for an accepted `PVPANIC_PANICKED` event.
    pub fn panic_action(&self) -> PvPanicAction {
        self.panic_action
    }

    /// Share the notification eventfd with the device manager during registration.
    pub(crate) fn panic_evt(&self) -> &Arc<EventFd> {
        &self.panic_evt
    }
}

impl BusDevice for PvPanic {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        if offset == 0 && data.len() == 1 {
            data[0] = SUPPORTED_EVENTS;
        }
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> BusWriteAction {
        if offset != 0 || data.len() != 1 {
            return BusWriteAction::Continue;
        }

        match PvPanicEvent::from_event(data[0]) {
            PvPanicEvent::Panicked if !self.panic_reported => {
                if let Err(err) = self.panic_evt.write(1) {
                    error!("pvpanic: failed to notify the VMM of the guest panic: {err}");
                    // Keep the device armed. Never self-pause without notifying the VMM.
                    return BusWriteAction::Continue;
                }
                self.panic_reported = true;
                return match self.panic_action {
                    PvPanicAction::None => BusWriteAction::Continue,
                    PvPanicAction::Pause => BusWriteAction::PauseVcpu,
                };
            }
            PvPanicEvent::CrashLoaded => {
                // Do not pause or consume the reporting flag: the crash kernel may panic later.
                info!(
                    "pvpanic: guest panicked and is handling the crash itself (event={:#x})",
                    data[0]
                );
            }
            PvPanicEvent::Panicked | PvPanicEvent::Ignore => {}
        }
        BusWriteAction::Continue
    }
}

impl Persist<'_> for PvPanic {
    type State = PvPanicState;
    type ConstructorArgs = ();
    type Error = std::io::Error;

    fn save(&self) -> Self::State {
        PvPanicState {
            panic_action: self.panic_action,
        }
    }

    fn restore(_: Self::ConstructorArgs, state: &Self::State) -> Result<Self, Self::Error> {
        let panic_evt = Arc::new(EventFd::new(libc::EFD_NONBLOCK)?);
        Ok(Self::new(panic_evt, state.panic_action))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(action: PvPanicAction) -> PvPanic {
        PvPanic::new(Arc::new(EventFd::new(libc::EFD_NONBLOCK).unwrap()), action)
    }

    #[test]
    fn test_read_capabilities_and_invalid_accesses() {
        let mut dev = device(PvPanicAction::None);
        let mut data = [0];
        dev.read(0, 0, &mut data);
        assert_eq!(data, [PVPANIC_PANICKED | PVPANIC_CRASH_LOADED]);

        data[0] = 0x80;
        dev.read(0, 1, &mut data);
        assert_eq!(data, [0x80]);
        let mut wide = [0x80; 4];
        dev.read(0, 0, &mut wide);
        assert_eq!(wide, [0x80; 4]);
        dev.read(0, 0, &mut []);
    }

    #[test]
    fn test_ignored_writes_do_not_consume_panic_report() {
        let mut dev = device(PvPanicAction::Pause);
        for (offset, data) in [
            (1, &[PVPANIC_PANICKED][..]),
            (0, &[][..]),
            (0, &[PVPANIC_PANICKED, 0][..]),
            (0, &[0][..]),
            (0, &[1 << 2][..]),
            (0, &[0x80][..]),
        ] {
            assert!(matches!(
                dev.write(0, offset, data),
                BusWriteAction::Continue
            ));
            dev.panic_evt.read().unwrap_err();
        }
        for _ in 0..2 {
            assert!(matches!(
                dev.write(0, 0, &[PVPANIC_CRASH_LOADED]),
                BusWriteAction::Continue
            ));
            dev.panic_evt.read().unwrap_err();
        }
        assert!(matches!(
            dev.write(0, 0, &[PVPANIC_PANICKED]),
            BusWriteAction::PauseVcpu
        ));
        assert_eq!(dev.panic_evt.read().unwrap(), 1);
    }

    #[test]
    fn test_panic_actions_priority_unknown_bits_and_deduplication() {
        for (action, event, expected) in [
            (
                PvPanicAction::None,
                PVPANIC_PANICKED,
                BusWriteAction::Continue,
            ),
            (
                PvPanicAction::Pause,
                PVPANIC_PANICKED,
                BusWriteAction::PauseVcpu,
            ),
            (
                PvPanicAction::Pause,
                PVPANIC_PANICKED | PVPANIC_CRASH_LOADED,
                BusWriteAction::PauseVcpu,
            ),
            (
                PvPanicAction::Pause,
                PVPANIC_PANICKED | 0x80,
                BusWriteAction::PauseVcpu,
            ),
        ] {
            let mut dev = device(action);
            let result = dev.write(0, 0, &[event]);
            assert!(matches!(
                (result, expected),
                (BusWriteAction::Continue, BusWriteAction::Continue)
                    | (BusWriteAction::PauseVcpu, BusWriteAction::PauseVcpu)
            ));
            if event == PVPANIC_PANICKED {
                assert!(matches!(
                    dev.write(0, 0, &[PVPANIC_PANICKED]),
                    BusWriteAction::Continue
                ));
            }
            assert_eq!(dev.panic_evt.read().unwrap(), 1);
            if event == PVPANIC_PANICKED {
                // Draining the notification must not rearm the device, including after Resume.
                assert!(matches!(
                    dev.write(0, 0, &[PVPANIC_PANICKED]),
                    BusWriteAction::Continue
                ));
                dev.panic_evt.read().unwrap_err();
            }
        }
    }

    #[test]
    fn test_notification_failure_allows_retry_without_pausing() {
        let mut dev = device(PvPanicAction::Pause);
        dev.panic_evt.write(u64::MAX - 1).unwrap();
        assert!(matches!(
            dev.write(0, 0, &[PVPANIC_PANICKED]),
            BusWriteAction::Continue
        ));
        assert_eq!(dev.panic_evt.read().unwrap(), u64::MAX - 1);
        assert!(matches!(
            dev.write(0, 0, &[PVPANIC_PANICKED]),
            BusWriteAction::PauseVcpu
        ));
        assert_eq!(dev.panic_evt.read().unwrap(), 1);
    }

    #[test]
    fn test_device_save_restore() {
        // A device that already reported a panic is armed again by restore: the
        // runtime reporting flag is not part of the saved state.
        let mut dev = device(PvPanicAction::Pause);
        let _ = dev.write(0, 0, &[PVPANIC_PANICKED]);

        let mut restored = PvPanic::restore((), &dev.save()).unwrap();
        let _ = restored.write(0, 0, &[PVPANIC_PANICKED]);
        assert_eq!(restored.panic_evt.read().unwrap(), 1);
    }
}
