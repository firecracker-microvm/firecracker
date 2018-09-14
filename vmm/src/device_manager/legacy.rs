use std::io::{self, stdout};
use std::sync::{Arc, Mutex};

use devices;
use sys_util::{self, EventFd, Terminal};

#[derive(Debug)]
pub enum Error {
    BusError(devices::BusError),
    EventFd(sys_util::Error),
    StdinHandle(sys_util::Error),
}

type Result<T> = ::std::result::Result<T, Error>;

pub struct LegacyDeviceManager {
    pub io_bus: devices::Bus,
    pub stdio_serial: Arc<Mutex<devices::legacy::Serial>>,
    pub i8042: Arc<Mutex<devices::legacy::I8042Device>>,

    pub com_evt_1_3: EventFd,
    pub com_evt_2_4: EventFd,
    pub stdin_handle: io::Stdin,
}

impl LegacyDeviceManager {
    /// Create a new DeviceManager handling legacy devices (uart, i8042).
    pub fn new() -> Result<Self> {
        let io_bus = devices::Bus::new();
        let com_evt_1_3 = EventFd::new().map_err(Error::EventFd)?;
        let com_evt_2_4 = EventFd::new().map_err(Error::EventFd)?;
        let stdio_serial = Arc::new(Mutex::new(devices::legacy::Serial::new_out(
            com_evt_1_3.try_clone().map_err(Error::EventFd)?,
            Box::new(stdout()),
        )));

        // Create exit event for i8042
        let exit_evt = EventFd::new().map_err(Error::EventFd)?;
        let i8042 = Arc::new(Mutex::new(devices::legacy::I8042Device::new(exit_evt)));

        Ok(LegacyDeviceManager {
            io_bus,
            stdio_serial,
            i8042,
            com_evt_1_3,
            com_evt_2_4,
            stdin_handle: io::stdin(),
        })
    }

    /// Register supported legacy devices.
    pub fn register_devices(&mut self) -> Result<()> {
        self.io_bus
            .insert(self.stdio_serial.clone(), 0x3f8, 0x8)
            .map_err(|err| Error::BusError(err))?;
        self.io_bus
            .insert(
                Arc::new(Mutex::new(devices::legacy::Serial::new_sink(
                    self.com_evt_2_4.try_clone().map_err(Error::EventFd)?,
                ))),
                0x2f8,
                0x8,
            ).map_err(|err| Error::BusError(err))?;
        self.io_bus
            .insert(
                Arc::new(Mutex::new(devices::legacy::Serial::new_sink(
                    self.com_evt_1_3.try_clone().map_err(Error::EventFd)?,
                ))),
                0x3e8,
                0x8,
            ).map_err(|err| Error::BusError(err))?;
        self.io_bus
            .insert(
                Arc::new(Mutex::new(devices::legacy::Serial::new_sink(
                    self.com_evt_2_4.try_clone().map_err(Error::EventFd)?,
                ))),
                0x2e8,
                0x8,
            ).map_err(|err| Error::BusError(err))?;
        self.stdin_handle
            .lock()
            .set_raw_mode()
            .map_err(|e| Error::StdinHandle(e))?;
        self.io_bus
            .insert(self.i8042.clone(), 0x064, 0x1)
            .map_err(|err| Error::BusError(err))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_legacy_devices() {
        let ldm = LegacyDeviceManager::new();
        assert!(ldm.is_ok());
        assert!(&ldm.unwrap().register_devices().is_ok());
        // we need to reset the terminal otherwise stdin will remain in raw mode
        let stdin_handle = io::stdin();
        stdin_handle.lock().set_canon_mode().unwrap();
    }

    #[test]
    fn test_debug_error() {
        assert_eq!(
            format!("{:?}", Error::EventFd(sys_util::Error::new(0))),
            "EventFd(Error(0))"
        );
        assert_eq!(
            format!("{:?}", Error::StdinHandle(sys_util::Error::new(1))),
            "StdinHandle(Error(1))"
        );
    }
}
