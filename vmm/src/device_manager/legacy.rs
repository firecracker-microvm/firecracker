use std::io::{self, stdout};
use std::sync::{Arc, Mutex};

use devices;
use sys_util::{self, EventFd, Terminal};

pub struct LegacyDeviceManager {
    pub io_bus: devices::Bus,
    pub stdio_serial: Arc<Mutex<devices::legacy::Serial>>,
    pub i8042: Arc<Mutex<devices::legacy::I8042Device>>,

    pub com_evt_1_3: EventFd,
    pub com_evt_2_4: EventFd,
    pub stdin_handle: io::Stdin,
}

pub type Result<T> = ::std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    EventFd(sys_util::Error),
    StdinHandle(sys_util::Error),
}

impl LegacyDeviceManager {
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

    pub fn register_devices(&mut self) -> Result<()> {
        self.io_bus
            .insert(self.stdio_serial.clone(), 0x3f8, 0x8)
            .unwrap();
        self.io_bus
            .insert(
                Arc::new(Mutex::new(devices::legacy::Serial::new_sink(
                    self.com_evt_2_4.try_clone().map_err(Error::EventFd)?,
                ))),
                0x2f8,
                0x8,
            )
            .unwrap();
        self.io_bus
            .insert(
                Arc::new(Mutex::new(devices::legacy::Serial::new_sink(
                    self.com_evt_1_3.try_clone().map_err(Error::EventFd)?,
                ))),
                0x3e8,
                0x8,
            )
            .unwrap();
        self.io_bus
            .insert(
                Arc::new(Mutex::new(devices::legacy::Serial::new_sink(
                    self.com_evt_2_4.try_clone().map_err(Error::EventFd)?,
                ))),
                0x2e8,
                0x8,
            )
            .unwrap();
        self.stdin_handle
            .lock()
            .set_raw_mode()
            .map_err(|e| Error::StdinHandle(e))?;
        self.io_bus.insert(self.i8042.clone(), 0x064, 0x1).unwrap();
        Ok(())
    }
}
