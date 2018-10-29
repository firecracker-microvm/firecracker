// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
use logger::{Metric, METRICS};
use sys_util::{EventFd, Result};

use BusDevice;

const RESET_CMD: u8 = 0xfe;

/// A i8042 PS/2 controller that emulates just enough to shutdown the machine.
pub struct I8042Device {
    reset_evt: EventFd,
}

impl I8042Device {
    /// Constructs a i8042 device that will signal the given event when the guest requests it.
    pub fn new(reset_evt: EventFd) -> I8042Device {
        I8042Device { reset_evt }
    }

    /// Returns a clone of the EventFd
    pub fn get_eventfd_clone(&self) -> Result<EventFd> {
        return self.reset_evt.try_clone();
    }
}

impl BusDevice for I8042Device {
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        if data.len() == 1 && offset == 0 {
            data[0] = 0x0;
            METRICS.i8042.read_count.add(data.len());
        } else {
            METRICS.i8042.missed_read_count.inc();
        }
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        if data.len() == 1 && data[0] == RESET_CMD && offset == 0 {
            if let Err(e) = self.reset_evt.write(1) {
                error!("Failed to trigger i8042 reset event: {:?}", e);
                METRICS.i8042.error_count.inc();
            }
            METRICS.i8042.reset_count.inc();
        } else {
            METRICS.i8042.missed_write_count.inc();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_i8042_read_write_and_event() {
        let mut i8042 = I8042Device::new(EventFd::new().unwrap());
        let reset_evt = i8042.get_eventfd_clone().unwrap();

        // Check if reading in a 2-length array doesn't have side effects.
        let mut data = [1, 2];
        i8042.read(0, &mut data);
        assert_eq!(data, [1, 2]);
        i8042.read(1, &mut data);
        assert_eq!(data, [1, 2]);

        // Check if reset works.
        // Write 1 to the reset event fd, so that read doesn't block in case the event fd
        // counter doesn't change (for 0 it blocks).
        assert!(reset_evt.write(1).is_ok());
        let mut data = [RESET_CMD];
        i8042.write(0, &mut data);
        assert_eq!(reset_evt.read(), Ok(2));

        // Check if reading with offset 1 doesn't have side effects.
        i8042.read(1, &mut data);
        assert_eq!(data[0], RESET_CMD);

        // Check if reading in a 1-length array with offset 0 returns [0].
        i8042.read(0, &mut data);
        assert_eq!(data[0], 0);

        // Check invalid `write`s.
        let before = METRICS.i8042.missed_write_count.count();
        // offset != 0.
        i8042.write(1, &mut data);
        // data != RESET_CMD
        data[0] = RESET_CMD + 1;
        i8042.write(1, &mut data);
        // data.len() != 1
        let mut data = [RESET_CMD; 2];
        i8042.write(1, &mut data);
        assert_eq!(METRICS.i8042.missed_write_count.count(), before + 3);
    }
}
