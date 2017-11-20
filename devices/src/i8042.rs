// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use sys_util::EventFd;

use BusDevice;

/// A i8042 PS/2 controller that emulates just enough to shutdown the machine.
pub struct I8042Device {
    reset_evt: EventFd,
}

impl I8042Device {
    /// Constructs a i8042 device that will signal the given event when the guest requests it.
    pub fn new(reset_evt: EventFd) -> I8042Device {
        I8042Device { reset_evt: reset_evt }
    }
}

impl BusDevice for I8042Device {
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        if data.len() == 1 && offset == 0 {
            data[0] = 0x0;
        }
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        if data.len() == 1 && data[0] == 0xfe && offset == 0 {
            if let Err(e) = self.reset_evt.write(1) {
                error!("failed to trigger i8042 reset event: {:?}", e);
            }
        }
    }
}
