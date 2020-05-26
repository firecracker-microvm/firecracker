// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod serial_utils;

use std::io;
use std::os::raw::{c_int, c_void};
use std::sync::{Arc, Mutex};

use devices::legacy::Serial;
use devices::BusDevice;
use polly::event_manager::EventManager;
use serial_utils::MockSerialInput;
use utils::epoll::{EpollEvent, EventSet};
use utils::eventfd::EventFd;

#[test]
fn test_issue_serial_hangup_anon_pipe() {
    let mut fds: [c_int; 2] = [0; 2];
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert!(rc == 0);

    // Serial input is the reading end of the pipe.
    let serial_in = MockSerialInput(fds[0]);
    let serial = Arc::new(Mutex::new(Serial::new_in_out(
        EventFd::new(libc::EFD_NONBLOCK).unwrap(),
        Box::new(serial_in),
        Box::new(io::stdout()),
    )));

    // Make reading fd non blocking to read just what is inflight.
    let flags = unsafe { libc::fcntl(fds[0], libc::F_GETFL, 0) };
    let mut rc = unsafe { libc::fcntl(fds[0], libc::F_SETFL, flags | libc::O_NONBLOCK) };
    assert!(rc == 0);

    // Write some dummy data on the writing end of the pipe to handle it later on.
    // 33 bytes are read in two rounds of serial input processing because
    // it  is handled in batches of 32 bytes at maximum.
    const BYTES_COUNT: usize = 33;
    let mut dummy_data = [1u8; BYTES_COUNT];
    rc = unsafe {
        libc::write(
            fds[1],
            dummy_data.as_mut_ptr() as *const c_void,
            dummy_data.len(),
        ) as i32
    };
    assert!(dummy_data.len() == rc as usize);

    // Register the reading end of the pipe to the event manager, to be processed later on.
    let mut event_manager = EventManager::new().unwrap();
    event_manager
        .register(
            fds[0],
            EpollEvent::new(EventSet::IN, fds[0] as u64),
            serial.clone(),
        )
        .unwrap();

    let mut ev_count = 1;
    while ev_count != 0 {
        // `EventSet::IN` was received.
        ev_count = event_manager.run_with_timeout(0).unwrap();
    }

    let mut data = [0u8; BYTES_COUNT];

    // On the main thread, we will simulate guest "vCPU" thread serial reads.
    let data_bus_offset = 0;
    for i in 0..BYTES_COUNT {
        serial
            .lock()
            .unwrap()
            .read(data_bus_offset, &mut data[i..=i]);
    }

    // We need to assert on a maximum of 32 bytes slices, because this is the maximum
    // rust can compare.
    assert!(data[..31] == dummy_data[..31]);
    assert!(data[32] == dummy_data[32]);

    // Close the writing end (this sends an HANG_UP to the reading end).
    rc = unsafe { libc::close(fds[1]) };
    assert!(rc == 0);

    // `EventSet::HANG_UP` was received.
    let ev_count = event_manager.run().unwrap();
    assert!(ev_count == 1);

    // Serial input was unregistered.
    let ev_count = event_manager.run_with_timeout(1).unwrap();
    assert!(ev_count == 0);
}
