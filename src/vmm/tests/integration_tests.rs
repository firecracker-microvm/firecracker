// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate devices;
extern crate polly;
extern crate vm_memory;
extern crate vmm;
extern crate vmm_sys_util;

mod mock_devices;

use std::io;

use polly::event_manager::EventManager;
use vmm::builder::setup_serial_device;
use vmm_sys_util::tempfile::TempFile;

use mock_devices::MockSerialInput;

#[test]
fn test_setup_serial_device() {
    let read_tempfile = TempFile::new().unwrap();
    let read_handle = MockSerialInput(read_tempfile.into_file());
    let mut event_manager = EventManager::new().unwrap();

    assert!(setup_serial_device(
        &mut event_manager,
        Box::new(read_handle),
        Box::new(io::stdout()),
    )
    .is_ok());
}
