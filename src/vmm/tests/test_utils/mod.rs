// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::panic;

use utils::terminal::Terminal;

const VMM_ERR_EXIT: i32 = 42;

pub fn restore_stdin() {
    let stdin = io::stdin();
    stdin.lock().set_canon_mode().unwrap();
}

pub fn set_panic_hook() {
    panic::set_hook(Box::new(move |_| {
        restore_stdin();
        unsafe {
            libc::exit(VMM_ERR_EXIT);
        }
    }));
}
