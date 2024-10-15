// Copyright 2023 Arm Limited (or its affiliates). All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use libc::{sysconf, _SC_PAGESIZE};

/// get host page size
pub fn get_page_size() -> u64 {
    // SAFETY: FFI call. Trivially safe.
    unsafe { sysconf(_SC_PAGESIZE) as u64 }
}

/// round up address to let it align page size
pub fn align_page_size_up(address: u64) -> u64 {
    let page_size = get_page_size();
    (address + page_size - 1) & !(page_size - 1)
}

/// round down address to let it align page size
pub fn align_page_size_down(address: u64) -> u64 {
    let page_size = get_page_size();
    address & !(page_size - 1)
}

/// Test if address is 4k aligned
pub fn is_4k_aligned(address: u64) -> bool {
    (address & 0xfff) == 0
}

/// Test if size is 4k aligned
pub fn is_4k_multiple(size: u64) -> bool {
    (size & 0xfff) == 0
}

/// Test if address is page size aligned
pub fn is_page_size_aligned(address: u64) -> bool {
    let page_size = get_page_size();
    address & (page_size - 1) == 0
}
