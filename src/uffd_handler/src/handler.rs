// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{MemPageState, MemRegion};
use userfaultfd::Uffd;
use utils::get_page_size;

pub struct UffdPfHandler {
    mem_regions: Vec<MemRegion>,
    backing_buffer: *const libc::c_void,
    pub uffd: Uffd,
    // Not currently used but included to demonstrate how a page fault handler can
    // fetch Firecracker's PID in order to make it aware of any crashes/exits.
    _firecracker_pid: u32,
}

impl UffdPfHandler {
    pub fn new(
        mem_regions: Vec<MemRegion>,
        buf: *const libc::c_void,
        uffd: Uffd,
        pid: u32,
    ) -> Self {
        UffdPfHandler {
            mem_regions,
            backing_buffer: buf,
            uffd,
            _firecracker_pid: pid,
        }
    }

    pub fn update_mem_state_mappings(&mut self, start: u64, end: u64, state: MemPageState) {
        for region in self.mem_regions.iter_mut() {
            for (key, value) in region.page_states.iter_mut() {
                if (start..end).contains(key) {
                    *value = state;
                }
            }
        }
    }

    fn populate_from_file(&self, region: &MemRegion) -> (u64, u64) {
        let src = self.backing_buffer as u64 + region.mapping.offset;
        let start_addr = region.mapping.base_host_virt_addr;
        let len = region.mapping.size;
        // Populate whole region from backing mem-file.
        // This offers an example of how memory can be loaded in RAM,
        // however this can be adjusted to accommodate use case needs.
        // SAFETY: this is safe because the parameters are controlled by us.
        let ret = unsafe {
            self.uffd
                .copy(src as *const _, start_addr as *mut _, len, true)
                .expect("Uffd copy failed")
        };

        // Make sure the UFFD copied some bytes.
        assert!(ret > 0);

        (start_addr, start_addr + len as u64)
    }

    fn zero_out(&mut self, addr: u64) -> (u64, u64) {
        let page_size = get_page_size().unwrap();

        // SAFETY: this is safe because the parameters are controlled by us.
        let ret = unsafe {
            self.uffd
                .zeropage(addr as *mut _, page_size, true)
                .expect("Uffd zeropage failed")
        };
        // Make sure the UFFD zeroed out some bytes.
        assert!(ret > 0);

        (addr, addr + page_size as u64)
    }

    pub fn serve_pf(&mut self, addr: *mut u8) {
        let page_size = get_page_size().unwrap();

        // Find the start of the page that the current faulting address belongs to.
        let dst = (addr as usize & !(page_size - 1)) as *mut libc::c_void;
        let fault_page_addr = dst as u64;

        // Get the state of the current faulting page.
        for region in self.mem_regions.iter() {
            match region.page_states.get(&fault_page_addr) {
                // Our simple PF handler has a simple strategy:
                // There exist 4 states in which a memory page can be in:
                // 1. Uninitialized - page was never touched
                // 2. FromFile - the page is populated with content from snapshotted memory file
                // 3. Removed - MADV_DONTNEED was called due to balloon inflation
                // 4. Anonymous - page was zeroed out -> this implies that more than one page fault
                //    event was received. This can be a consequence of guest reclaiming back its
                //    memory from the host (through balloon device)
                Some(MemPageState::Uninitialized) | Some(MemPageState::FromFile) => {
                    let (start, end) = self.populate_from_file(region);
                    self.update_mem_state_mappings(start, end, MemPageState::FromFile);
                    return;
                }
                Some(MemPageState::Removed) | Some(MemPageState::Anonymous) => {
                    let (start, end) = self.zero_out(fault_page_addr);
                    self.update_mem_state_mappings(start, end, MemPageState::Anonymous);
                    return;
                }
                None => {}
            }
        }

        panic!(
            "Could not find addr: {:?} within guest region mappings.",
            addr
        );
    }
}
