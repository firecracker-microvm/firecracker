// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::io::AsRawFd;

use userfaultfd::{Event, Uffd};
use utils::get_page_size;

use crate::memory_region::{MemPageState, MemRegion};

#[derive(Debug, thiserror::Error)]
pub enum HandlerError {
    #[error("Page fault address does not belong to any of the guest memory regions.")]
    AddressNotInRegion,
    #[error("Userfaultfd event is not ready.")]
    EventNotReady,
    #[error("Failed to fetch system's page size: {0}")]
    PageSize(utils::errno::Error),
    #[error("Failed to read userfaultfd event: {0}.")]
    ReadEvent(userfaultfd::Error),
    #[error("Userfaultfd copy failed: {0}")]
    UffdCopy(userfaultfd::Error),
    #[error("Userfaultfd {0} operation returned 0 bytes.")]
    UffdNoOperation(String),
    #[error("Userfaultfd failed to zero out pages: {0}")]
    UffdZero(userfaultfd::Error),
}

type Result<T> = std::result::Result<T, HandlerError>;

pub trait UffdManager: AsRawFd {
    fn poll_fd(&self) -> Result<Event>;

    fn populate_from_file(
        &self,
        buff: *const libc::c_void,
        region: &MemRegion,
    ) -> Result<(usize, usize)>;

    fn zero_out(&self, addr: usize) -> Result<(usize, usize)>;
}

impl UffdManager for Uffd {
    fn poll_fd(&self) -> Result<Event> {
        // Read an event from the userfaultfd.
        let event_op = self.read_event().map_err(HandlerError::ReadEvent)?;
        match event_op {
            Some(event) => Ok(event),
            None => Err(HandlerError::EventNotReady),
        }
    }

    fn populate_from_file(
        &self,
        buff: *const libc::c_void,
        region: &MemRegion,
    ) -> Result<(usize, usize)> {
        let src = buff as u64 + region.mapping.offset;
        let start_addr = region.mapping.base_host_virt_addr;
        let len = region.mapping.size;
        // Populate whole region from backing mem-file.
        // This offers an example of how memory can be loaded in RAM,
        // however this can be adjusted to accommodate use case needs.
        // SAFETY: this is safe because the parameters are valid.
        let ret = unsafe {
            self.copy(src as *const _, start_addr as *mut _, len, true)
                .map_err(HandlerError::UffdCopy)?
        };

        // Make sure the UFFD copied some bytes.
        if ret == 0 {
            return Err(HandlerError::UffdNoOperation(String::from("copy")));
        }

        Ok((start_addr, start_addr + ret))
    }

    fn zero_out(&self, addr: usize) -> Result<(usize, usize)> {
        let page_size = get_page_size().map_err(HandlerError::PageSize)?;

        // SAFETY: this is safe because the parameters are valid.
        let ret = unsafe {
            self.zeropage(addr as *mut _, page_size, true)
                .map_err(HandlerError::UffdZero)?
        };
        // Make sure the UFFD zeroed out some bytes.
        if ret == 0 {
            return Err(HandlerError::UffdNoOperation(String::from("zero")));
        }

        Ok((addr, addr + ret))
    }
}

pub struct PageFaultHandler<T: UffdManager> {
    mem_regions: Vec<MemRegion>,
    backing_buffer: *const libc::c_void,
    pub uffd: T,
    // Not currently used but included to demonstrate how a page fault handler can
    // fetch Firecracker's PID in order to make it aware of any crashes/exits.
    _firecracker_pid: u32,
}

impl<T> PageFaultHandler<T>
where
    T: UffdManager,
{
    pub fn new(mem_regions: Vec<MemRegion>, buff: *const libc::c_void, uffd: T, pid: u32) -> Self {
        PageFaultHandler {
            mem_regions,
            backing_buffer: buff,
            uffd,
            _firecracker_pid: pid,
        }
    }

    pub fn update_mem_state_mappings(&mut self, start: usize, end: usize, state: MemPageState) {
        for region in self.mem_regions.iter_mut() {
            for (key, value) in region.page_states.iter_mut() {
                if (start..end).contains(key) {
                    *value = state;
                }
            }
        }
    }

    pub fn serve_pf(&mut self, addr: usize) -> Result<()> {
        let page_size = get_page_size().map_err(HandlerError::PageSize)?;

        // Find the start of the page that the current faulting address belongs to.
        let fault_page_addr = addr & !(page_size - 1);

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
                    let (start, end) = self.uffd.populate_from_file(self.backing_buffer, region)?;
                    self.update_mem_state_mappings(start, end, MemPageState::FromFile);
                    return Ok(());
                }
                Some(MemPageState::Removed) | Some(MemPageState::Anonymous) => {
                    let (start, end) = self.uffd.zero_out(fault_page_addr)?;
                    self.update_mem_state_mappings(start, end, MemPageState::Anonymous);
                    return Ok(());
                }
                None => {}
            }
        }

        Err(HandlerError::AddressNotInRegion)
    }
}
