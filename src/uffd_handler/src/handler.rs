// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::os::unix::io::AsRawFd;

use userfaultfd::{Event, Uffd};
use utils::get_page_size;

use crate::memory_region::{MemPageState, MemRegion};
use crate::prefaulter::UffdPrefaulter;

/// Timeout for poll()ing on the userfaultfd for events.
/// A negative value translates to an infinite timeout. Page faults are not meant to
/// appear at a constant frequency, so depending on the guest workload, there can be
/// situations when we need to wait longer for events.
const POLL_TIMEOUT: i32 = -1;

#[derive(Debug, thiserror::Error)]
pub enum HandlerError {
    #[error("Page fault address does not belong to any of the guest memory regions.")]
    AddressNotInRegion,
    #[error("Userfaultfd event is not ready.")]
    EventNotReady,
    #[error("Failed to fetch system's page size: {0}")]
    PageSize(utils::errno::Error),
    #[error("Failed to poll on userfaultfd: {0}")]
    Poll(io::Error),
    #[error("Failed to read userfaultfd event: {0}.")]
    ReadEvent(userfaultfd::Error),
    #[error("Userfaultfd copy failed: {0}")]
    UffdCopy(userfaultfd::Error),
    #[error("Userfaultfd {0} operation returned 0 bytes.")]
    UffdNoOperation(String),
    #[error("Userfaultfd failed to zero out pages: {0}")]
    UffdZero(userfaultfd::Error),
    #[error("Userfaultfd received unexpected event: {0:?}.")]
    UnexpectedEvent(Event),
}

type Result<T> = std::result::Result<T, HandlerError>;

pub trait UffdManager: AsRawFd {
    fn poll_fd(&self) -> Result<Event>;

    fn populate_from_file(
        &self,
        buff: *const libc::c_void,
        start_addr: usize,
        end_addr: usize,
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
        start_addr: usize,
        end_addr: usize,
        region: &MemRegion,
    ) -> Result<(usize, usize)> {
        let page_size = get_page_size().map_err(HandlerError::PageSize)?;
        // The result will always be positive because both start_addr and end_addr are within the
        // current region and the difference between them is always at least page size.
        let mut len = end_addr - start_addr;
        // Length to uffd copy must be multiple of page size.
        let reminder = len % page_size;
        if reminder != 0 {
            len += page_size - reminder;
        }

        // Compute source to prefault the memory chunk from.
        let prefault_offset = start_addr - region.mapping.base_host_virt_addr;
        let src = buff as u64 + region.mapping.offset + prefault_offset as u64;

        // SAFETY: this is safe because the parameters are valid.
        let ret = match unsafe { self.copy(src as *const _, start_addr as *mut _, len, true) } {
            // Allow partial copy, which happens when a part of the requested region for
            // prefaulting has already been brought into RAM when serving a previous page fault.
            Ok(ret) | Err(userfaultfd::Error::PartiallyCopied(ret)) => ret,
            Err(err) => return Err(HandlerError::UffdCopy(err)),
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
    prefaulter: UffdPrefaulter,
    // Not currently used but included to demonstrate how a page fault handler can
    // fetch Firecracker's PID in order to make it aware of any crashes/exits.
    _firecracker_pid: u32,
}

impl<T> PageFaultHandler<T>
where
    T: UffdManager,
{
    pub fn new(
        mem_regions: Vec<MemRegion>,
        buff: *const libc::c_void,
        uffd: T,
        prefaulter: UffdPrefaulter,
        pid: u32,
    ) -> Self {
        PageFaultHandler {
            mem_regions,
            backing_buffer: buff,
            uffd,
            prefaulter,
            _firecracker_pid: pid,
        }
    }

    fn update_mem_state_mappings(&mut self, start: usize, end: usize, state: MemPageState) {
        for region in self.mem_regions.iter_mut() {
            for (key, value) in region.page_states.iter_mut() {
                if (start..end).contains(key) {
                    *value = state;
                }
            }
        }
    }

    fn serve_page_fault(&mut self, addr: usize) -> Result<()> {
        let fault_page_addr = page_start_of_addr(addr)?;

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
                    let start_addr = self
                        .prefaulter
                        .get_prefaulting_start_address(fault_page_addr)?;
                    let end_addr = self
                        .prefaulter
                        .get_prefaulting_end_address(fault_page_addr, region)?;
                    let (start, end) = self.uffd.populate_from_file(
                        self.backing_buffer,
                        start_addr,
                        end_addr,
                        region,
                    )?;
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

    fn handle_event(&mut self, event: Event) -> Result<()> {
        // Expect to receive either a `PageFault` or `Removed` event
        // (if the balloon device is enabled).
        match event {
            Event::Pagefault { addr, .. } => self.serve_page_fault(addr as usize)?,
            Event::Remove { start, end } => {
                self.update_mem_state_mappings(start as usize, end as usize, MemPageState::Removed)
            }
            event => return Err(HandlerError::UnexpectedEvent(event)),
        }
        Ok(())
    }

    pub fn run(&mut self) -> Result<()> {
        let mut pollfd = libc::pollfd {
            fd: self.uffd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };

        // Loop, handling incoming events on the userfaultfd file descriptor.
        loop {
            // SAFETY: Safe because fd, nfds and timeout are valid parameters.
            let nready = unsafe { libc::poll(&mut pollfd, 1, POLL_TIMEOUT) };
            if nready == -1 {
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    // Retry in case of `EINTR` error, which means that a signal occurred before
                    // any requested event (see https://man7.org/linux/man-pages/man2/poll.2.html#ERRORS).
                    Some(libc::EINTR) => continue,
                    Some(_) => return Err(HandlerError::Poll(err)),
                    // When `poll` fails, errno is always set so this case should never happen.
                    None => unreachable!(),
                }
            }

            // Read an event from the userfaultfd.
            let event = self.uffd.poll_fd()?;
            self.handle_event(event)?;
        }
    }
}

/// Find the start of the page that the current address belongs to.
pub fn page_start_of_addr(addr: usize) -> Result<usize> {
    let page_size = get_page_size().map_err(HandlerError::PageSize)?;
    let dst = (addr & !(page_size - 1)) as *mut libc::c_void;

    Ok(dst as usize)
}

#[cfg(test)]
mod tests {
    use std::os::unix::io::RawFd;
    use std::ptr;

    use utils::GuestRegionUffdMapping;

    use super::*;
    use crate::handler::UffdPrefaulter;
    use crate::memory_region::create_mem_regions;

    const PAGE_SIZE: usize = 4096;

    struct MockUffd;

    impl AsRawFd for MockUffd {
        fn as_raw_fd(&self) -> RawFd {
            RawFd::MIN
        }
    }

    impl UffdManager for MockUffd {
        fn poll_fd(&self) -> Result<Event> {
            Err(HandlerError::EventNotReady)
        }

        // Simulate copying the first page.
        fn populate_from_file(
            &self,
            _buff: *const libc::c_void,
            _start: usize,
            _end: usize,
            _region: &MemRegion,
        ) -> Result<(usize, usize)> {
            Ok((0x0, 0x1000))
        }

        // Simulate zeroing out the third page.
        fn zero_out(&self, _addr: usize) -> Result<(usize, usize)> {
            Ok((0x1000, 0x2000))
        }
    }

    fn create_handler(start: usize, mem_size: usize) -> PageFaultHandler<MockUffd> {
        // Create a memory mapping of one region with size and address specified.
        let mappings = vec![GuestRegionUffdMapping {
            base_host_virt_addr: start,
            size: mem_size,
            offset: 0,
        }];

        PageFaultHandler::new(
            create_mem_regions(mappings),
            ptr::null(),
            MockUffd {},
            UffdPrefaulter::default(),
            0,
        )
    }

    #[test]
    fn test_serve_page_fault() {
        let start = 0;
        let size = PAGE_SIZE * 3;
        let mut handler = create_handler(start, size);

        // Serve page fault for the first page (address 0x0).
        // Handling a page fault on an Uninitialized page should trigger
        // a copy from file. The first page should now be marked as `FromFile`.
        assert_eq!(
            *handler.mem_regions[0].page_states.get(&start).unwrap(),
            MemPageState::Uninitialized
        );
        handler.serve_page_fault(0x100).unwrap();
        assert_eq!(
            *handler.mem_regions[0].page_states.get(&start).unwrap(),
            MemPageState::FromFile
        );

        // Mark the second page in the memory region as `Removed`.
        // Handling a page fault on this type of page should trigger a zero out.
        handler.mem_regions[0]
            .page_states
            .insert(0x1000, MemPageState::Removed);
        handler.serve_page_fault(0x1500).unwrap();
        // The second page should now be marked as `Anonymous`.
        assert_eq!(
            *handler.mem_regions[0]
                .page_states
                .get(&(start + PAGE_SIZE))
                .unwrap(),
            MemPageState::Anonymous
        );

        // Serving a page fault for an address outside of region should fail.
        let res = handler.serve_page_fault(size + 1);
        assert!(res.is_err());
        assert_eq!(
            HandlerError::AddressNotInRegion.to_string(),
            res.err().unwrap().to_string()
        );
    }

    #[test]
    fn test_update_mem_state_mappings() {
        let start = 0;
        let size = PAGE_SIZE * 3;
        let mut handler = create_handler(start, size);
        assert!(handler
            .mem_regions
            .iter()
            .flat_map(|region| region.page_states.values())
            .all(|state| matches!(state, MemPageState::Uninitialized)));

        handler.update_mem_state_mappings(start, size, MemPageState::FromFile);
        assert!(handler
            .mem_regions
            .iter()
            .flat_map(|region| region.page_states.values())
            .all(|state| matches!(state, MemPageState::FromFile)));

        // Attempt to update pages from outside the current region. Mapping should not change.
        handler.update_mem_state_mappings(size + 1, size, MemPageState::Removed);
        assert!(handler
            .mem_regions
            .iter()
            .flat_map(|region| region.page_states.values())
            .all(|state| matches!(state, MemPageState::FromFile)));
    }

    #[test]
    fn test_handle_pf_event() {
        let start = 0;
        let size = PAGE_SIZE * 3;
        let mut handler = create_handler(start, size);

        assert_eq!(
            *handler.mem_regions[0].page_states.get(&start).unwrap(),
            MemPageState::Uninitialized
        );
        assert!(handler
            .handle_event(Event::Pagefault {
                kind: userfaultfd::FaultKind::Missing,
                rw: userfaultfd::ReadWrite::Read,
                addr: start as *mut libc::c_void
            })
            .is_ok());
        assert_eq!(
            *handler.mem_regions[0].page_states.get(&start).unwrap(),
            MemPageState::FromFile
        );
    }

    #[test]
    fn test_handle_remove_event() {
        let start = 0;
        let size = PAGE_SIZE * 3;
        let mut handler = create_handler(start, size);

        assert!(handler
            .handle_event(Event::Remove {
                start: start as *mut libc::c_void,
                end: PAGE_SIZE as *mut libc::c_void
            })
            .is_ok());
        assert_eq!(
            *handler.mem_regions[0].page_states.get(&start).unwrap(),
            MemPageState::Removed
        );
    }

    #[test]
    fn test_handle_unexpected_event() {
        let start = 0;
        let size = PAGE_SIZE * 3;
        let mut handler = create_handler(start, size);

        let event = Event::Unmap {
            start: start as *mut libc::c_void,
            end: PAGE_SIZE as *mut libc::c_void,
        };
        let res = handler.handle_event(event);
        assert!(res.is_err());
        assert!(matches!(
            res.err().unwrap(),
            HandlerError::UnexpectedEvent(_)
        ));
    }

    #[test]
    fn test_page_start_of_addr() {
        assert_eq!(page_start_of_addr(0).unwrap(), 0);
        assert_eq!(page_start_of_addr(PAGE_SIZE / 2).unwrap(), 0);
        assert_eq!(page_start_of_addr(PAGE_SIZE - 1).unwrap(), 0);
        assert_eq!(
            page_start_of_addr(PAGE_SIZE * 10 - 1).unwrap(),
            PAGE_SIZE * 9
        );
    }
}
