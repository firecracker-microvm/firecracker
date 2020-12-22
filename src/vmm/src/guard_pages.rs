use std::fmt;
use std::io;
use std::os::unix::io::AsRawFd;
use std::ptr::null_mut;
use std::result;
use std::borrow::Borrow;

use vm_memory::mmap::{check_file_offset, Error as MmapError};
use vm_memory::{FileOffset, MmapRegion, GuestAddress, GuestMemoryMmap, GuestRegionMmap};

const GUARD_NUMBER: usize = 2;

/// Errors that can occur when creating a memory map.
#[derive(Debug)]
pub enum GuardPageError {
    /// Libc::mmap errors
    Mmap(io::Error),
    /// Error when trying to create a MmapRegion
    MmapRegionError(MmapError),
}

impl fmt::Display for GuardPageError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> fmt::Result {
        match self {
            GuardPageError::Mmap(error) => write!(f, "{}", error),
            GuardPageError::MmapRegionError(error) => write!(f, "MmapRegionError: {}", error),
        }
    }
}

/// Creates a container, allocates anonymous memory for guest memory regions and enables dirty page
/// tracking if set to True.
/// Every memory range is mapped guarded.
///
/// Valid memory regions are specified as a slice of (Address, Size) tuples sorted by Address
pub fn create_guest_memory_guarded(
    ranges: &[(GuestAddress, usize)],
    track_dirty_pages: bool
) -> result::Result<GuestMemoryMmap, GuardPageError> {
    map_guest_memory_guarded(ranges.iter().map(|r| (r.0, r.1, None)), track_dirty_pages)
}

/// Creates a container and allocates anonymous memory for guest memory regions.
/// Adds guard pages to every region.
///
/// # Arguments
///
/// * 'ranges' - Iterator over a sequence of (Address, Size, Option<FileOffset>)
///              tuples sorted by Address.
/// * 'track_dirty_pages' - Whether or not dirty page tracking is enabled.
///                         If set, it creates a dedicated bitmap for tracing memory writes
///                         specific to every region.
pub fn map_guest_memory_guarded<A, T>(
    ranges: T,
    track_dirty_pages: bool,
) -> result::Result<GuestMemoryMmap, GuardPageError>
where
    A: Borrow<(GuestAddress, usize, Option<FileOffset>)>,
    T: IntoIterator<Item = A>,
{
    let prot = libc::PROT_READ | libc::PROT_WRITE;
    let file_flags = libc::MAP_NORESERVE | libc::MAP_SHARED;
    let create_flags = libc::MAP_NORESERVE | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;

    GuestMemoryMmap::from_regions(
        ranges
            .into_iter()
            .map(|x| {
                let guest_base = x.borrow().0;
                let size = x.borrow().1;

                if let Some(ref f_off) = x.borrow().2 {
                    build_guarded(Some(f_off.clone()), size, prot, file_flags)
                } else {
                    build_guarded(None, size, prot, create_flags)
                }
                .and_then(|r| {
                    let mut mmap = GuestRegionMmap::new(r, guest_base)
                    .map_err(GuardPageError::MmapRegionError)?;
                    if track_dirty_pages {
                        mmap.enable_dirty_page_tracking();
                    }
                    Ok(mmap)
                })
            })
            .collect::<result::Result<Vec<_>, GuardPageError>>()?,
        )
        .map_err(GuardPageError::MmapRegionError)
}

/// Creates a guarded mapping based on the provided arguments.
/// Guard pages will be created at the beginning and the end of the range.
///
/// # Arguments
/// * `file_offset` - if provided, the method will create a file mapping at offset
///                   `file_offset.start` in the file referred to by `file_offset.file`.
/// * `size` - The size of the memory region in bytes.
/// * `prot` - The desired memory protection of the mapping.
/// * `flags` - This argument determines whether updates to the mapping are visible to other
///             processes mapping the same region, and whether updates are carried through to
///             the underlying file.
pub fn build_guarded(
    file_offset: Option<FileOffset>,
    size: usize,
    prot: i32,
    flags: i32,
) -> Result<MmapRegion, GuardPageError> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
    // Create the guarded range size (received size + 2 pages)
    let guarded_size = size + GUARD_NUMBER * page_size;

    // Map the guarded range to PROT_NONE
    let guard_addr = unsafe {
        libc::mmap(
            null_mut(),
            guarded_size,
            libc::PROT_NONE,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_NORESERVE,
            -1,
            0,
        )
    };

    if guard_addr == libc::MAP_FAILED {
        return Err(GuardPageError::Mmap(io::Error::last_os_error()));
    }

    let (fd, offset) = if let Some(ref f_off) = file_offset {
        check_file_offset(f_off, size)
            .map_err(MmapError::MmapRegion)
            .map_err(GuardPageError::MmapRegionError)?;
        (f_off.file().as_raw_fd(), f_off.start())
    } else {
        (-1, 0)
    };

    let map_addr = guard_addr as usize + page_size;

    // Inside the protected range, starting with guard_addr + PAGE_SIZE,
    // map the requested range with received protection and flags
    let addr = unsafe {
        libc::mmap(
            map_addr as *mut libc::c_void,
            size,
            prot,
            flags | libc::MAP_FIXED,
            fd,
            offset as libc::off_t,
        )
    };

    if addr == libc::MAP_FAILED {
        return Err(GuardPageError::Mmap(io::Error::last_os_error()));
    }

    Ok(unsafe {
        MmapRegion::build_raw(addr as *mut u8, size, prot, flags)
            .map_err(MmapError::MmapRegion)
            .map_err(GuardPageError::MmapRegionError)?
    })
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use vm_memory::FileOffset;
    use utils::tempfile::TempFile;
    use std::os::unix::io::AsRawFd;
    use vm_memory::GuestMemory;


    enum RegionOp {
        RegionRead,
        RegionWrite,
    }

    fn apply_operation_on_region(addr: *mut u8, op: RegionOp) {
        let pid = unsafe { libc::fork() };
        match pid {
            0 => {
                match op {
                    RegionOp::RegionRead => unsafe {
                        let _ = std::ptr::read(addr);
                    },
                    RegionOp::RegionWrite => unsafe {
                        std::ptr::write(addr, 0xFF);
                    },
                }
                unreachable!();
            }
            child_pid => {
                let mut child_status: i32 = -1;
                let pid_done = unsafe { libc::waitpid(child_pid, &mut child_status, 0) };
                assert_eq!(pid_done, child_pid);

                // Asserts that the child process terminated because
                // it received a signal that was not handled.
                assert!(libc::WIFSIGNALED(child_status));
                // Signal code should be a SIGSEGV (11)
                assert_eq!(libc::WTERMSIG(child_status), 11);
            }
        };
    }

    fn validate_guard_region(region: &MmapRegion) {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };

        // Check that the created range allows us to write inside it
        let addr = region.as_ptr();

        unsafe {
            std::ptr::write(addr, 0xFF);
            assert_eq!(std::ptr::read(addr), 0xFF);
        }

        // Try a read/write operation against the left guard border of the range
        let left_border = (addr as usize - page_size) as *mut u8;
        apply_operation_on_region(left_border, RegionOp::RegionWrite);
        apply_operation_on_region(left_border, RegionOp::RegionRead);

        // Try a read/write operation against the right guard border of the range
        let right_border = (addr as usize + region.size()) as *mut u8;
        apply_operation_on_region(right_border, RegionOp::RegionWrite);
        apply_operation_on_region(right_border, RegionOp::RegionRead);
    }

    #[test]
    fn test_create_guard_region() {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
        let size = page_size * 10;
        let prot = libc::PROT_READ | libc::PROT_WRITE;
        let flags = libc::MAP_ANONYMOUS | libc::MAP_NORESERVE | libc::MAP_PRIVATE;

        let region = build_guarded(None, size, prot, flags).unwrap();

        // Verify that the region was built correctly
        assert_eq!(region.size(), size);
        assert!(region.file_offset().is_none());
        assert_eq!(region.prot(), prot);
        assert_eq!(region.flags(), flags);

        validate_guard_region(&region);
    }

    #[test]
    fn test_create_guard_region_from_file() {
        let file = TempFile::new().unwrap().into_file();

        let prot = libc::PROT_READ | libc::PROT_WRITE;
        let flags = libc::MAP_NORESERVE | libc::MAP_PRIVATE;
        let offset = 0;
        let size = 10 * 4096;
        assert_eq!(unsafe { libc::ftruncate(file.as_raw_fd(), 4096 * 10) }, 0);

        //
        let region = build_guarded(
            Some(FileOffset::new(file, offset)),
            size,
            prot,
            flags,
        )
        .unwrap();

        // Verify that the region was built correctly
        assert_eq!(region.size(), size);
        // assert_eq!(region.file_offset().unwrap().start(), offset as u64);
        assert_eq!(region.prot(), prot);
        assert_eq!(region.flags(), flags);

        validate_guard_region(&region);
    }

    #[test]
    fn test_create_guest_memory_guarded(){
        let mem_size_mib = 128;
        let mem_size = mem_size_mib << 20;
        let arch_mem_regions = arch::arch_memory_regions(mem_size);

        let guest_memory = create_guest_memory_guarded(&arch_mem_regions, true).unwrap();
        guest_memory.with_regions(
            |_, region| -> Result<(), GuardPageError>{
                validate_guard_region(region);
                Ok(())
            }
        ).unwrap();
    }
}
