// Copyright (c) 2026 Tencent. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

use imago::FormatDriverBuilder;
use imago::file::File as ImagoFile;
use imago::format::access::FormatAccess;
use imago::format::gate::ImplicitOpenGate;
use imago::vmdk::Vmdk;
use imago::{Storage, StorageOpenOptions};
use vm_memory::{GuestMemoryBackend, GuestMemoryError};

use crate::vstate::memory::{GuestAddress, GuestMemoryMmap};

/// Errors specific to the VMDK IO engine.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VmdkIoError {
    /// Failed to open VMDK image: {0}
    Open(io::Error),
    /// VMDK backend does not support the async file engine.
    AsyncNotSupported,
    /// VMDK read error: {0}
    Read(io::Error),
    /// VMDK write not supported (read-only image)
    WriteNotSupported,
    /// The VMDK backend cannot be re-pointed at another file after being opened.
    UnsupportedOperation,
    /// VMDK backend requires is_read_only=true.
    RequiresReadOnly,
    /// Guest memory error: {0}
    GuestMemory(GuestMemoryError),
    /// VMDK flush error: {0}
    Flush(io::Error),
}

const READ_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Debug)]
pub struct VmdkFileEngine {
    access: FormatAccess<ImagoFile>,
    read_buffer: Box<[u8]>,
}

#[derive(Debug)]
struct VmdkImplicitOpenGate {
    descriptor_path: PathBuf,
    descriptor_dir: fs::File,
}

impl VmdkImplicitOpenGate {
    fn new(path: &Path) -> io::Result<Self> {
        let descriptor_path = fs::canonicalize(path)?;
        let descriptor_dir_path = descriptor_path
            .parent()
            .ok_or_else(|| io::Error::other("VMDK descriptor has no parent directory"))?;
        let descriptor_dir = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(descriptor_dir_path)?;

        Ok(Self {
            descriptor_path,
            descriptor_dir,
        })
    }

    fn open_extent(&self, path: &Path) -> io::Result<ImagoFile> {
        // Extents are opened read-only and restricted to direct children of the descriptor
        // directory. Opening relative to its held directory FD prevents path traversal,
        // symlink traversal, and check-then-open races.
        let relative = path
            .strip_prefix(
                self.descriptor_path
                    .parent()
                    .expect("canonical descriptor path has a parent"),
            )
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "VMDK extent is outside the descriptor directory",
                )
            })?;
        let mut components = relative.components();
        let Some(Component::Normal(filename)) = components.next() else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "VMDK extent must be a direct child of the descriptor directory",
            ));
        };
        if components.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "VMDK extent must be a direct child of the descriptor directory",
            ));
        }
        let filename = CString::new(filename.as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "VMDK extent filename contains a null byte",
            )
        })?;
        // SAFETY: descriptor_dir is an open directory FD and filename is a NUL-terminated component.
        let fd = unsafe {
            libc::openat(
                self.descriptor_dir.as_raw_fd(),
                filename.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: fd was returned by openat and ownership is transferred to std::fs::File.
        let file = unsafe { fs::File::from_raw_fd(fd) };
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VMDK extent must be a regular file",
            ));
        }

        // from_open_file (not TryFrom) skips fcntl(F_GETFL) / alignment probes.
        ImagoFile::from_open_file(
            file,
            StorageOpenOptions::new()
                .filename(path)
                .write(false)
                .direct(false),
        )
    }
}

impl ImplicitOpenGate<ImagoFile> for VmdkImplicitOpenGate {
    fn open_format<F: FormatDriverBuilder<ImagoFile>>(
        &mut self,
        _builder: F,
    ) -> io::Result<FormatAccess<ImagoFile>> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Opening implicit VMDK format dependencies is denied",
        ))
    }

    fn open_storage(&mut self, options: StorageOpenOptions) -> io::Result<ImagoFile> {
        if options.get_writable() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Opening writable VMDK dependencies is denied",
            ));
        }

        let path = options.get_filename().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "VMDK dependency is missing its filename",
            )
        })?;
        if path == self.descriptor_path {
            return ImagoFile::open(options);
        }

        self.open_extent(path)
    }
}

impl VmdkFileEngine {
    pub fn from_path(path: &Path) -> Result<Self, VmdkIoError> {
        let gate = VmdkImplicitOpenGate::new(path).map_err(VmdkIoError::Open)?;
        let vmdk = Vmdk::<ImagoFile>::builder_path(&gate.descriptor_path)
            .write(false)
            .open(gate)
            .map_err(VmdkIoError::Open)?;

        Ok(Self {
            access: FormatAccess::new(vmdk),
            read_buffer: vec![0; READ_BUFFER_SIZE].into_boxed_slice(),
        })
    }

    pub fn disk_size(&self) -> u64 {
        self.access.size()
    }

    pub fn read(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> Result<u32, VmdkIoError> {
        let slice = mem
            .get_slice(addr, count as usize)
            .map_err(VmdkIoError::GuestMemory)?;
        offset.checked_add(u64::from(count)).ok_or_else(|| {
            VmdkIoError::Read(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VMDK read offset overflow",
            ))
        })?;

        // Stage reads because imago does not report partial writes on error.
        for start in (0..slice.len()).step_by(READ_BUFFER_SIZE) {
            let len = (slice.len() - start).min(READ_BUFFER_SIZE);
            self.access
                .read(&mut self.read_buffer[..len], offset + start as u64)
                .map_err(VmdkIoError::Read)?;
            slice
                .subslice(start, len)
                .map_err(|err| VmdkIoError::GuestMemory(err.into()))?
                .copy_from(&self.read_buffer[..len]);
        }

        Ok(count)
    }

    pub fn write(
        &self,
        _offset: u64,
        _mem: &GuestMemoryMmap,
        _addr: GuestAddress,
        _count: u32,
    ) -> Result<u32, VmdkIoError> {
        Err(VmdkIoError::WriteNotSupported)
    }

    pub fn flush(&self) -> Result<(), VmdkIoError> {
        self.access.flush().map_err(VmdkIoError::Flush)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    use vmm_sys_util::tempdir::TempDir;

    use super::*;
    use crate::arch::host_page_size;
    use crate::devices::virtio::test_utils::default_mem;
    use crate::test_utils::single_region_mem_dirty_tracking;
    use crate::vstate::memory::{Bitmap, Bytes, GuestMemoryExtension};

    /// Creates a VMDK whose extent data starts `extent_offset_sectors` sectors into the
    /// extent file, which is zero-filled up to that point.
    pub(crate) fn create_test_vmdk(extent: &str, extent_offset_sectors: u64) -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let extent_file = dir.as_path().join("extent");
        let extent_size = 1024 * 1024usize;
        let data_offset = usize::try_from(extent_offset_sectors * 512).unwrap();

        let test_data = b"Hello VMDK from Firecracker!";
        let mut extent_data = vec![0u8; data_offset + extent_size];
        extent_data[data_offset..][..test_data.len()].copy_from_slice(test_data);
        fs::write(&extent_file, extent_data).unwrap();
        let extent_sectors = extent_size / 512;

        let descriptor_file = dir.as_path().join("descriptor.vmdk");
        let descriptor_content = format!(
            r#"# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType="monolithicFlat"

# Extent description
RW {extent_sectors} FLAT "{extent}" {extent_offset_sectors}

# The Disk Data Base
#DDB
"#
        );
        fs::write(&descriptor_file, descriptor_content).unwrap();

        (dir, descriptor_file)
    }

    /// Extent offsets are in 512-byte sectors, so `8` means byte 4096. Reading from the
    /// raw byte value would return the zero padding in front of the data.
    #[test]
    fn test_vmdk_engine_reads_at_sector_offset() {
        let (_dir, descriptor) = create_test_vmdk("extent", 8);
        let engine = VmdkFileEngine::from_path(&descriptor).unwrap();

        let mut buf = vec![0u8; 512];
        engine.access.read(&mut buf[..], 0).unwrap();
        assert_eq!(&buf[..28], b"Hello VMDK from Firecracker!");
    }

    #[test]
    fn test_vmdk_engine_open_and_read() {
        let (_dir, descriptor) = create_test_vmdk("extent", 0);
        let mut engine = VmdkFileEngine::from_path(&descriptor).unwrap();

        assert_eq!(engine.disk_size(), 1024 * 1024);

        let mem = default_mem();
        engine.read(0, &mem, GuestAddress(0), 512).unwrap();
        let mut buf = vec![0u8; 512];
        mem.read_slice(&mut buf, GuestAddress(0)).unwrap();
        assert_eq!(&buf[..28], b"Hello VMDK from Firecracker!");
        assert!(matches!(
            engine.write(0, &mem, GuestAddress(0), 512),
            Err(VmdkIoError::WriteNotSupported)
        ));
        engine.flush().unwrap();
    }

    fn assert_guest_write(mem: &GuestMemoryMmap, expected: &[u8], start: usize, len: usize) {
        let mut actual = vec![0; expected.len()];
        mem.read_slice(&mut actual, GuestAddress(0)).unwrap();
        assert_eq!(actual, expected);
        let slice = mem.get_slice(GuestAddress(0), expected.len()).unwrap();
        let page_size = host_page_size();
        for page in (0..expected.len()).step_by(page_size) {
            assert_eq!(
                slice.bitmap().dirty_at(page),
                len != 0 && page < start + len && page + page_size > start,
                "unexpected dirty state for page at {page}"
            );
        }
    }

    #[test]
    fn test_vmdk_read_dirty_tracking() {
        let (dir, descriptor) = create_test_vmdk("extent", 0);
        fs::write(dir.as_path().join("extent"), vec![0x5a; 1024 * 1024]).unwrap();
        let mut engine = VmdkFileEngine::from_path(&descriptor).unwrap();
        let start = host_page_size() - 17;
        let len = READ_BUFFER_SIZE + 513;
        let mem = single_region_mem_dirty_tracking(start + len + host_page_size());
        let mut expected = vec![0xa5; start + len + host_page_size()];
        mem.write_slice(&expected, GuestAddress(0)).unwrap();
        mem.reset_dirty();

        assert_eq!(
            engine
                .read(
                    0,
                    &mem,
                    GuestAddress(start as u64),
                    u32::try_from(len).unwrap()
                )
                .unwrap(),
            u32::try_from(len).unwrap()
        );
        expected[start..start + len].fill(0x5a);
        assert_guest_write(&mem, &expected, start, len);

        mem.reset_dirty();
        engine
            .read(
                engine.disk_size() - 512,
                &mem,
                GuestAddress(start as u64),
                1024,
            )
            .unwrap();
        expected[start + 512..start + 1024].fill(0);
        assert_guest_write(&mem, &expected, start, 1024);

        mem.reset_dirty();
        engine.read(0, &mem, GuestAddress(start as u64), 0).unwrap();
        assert_guest_write(&mem, &expected, 0, 0);
    }

    #[test]
    fn test_vmdk_zero_extent_dirty_tracking() {
        let (_dir, descriptor) = create_test_vmdk("extent", 0);
        let content = fs::read_to_string(&descriptor).unwrap();
        fs::write(&descriptor, content.replace("FLAT \"extent\" 0", "ZERO")).unwrap();
        let mut engine = VmdkFileEngine::from_path(&descriptor).unwrap();
        let len = READ_BUFFER_SIZE + 512;
        let mem = single_region_mem_dirty_tracking(len + host_page_size());
        let mut expected = vec![0xa5; len + host_page_size()];
        mem.write_slice(&expected, GuestAddress(0)).unwrap();
        mem.reset_dirty();

        engine
            .read(0, &mem, GuestAddress(0), u32::try_from(len).unwrap())
            .unwrap();
        expected[..len].fill(0);
        assert_guest_write(&mem, &expected, 0, len);
    }

    #[test]
    fn test_vmdk_read_error_dirty_tracking() {
        for readable in [0, 4096, READ_BUFFER_SIZE + 4096] {
            let (dir, descriptor) = create_test_vmdk("extent", 0);
            fs::write(dir.as_path().join("extent"), vec![0x5a; 1024 * 1024]).unwrap();
            let content = fs::read_to_string(&descriptor).unwrap();
            let extents = if readable == 0 {
                "NOACCESS 8 ZERO".to_string()
            } else {
                format!("RW {} FLAT \"extent\" 0\nNOACCESS 8 ZERO", readable / 512)
            };
            fs::write(
                &descriptor,
                content.replace("RW 2048 FLAT \"extent\" 0", &extents),
            )
            .unwrap();
            let mut engine = VmdkFileEngine::from_path(&descriptor).unwrap();
            let count = readable + 4096;
            let start = host_page_size() - 17;
            let mem_size = start + count + host_page_size();
            let mem = single_region_mem_dirty_tracking(mem_size);
            let mut expected = vec![0xa5; mem_size];
            mem.write_slice(&expected, GuestAddress(0)).unwrap();
            mem.reset_dirty();

            assert!(matches!(
                engine.read(
                    0,
                    &mem,
                    GuestAddress(start as u64),
                    u32::try_from(count).unwrap()
                ),
                Err(VmdkIoError::Read(_))
            ));
            let committed = readable / READ_BUFFER_SIZE * READ_BUFFER_SIZE;
            expected[start..start + committed].fill(0x5a);
            assert_guest_write(&mem, &expected, start, committed);
            if readable != 0 {
                assert!(engine.read_buffer[..4096].iter().all(|byte| *byte == 0x5a));
                mem.reset_dirty();
                engine.read(0, &mem, GuestAddress(0), 4096).unwrap();
                expected[..4096].fill(0x5a);
                assert_guest_write(&mem, &expected, 0, 4096);
            }
        }
    }

    #[test]
    fn test_vmdk_read_invalid_range() {
        let (_dir, descriptor) = create_test_vmdk("extent", 0);
        let mut engine = VmdkFileEngine::from_path(&descriptor).unwrap();
        let size = READ_BUFFER_SIZE + host_page_size();
        let mem = single_region_mem_dirty_tracking(size);
        let expected = vec![0xa5; size];
        mem.write_slice(&expected, GuestAddress(0)).unwrap();
        mem.reset_dirty();

        assert!(matches!(
            engine.read(0, &mem, GuestAddress(0), u32::try_from(size + 1).unwrap()),
            Err(VmdkIoError::GuestMemory(_))
        ));
        assert_guest_write(&mem, &expected, 0, 0);
        assert!(matches!(
            engine.read(u64::MAX, &mem, GuestAddress(0), 512),
            Err(VmdkIoError::Read(_))
        ));
        assert_guest_write(&mem, &expected, 0, 0);
    }

    #[test]
    fn test_vmdk_engine_rejects_unsafe_extents() {
        for extent in ["../secret", "/etc/passwd", "sub/extent"] {
            let (_dir, descriptor) = create_test_vmdk(extent, 0);
            VmdkFileEngine::from_path(&descriptor).unwrap_err();
        }

        let (dir, descriptor) = create_test_vmdk("symlink", 0);
        symlink(dir.as_path().join("extent"), dir.as_path().join("symlink")).unwrap();
        VmdkFileEngine::from_path(&descriptor).unwrap_err();
    }

    #[test]
    fn test_vmdk_gate_rejects_directory_extent() {
        let (dir, descriptor) = create_test_vmdk("directory", 0);
        let extent_path = dir.as_path().join("directory");
        fs::create_dir(&extent_path).unwrap();
        let gate = VmdkImplicitOpenGate::new(&descriptor).unwrap();
        assert_eq!(
            gate.open_extent(&extent_path).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(matches!(
            VmdkFileEngine::from_path(&descriptor),
            Err(VmdkIoError::Open(err)) if err.kind() == io::ErrorKind::InvalidInput
        ));
    }

    #[test]
    fn test_vmdk_gate_rejects_fifo_extent_without_blocking() {
        let (dir, descriptor) = create_test_vmdk("fifo", 0);
        let extent_path = dir.as_path().join("fifo");
        let filename = CString::new(extent_path.as_os_str().as_bytes()).unwrap();
        // SAFETY: filename is NUL-terminated and remains valid for the call.
        assert_eq!(unsafe { libc::mkfifo(filename.as_ptr(), 0o600) }, 0);

        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = VmdkFileEngine::from_path(&descriptor);
            sender
                .send(matches!(
                    result,
                    Err(VmdkIoError::Open(err)) if err.kind() == io::ErrorKind::InvalidInput
                ))
                .unwrap();
        });
        let result = receiver.recv_timeout(std::time::Duration::from_secs(5));
        let _peer = result.is_err().then(|| {
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&extent_path)
                .unwrap()
        });
        worker.join().unwrap();
        assert!(result.expect("opening a FIFO extent blocked without a writer"));
    }

    #[test]
    fn test_vmdk_gate_rejects_writable_extent() {
        let (dir, descriptor) = create_test_vmdk("extent", 0);
        let mut gate = VmdkImplicitOpenGate::new(&descriptor).unwrap();
        let options = StorageOpenOptions::new()
            .filename(dir.as_path().join("extent"))
            .write(true);

        gate.open_storage(options).unwrap_err();
    }
}
