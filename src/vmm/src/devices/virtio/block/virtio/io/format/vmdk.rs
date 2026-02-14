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
use imago::io_buffers::IoVectorMut;
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
    /// VMDK backend requires is_read_only=true.
    RequiresReadOnly,
    /// Guest memory error: {0}
    GuestMemory(GuestMemoryError),
    /// VMDK flush error: {0}
    Flush(io::Error),
}

#[derive(Debug)]
pub struct VmdkFileEngine {
    access: FormatAccess<ImagoFile>,
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
        // VMDK descriptors are untrusted input.  Extents are read-only, direct children of the
        // descriptor directory, and are opened relative to its held directory FD to prevent path
        // traversal, symlink traversal, and check-then-open races.
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
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: fd was returned by openat and ownership is transferred to std::fs::File.
        ImagoFile::try_from(unsafe { fs::File::from_raw_fd(fd) })
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
        })
    }

    pub fn disk_size(&self) -> u64 {
        self.access.size()
    }

    pub fn read(
        &self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> Result<u32, VmdkIoError> {
        let slice = mem
            .get_slice(addr, count as usize)
            .map_err(VmdkIoError::GuestMemory)?;
        let slices = [slice];
        let (bufv, _guard) = IoVectorMut::from_volatile_slice(&slices);
        self.access.readv(bufv, offset).map_err(VmdkIoError::Read)?;

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
mod tests {
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    use vmm_sys_util::tempdir::TempDir;

    use super::*;

    fn create_test_vmdk(extent: &str) -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let extent_file = dir.as_path().join("extent");
        let extent_size: u64 = 1024 * 1024;
        let mut file = fs::File::create(&extent_file).unwrap();
        file.set_len(extent_size).unwrap();

        let test_data = b"Hello VMDK from Firecracker!";
        file.write_all(test_data).unwrap();
        let extent_sectors = extent_size / 512;

        let descriptor_file = dir.as_path().join("descriptor.vmdk");
        let descriptor_content = format!(
            r#"# Disk DescriptorFile
version=1
CID=fffffffe
parentCID=ffffffff
createType="monolithicFlat"

# Extent description
RW {extent_sectors} FLAT "{extent}" 0

# The Disk Data Base
#DDB
"#
        );
        fs::write(&descriptor_file, descriptor_content).unwrap();

        (dir, descriptor_file)
    }

    #[test]
    fn test_vmdk_engine_open_and_read() {
        let (_dir, descriptor) = create_test_vmdk("extent");
        let engine = VmdkFileEngine::from_path(&descriptor).unwrap();

        assert_eq!(engine.disk_size(), 1024 * 1024);

        let mut buf = vec![0u8; 512];
        engine.access.read(&mut buf[..], 0).unwrap();
        assert_eq!(&buf[..28], b"Hello VMDK from Firecracker!");
    }

    #[test]
    fn test_vmdk_engine_rejects_unsafe_extents() {
        for extent in ["../secret", "/etc/passwd", "sub/extent"] {
            let (_dir, descriptor) = create_test_vmdk(extent);
            VmdkFileEngine::from_path(&descriptor).unwrap_err();
        }

        let (dir, descriptor) = create_test_vmdk("symlink");
        symlink(dir.as_path().join("extent"), dir.as_path().join("symlink")).unwrap();
        VmdkFileEngine::from_path(&descriptor).unwrap_err();
    }

    #[test]
    fn test_vmdk_gate_rejects_writable_extent() {
        let (dir, descriptor) = create_test_vmdk("extent");
        let mut gate = VmdkImplicitOpenGate::new(&descriptor).unwrap();
        let options = StorageOpenOptions::new()
            .filename(dir.as_path().join("extent"))
            .write(true);

        gate.open_storage(options).unwrap_err();
    }
}
