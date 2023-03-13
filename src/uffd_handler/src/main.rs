// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provides functionality for a userspace page fault handler
//! which loads the whole region from the backing memory file
//! when a page fault occurs.

mod common;
mod handler;
mod memory_region;

use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::net::UnixListener;
use std::{io, mem, process, ptr};

use userfaultfd::Uffd;

use crate::common::{parse_unix_stream, StreamError};
use crate::handler::{HandlerError, PageFaultHandler, UffdManager};
use crate::memory_region::{mem_regions_from_stream, MemRegionError};

const EXIT_CODE_ERROR: i32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to accept connection on userfaultfd socket: {0}")]
    AcceptConnection(io::Error),
    #[error("Failed to parse arguments: {0}")]
    ArgumentParsing(String),
    #[error("Failed to bind userfaultfd socket path: {0}")]
    BindSocket(io::Error),
    #[error("Memory mappings received through uffd socket might be corrupted: {0}")]
    CorruptedMemoryMappings(MemRegionError),
    #[error("Deserializing guest memory mappings failed: {0}")]
    DeserializeMemoryMappings(serde_json::Error),
    #[error("Snapshot memory file is empty.")]
    EmptySnapshotFile,
    #[error("Failed to get metadata of snapshot memory file: {0}")]
    Metadata(io::Error),
    #[error("Mmap failed: {0}")]
    Mmap(io::Error),
    #[error("Failed to open snapshot memory file: {0}")]
    Open(io::Error),
    #[error("Parsing data stream failed: {0}")]
    ParseStream(StreamError),
    #[error("Failed to obtain Firecracker's credentials.")]
    PeerCredentials,
    #[error("Failed to create userfaultfd handler: {0}")]
    UffdHandler(HandlerError),
}

type Result<T> = std::result::Result<T, Error>;

fn validate_snapshot_file(file_name: &str) -> Result<(File, usize)> {
    let file = File::open(file_name).map_err(Error::Open)?;
    let metadata = file.metadata().map_err(Error::Metadata)?;
    let size = metadata.len() as usize;
    if size == 0 {
        return Err(Error::EmptySnapshotFile);
    }

    Ok((file, size))
}

fn create_handler<U>() -> Result<PageFaultHandler<Uffd>>
where
    U: UffdManager,
{
    let uffd_sock_path = std::env::args()
        .nth(1)
        .ok_or_else(|| Error::ArgumentParsing(String::from("No socket path provided")))?;
    let mem_file_path = std::env::args()
        .nth(2)
        .ok_or_else(|| Error::ArgumentParsing(String::from("No memory file provided")))?;

    let (file, mem_file_size) = validate_snapshot_file(&mem_file_path)?;

    // mmap() a memory area used to bring in the faulting regions.
    // SAFETY: Safe because the parameters are valid.
    let memfile_buffer = unsafe {
        libc::mmap(
            ptr::null_mut(),
            mem_file_size,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            file.as_raw_fd(),
            0,
        )
    };
    if memfile_buffer == libc::MAP_FAILED {
        return Err(Error::Mmap(io::Error::last_os_error()));
    }

    // Get Uffd from UDS. We'll use the uffd to handle PFs for Firecracker.
    let listener = UnixListener::bind(uffd_sock_path).map_err(Error::BindSocket)?;
    let (stream, _) = listener.accept().map_err(Error::AcceptConnection)?;

    let (file, msg_body) = parse_unix_stream(&stream).map_err(Error::ParseStream)?;
    // SAFETY: Safe because it wraps the Uffd object around the valid raw file descriptor.
    let uffd = unsafe { Uffd::from_raw_fd(file.into_raw_fd()) };

    // Create guest memory regions from mappings received from Firecracker process.
    let mem_regions = mem_regions_from_stream(&msg_body, mem_file_size)?;

    // Get credentials of Firecracker process sent through the stream.
    let creds: libc::ucred = get_peer_process_credentials(stream.as_raw_fd())?;

    Ok(PageFaultHandler::new(
        mem_regions,
        memfile_buffer,
        uffd,
        u32::try_from(creds.pid).unwrap(),
    ))
}

fn get_peer_process_credentials(fd: RawFd) -> Result<libc::ucred> {
    let mut creds: libc::ucred = libc::ucred {
        pid: 0,
        gid: 0,
        uid: 0,
    };
    let mut creds_size = mem::size_of::<libc::ucred>() as u32;
    let creds_ref: *mut libc::ucred = &mut creds as *mut _;

    // Retrieve socket options in order to obtain credentials of peer process
    // (in our case, Firecracker's credentials).
    // SAFETY: Safe because all parameters are valid.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            creds_ref.cast::<libc::c_void>(),
            &mut creds_size as *mut libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(Error::PeerCredentials);
    }

    Ok(creds)
}

fn main() {
    let mut uffd_handler = create_handler::<Uffd>().unwrap_or_else(|err| {
        eprintln!("Creating userfaulfd handler failed: {:?}", err);
        process::exit(EXIT_CODE_ERROR);
    });

    uffd_handler.run().unwrap_or_else(|err| {
        eprintln!("Userfaultfd handler failed: {:?}", err);
        process::exit(EXIT_CODE_ERROR);
    });
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixStream;

    use utils::tempfile::TempFile;

    use super::get_peer_process_credentials;
    use crate::{validate_snapshot_file, Error};

    #[test]
    fn test_validate_snapshot_file_fail() {
        let res = validate_snapshot_file("foo");
        assert!(res.is_err());
        assert!(matches!(res.err().unwrap(), Error::Open(_)));

        let mem_file = TempFile::new().unwrap();
        let res = validate_snapshot_file(mem_file.as_path().to_str().unwrap());
        assert!(res.is_err());
        assert!(matches!(res.err().unwrap(), Error::EmptySnapshotFile));
    }

    #[test]
    fn test_validate_snapshot_file_successful() {
        let mem_file = TempFile::new().unwrap();
        let written = mem_file.as_file().write(b"hello world").unwrap();

        let (_, size) = validate_snapshot_file(mem_file.as_path().to_str().unwrap()).unwrap();
        assert_eq!(size, written);
    }

    #[test]
    fn test_get_peer_process_credentials_successful() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let sender_creds = get_peer_process_credentials(sender.as_raw_fd()).unwrap();
        let receiver_creds = get_peer_process_credentials(receiver.as_raw_fd()).unwrap();

        assert!(sender_creds.pid > 0);
        assert_eq!(sender_creds, receiver_creds);
    }
    #[test]
    fn test_get_peer_process_credentials_error() {
        let fd = TempFile::new().unwrap().as_file().as_raw_fd();
        // Getting credentials for regular file should fail.
        let res = get_peer_process_credentials(fd);
        assert!(res.is_err());
        assert_eq!(
            Error::PeerCredentials.to_string(),
            res.err().unwrap().to_string()
        );
    }
}
