// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provides functionality for a userspace page fault handler
//! which loads the whole region from the backing memory file
//! when a page fault occurs.

mod common;
mod handler;
mod memory_region;

use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::{io, mem, process, ptr};

use userfaultfd::Uffd;

use crate::common::{parse_unix_stream, StreamError};
use crate::handler::{HandlerError, PageFaultHandler, UffdManager};
use crate::memory_region::{create_mem_regions, deserialize_mappings, MemPageState};

const EXIT_CODE_ERROR: i32 = 1;
/// Timeout for poll()ing on the userfaultfd for events.
/// A negative value translates to an infinite timeout. Page faults are not meant to
/// appear at a constant frequency, so depending on the guest workload, there can be
/// situations when we need to wait longer for events.
const POLL_TIMEOUT: i32 = -1;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to accept connection on userfaultfd socket: {0}")]
    AcceptConnection(io::Error),
    #[error("Failed to parse arguments: {0}")]
    ArgumentParsing(String),
    #[error("Failed to bind userfaultfd socket path: {0}")]
    BindSocket(io::Error),
    #[error(
        "Size of snapshot memory file differs from the size of memory mappings.  Mappings \
         received through uffd socket might be corrupted."
    )]
    CorruptedMemoryMappings,
    #[error("Deserializing guest memory mappings failed: {0}")]
    DeserializeMemoryMappings(serde_json::Error),
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

    let file = File::open(mem_file_path).map_err(Error::Open)?;
    let metadata = file.metadata().map_err(Error::Metadata)?;
    let size = metadata.len() as usize;

    // mmap() a memory area used to bring in the faulting regions.
    // SAFETY: Safe because the parameters are valid.
    let memfile_buffer = unsafe {
        libc::mmap(
            ptr::null_mut(),
            size,
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
    let mappings = deserialize_mappings(&msg_body, size)?;
    let mem_regions = create_mem_regions(mappings);

    // Get credentials of Firecracker process sent through the stream.
    let creds: libc::ucred = get_peer_process_credentials(stream)?;

    Ok(PageFaultHandler::new(
        mem_regions,
        memfile_buffer,
        uffd,
        creds.pid as u32,
    ))
}

fn get_peer_process_credentials(stream: UnixStream) -> Result<libc::ucred> {
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
            stream.as_raw_fd(),
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

    let mut pollfd = libc::pollfd {
        fd: uffd_handler.uffd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };

    // Loop, handling incoming events on the userfaultfd file descriptor.
    loop {
        // SAFETY: Safe because fd, nfds and timeout are valid parameters.
        let nready = unsafe { libc::poll(&mut pollfd, 1, POLL_TIMEOUT) };
        // Poll has an infinite timeout, therefore in theory, this case should never happen.
        if nready == -1 {
            unreachable!();
        }

        // Read an event from the userfaultfd.
        let event = uffd_handler.uffd.poll_fd().unwrap_or_else(|err| {
            eprintln!("Reading event from userfaultfd failed: {:?}", err);
            process::exit(EXIT_CODE_ERROR);
        });

        // We expect to receive either a Page Fault or Removed
        // event (if the balloon device is enabled).
        match event {
            userfaultfd::Event::Pagefault { addr, .. } => {
                uffd_handler.serve_pf(addr as usize).unwrap_or_else(|err| {
                    eprintln!("Processing page fault failed: {:?}", err);
                    process::exit(EXIT_CODE_ERROR);
                })
            }
            userfaultfd::Event::Remove { start, end } => uffd_handler.update_mem_state_mappings(
                start as usize,
                end as usize,
                MemPageState::Removed,
            ),
            _ => {
                eprintln!("Unexpected event received on userfaultfd.");
                process::exit(EXIT_CODE_ERROR);
            }
        }
    }
}
