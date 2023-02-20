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
use utils::arg_parser::{ArgParser, Argument, Arguments as ArgumentsBag, Error as ArgumentError};

use crate::common::{parse_unix_stream, StreamError};
use crate::handler::{HandlerError, PageFaultHandler, UffdManager};
use crate::memory_region::{mem_regions_from_stream, MemRegionError};

const EXIT_CODE_ERROR: i32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to accept connection on userfaultfd socket: {0}")]
    AcceptConnection(io::Error),
    #[error("Failed to parse arguments: {0}")]
    ArgumentParsing(ArgumentError),
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

#[derive(Debug, PartialEq)]
struct Arguments {
    /// The path to the UDS through which the UFFD handler communicates with Firecracker.
    socket: String,
    /// The path to the snapshot memory file to serve page faults from.
    mem_file: String,
}

fn get_argument_values(args: &ArgumentsBag) -> Result<Arguments> {
    let socket = args
        .single_value("socket")
        .ok_or_else(|| Error::ArgumentParsing(ArgumentError::MissingValue("socket".to_string())))?;
    let mem_file = args.single_value("mem-file").ok_or_else(|| {
        Error::ArgumentParsing(ArgumentError::MissingValue("mem-file".to_string()))
    })?;

    Ok(Arguments {
        socket: socket.to_owned(),
        mem_file: mem_file.to_owned(),
    })
}

/// Create an ArgParser object which contains info about the command line argument parser and
/// populate it with the expected arguments and their characteristics.
fn build_arg_parser() -> ArgParser<'static> {
    ArgParser::new()
        .arg(
            Argument::new("socket")
                .required(true)
                .takes_value(true)
                .help(
                    "The path to the UDS through which the UFFD handler communicates with \
                     Firecracker.",
                ),
        )
        .arg(
            Argument::new("mem-file")
                .required(true)
                .takes_value(true)
                .help("The path to the snapshot memory file to serve page faults from."),
        )
}

fn create_handler<U>(args: &Arguments) -> Result<PageFaultHandler<Uffd>>
where
    U: UffdManager,
{
    let (file, mem_file_size) = validate_snapshot_file(&args.mem_file)?;

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
    let listener = UnixListener::bind(&args.socket).map_err(Error::BindSocket)?;
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
    let mut arg_parser = build_arg_parser();
    match arg_parser.parse_from_cmdline() {
        Err(err) => {
            eprintln!(
                "Arguments parsing error: {:?} \n\nFor more information try --help.",
                err
            );
            process::exit(EXIT_CODE_ERROR);
        }
        _ => {
            if arg_parser.arguments().flag_present("help") {
                println!("{}\n", arg_parser.formatted_help());
                process::exit(0);
            }
        }
    }

    let args = get_argument_values(arg_parser.arguments()).unwrap_or_else(|err| {
        eprintln!("{:?}", err);
        process::exit(EXIT_CODE_ERROR);
    });

    let mut uffd_handler = create_handler::<Uffd>(&args).unwrap_or_else(|err| {
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
    use crate::{
        build_arg_parser, get_argument_values, validate_snapshot_file, ArgumentError, Arguments,
        Error,
    };

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
    fn test_get_argument_values_successful() {
        let socket = "uffd.sock";
        let mem_file = "vm.mem";

        let arg_parser = build_arg_parser();
        let arguments = &mut arg_parser.arguments().clone();
        arguments
            .parse(
                vec!["uffd-handler", "--socket", socket, "--mem-file", mem_file]
                    .into_iter()
                    .map(String::from)
                    .collect::<Vec<String>>()
                    .as_ref(),
            )
            .unwrap();

        assert_eq!(
            get_argument_values(arguments).unwrap(),
            Arguments {
                socket: socket.to_string(),
                mem_file: mem_file.to_string()
            }
        );
    }

    #[test]
    fn test_get_argument_values_no_args() {
        let arg_parser = build_arg_parser();
        let arguments = &mut arg_parser.arguments().clone();
        let res = arguments.parse(vec![String::from("uffd-handler")].as_slice());

        assert!(res.is_err());
        assert_eq!(
            res.err().unwrap(),
            ArgumentError::MissingArgument(String::from("mem-file"))
        );
    }

    #[test]
    fn test_get_argument_values_no_mem_value() {
        let arg_parser = build_arg_parser();
        let arguments = &mut arg_parser.arguments().clone();
        let res = arguments
            .parse(vec![String::from("uffd-handler"), String::from("--mem-file")].as_slice());

        assert!(res.is_err());
        assert_eq!(
            res.err().unwrap(),
            ArgumentError::MissingValue(String::from("mem-file"))
        );
    }

    #[test]
    fn test_get_argument_values_no_socket() {
        let arg_parser = build_arg_parser();
        let arguments = &mut arg_parser.arguments().clone();
        let res = arguments.parse(
            vec!["uffd-handler", "--mem-file", "vm.mem"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<String>>()
                .as_ref(),
        );

        assert!(res.is_err());
        assert_eq!(
            res.err().unwrap(),
            ArgumentError::MissingArgument(String::from("socket"))
        );
    }

    #[test]
    fn test_get_argument_values_no_socket_value() {
        let arg_parser = build_arg_parser();
        let arguments = &mut arg_parser.arguments().clone();
        let res = arguments.parse(
            vec!["uffd-handler", "--mem-file", "vm.mem", "--socket"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<String>>()
                .as_ref(),
        );

        assert!(res.is_err());
        assert_eq!(
            res.err().unwrap(),
            ArgumentError::MissingValue(String::from("socket"))
        );
    }

    #[test]
    fn test_get_argument_values_unexpected_argument() {
        let arg_parser = build_arg_parser();
        let arguments = &mut arg_parser.arguments().clone();
        let res = arguments.parse(
            vec!["uffd-handler", "--foo", "vm.mem", "--socket"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<String>>()
                .as_ref(),
        );

        assert!(res.is_err());
        assert_eq!(
            res.err().unwrap(),
            ArgumentError::UnexpectedArgument(String::from("foo"))
        );
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
