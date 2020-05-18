// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate libc;
extern crate regex;

extern crate utils;

mod cgroup;
mod chroot;
mod env;

use std::ffi::{CString, NulError, OsString};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process;
use std::result;

use env::Env;
use utils::arg_parser::{ArgParser, Argument, Error as ParsingError};
use utils::validators;

const JAILER_VERSION: &str = env!("CARGO_PKG_VERSION");
#[derive(Debug)]
pub enum Error {
    ArgumentParsing(ParsingError),
    Canonicalize(PathBuf, io::Error),
    CgroupInheritFromParent(PathBuf, String),
    CgroupLineNotFound(String, String),
    CgroupLineNotUnique(String, String),
    ChangeFileOwner(PathBuf, io::Error),
    ChdirNewRoot(io::Error),
    Chmod(PathBuf, io::Error),
    CloseNetNsFd(io::Error),
    CloseDevNullFd(io::Error),
    Copy(PathBuf, PathBuf, io::Error),
    CreateDir(PathBuf, io::Error),
    CStringParsing(NulError),
    Dup2(io::Error),
    Exec(io::Error),
    FileName(PathBuf),
    FileOpen(PathBuf, io::Error),
    FromBytesWithNul(std::ffi::FromBytesWithNulError),
    GetOldFdFlags(io::Error),
    Gid(String),
    InvalidInstanceId(validators::Error),
    MissingParent(PathBuf),
    MkdirOldRoot(io::Error),
    MknodDev(io::Error, &'static str),
    MountBind(io::Error),
    MountPropagationSlave(io::Error),
    NotAFile(PathBuf),
    NotADirectory(PathBuf),
    NumaNode(String),
    OpenDevNull(io::Error),
    OsStringParsing(PathBuf, OsString),
    PivotRoot(io::Error),
    ReadLine(PathBuf, io::Error),
    ReadToString(PathBuf, io::Error),
    RegEx(regex::Error),
    RmOldRootDir(io::Error),
    SetCurrentDir(io::Error),
    SetNetNs(io::Error),
    SetSid(io::Error),
    Uid(String),
    UmountOldRoot(io::Error),
    UnexpectedListenerFd(i32),
    UnshareNewNs(io::Error),
    UnsetCloexec(io::Error),
    Write(PathBuf, io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match *self {
            ArgumentParsing(ref err) => write!(f, "Failed to parse arguments: {}", err),
            Canonicalize(ref path, ref io_err) => write!(
                f,
                "{}",
                format!("Failed to canonicalize path {:?}: {}", path, io_err).replace("\"", "")
            ),
            Chmod(ref path, ref err) => {
                write!(f, "Failed to change permissions on {:?}: {}", path, err)
            }
            CgroupInheritFromParent(ref path, ref filename) => write!(
                f,
                "{}",
                format!(
                    "Failed to inherit cgroups configurations from file {} in path {:?}",
                    filename, path
                )
                .replace("\"", "")
            ),
            CgroupLineNotFound(ref proc_mounts, ref controller) => write!(
                f,
                "{} configurations not found in {}",
                controller, proc_mounts
            ),
            CgroupLineNotUnique(ref proc_mounts, ref controller) => write!(
                f,
                "Found more than one cgroups configuration line in {} for {}",
                proc_mounts, controller
            ),
            ChangeFileOwner(ref path, ref err) => {
                write!(f, "Failed to change owner for {:?}: {}", path, err)
            }
            ChdirNewRoot(ref err) => write!(f, "Failed to chdir into chroot directory: {}", err),
            CloseNetNsFd(ref err) => write!(f, "Failed to close netns fd: {}", err),
            CloseDevNullFd(ref err) => write!(f, "Failed to close /dev/null fd: {}", err),
            Copy(ref file, ref path, ref err) => write!(
                f,
                "{}",
                format!("Failed to copy {:?} to {:?}: {}", file, path, err).replace("\"", "")
            ),
            CreateDir(ref path, ref err) => write!(
                f,
                "{}",
                format!("Failed to create directory {:?}: {}", path, err).replace("\"", "")
            ),
            CStringParsing(_) => write!(f, "Encountered interior \\0 while parsing a string"),
            Dup2(ref err) => write!(f, "Failed to duplicate fd: {}", err),
            Exec(ref err) => write!(f, "Failed to exec into Firecracker: {}", err),
            FileName(ref path) => write!(
                f,
                "{}",
                format!("Failed to extract filename from path {:?}", path).replace("\"", "")
            ),
            FileOpen(ref path, ref err) => write!(
                f,
                "{}",
                format!("Failed to open file {:?}: {}", path, err).replace("\"", "")
            ),
            FromBytesWithNul(ref err) => {
                write!(f, "Failed to decode string from byte array: {}", err)
            }
            GetOldFdFlags(ref err) => write!(f, "Failed to get flags from fd: {}", err),
            Gid(ref gid) => write!(f, "Invalid gid: {}", gid),
            InvalidInstanceId(ref err) => write!(f, "Invalid instance ID: {}", err),
            MissingParent(ref path) => write!(
                f,
                "{}",
                format!("File {:?} doesn't have a parent", path).replace("\"", "")
            ),
            MkdirOldRoot(ref err) => write!(
                f,
                "Failed to create the jail root directory before pivoting root: {}",
                err
            ),
            MknodDev(ref err, ref devname) => write!(
                f,
                "Failed to create {} via mknod inside the jail: {}",
                devname, err
            ),
            MountBind(ref err) => {
                write!(f, "Failed to bind mount the jail root directory: {}", err)
            }
            MountPropagationSlave(ref err) => {
                write!(f, "Failed to change the propagation type to slave: {}", err)
            }
            NotAFile(ref path) => write!(
                f,
                "{}",
                format!("{:?} is not a file", path).replace("\"", "")
            ),
            NotADirectory(ref path) => write!(
                f,
                "{}",
                format!("{:?} is not a directory", path).replace("\"", "")
            ),
            NumaNode(ref node) => write!(f, "Invalid numa node: {}", node),
            OpenDevNull(ref err) => write!(f, "Failed to open /dev/null: {}", err),
            OsStringParsing(ref path, _) => write!(
                f,
                "{}",
                format!("Failed to parse path {:?} into an OsString", path).replace("\"", "")
            ),
            PivotRoot(ref err) => write!(f, "Failed to pivot root: {}", err),
            ReadLine(ref path, ref err) => write!(
                f,
                "{}",
                format!("Failed to read line from {:?}: {}", path, err).replace("\"", "")
            ),
            ReadToString(ref path, ref err) => write!(
                f,
                "{}",
                format!("Failed to read file {:?} into a string: {}", path, err).replace("\"", "")
            ),
            RegEx(ref err) => write!(f, "Regex failed: {:?}", err),
            RmOldRootDir(ref err) => write!(f, "Failed to remove old jail root directory: {}", err),
            SetCurrentDir(ref err) => write!(f, "Failed to change current directory: {}", err),
            SetNetNs(ref err) => write!(f, "Failed to join network namespace: netns: {}", err),
            SetSid(ref err) => write!(f, "Failed to daemonize: setsid: {}", err),
            Uid(ref uid) => write!(f, "Invalid uid: {}", uid),
            UmountOldRoot(ref err) => write!(f, "Failed to unmount the old jail root: {}", err),
            UnexpectedListenerFd(fd) => {
                write!(f, "Unexpected value for the socket listener fd: {}", fd)
            }
            UnshareNewNs(ref err) => {
                write!(f, "Failed to unshare into new mount namespace: {}", err)
            }
            UnsetCloexec(ref err) => write!(
                f,
                "Failed to unset the O_CLOEXEC flag on the socket fd: {}",
                err
            ),
            Write(ref path, ref err) => write!(
                f,
                "{}",
                format!("Failed to write to {:?}: {}", path, err).replace("\"", "")
            ),
        }
    }
}

pub type Result<T> = result::Result<T, Error>;

/// Create an ArgParser object which contains info about the command line argument parser and populate
/// it with the expected arguments and their characteristics.
pub fn build_arg_parser() -> ArgParser<'static> {
    ArgParser::new()
        .arg(
            Argument::new("id")
                .required(true)
                .takes_value(true)
                .help("Jail ID."),
        )
        .arg(
            Argument::new("exec-file")
                .required(true)
                .takes_value(true)
                .help("File path to exec into."),
        )
        .arg(
            Argument::new("node")
                .required(true)
                .takes_value(true)
                .help("NUMA node to assign this microVM to."),
        )
        .arg(
            Argument::new("uid")
                .required(true)
                .takes_value(true)
                .help("The user identifier the jailer switches to after exec."),
        )
        .arg(
            Argument::new("gid")
                .required(true)
                .takes_value(true)
                .help("The group identifier the jailer switches to after exec."),
        )
        .arg(
            Argument::new("chroot-base-dir")
                .takes_value(true)
                .default_value("/srv/jailer")
                .help("The base folder where chroot jails are located."),
        )
        .arg(
            Argument::new("netns")
                .takes_value(true)
                .help("Path to the network namespace this microVM should join."),
        )
        .arg(Argument::new("daemonize").takes_value(false).help(
            "Daemonize the jailer before exec, by invoking setsid(), and redirecting \
             the standard I/O file descriptors to /dev/null.",
        ))
        .arg(
            Argument::new("extra-args")
                .takes_value(true)
                .help("Arguments that will be passed verbatim to the exec file."),
        )
}

fn sanitize_process() {
    // First thing to do is make sure we don't keep any inherited FDs
    // other that IN, OUT and ERR.
    if let Ok(paths) = fs::read_dir("/proc/self/fd") {
        for maybe_path in paths {
            if maybe_path.is_err() {
                continue;
            }

            let file_name = maybe_path.unwrap().file_name();
            let fd_str = file_name.to_str().unwrap_or("0");
            let fd = fd_str.parse::<i32>().unwrap_or(0);

            if fd > 2 {
                // Safe because close() cannot fail when passed a valid parameter.
                unsafe { libc::close(fd) };
            }
        }
    }
}

/// Turns an AsRef<Path> into a CString (c style string).
/// The expect should not fail, since Linux paths only contain valid Unicode chars (do they?),
/// and do not contain null bytes (do they?).
fn to_cstring<T: AsRef<Path>>(path: T) -> Result<CString> {
    let path_str = path
        .as_ref()
        .to_path_buf()
        .into_os_string()
        .into_string()
        .map_err(|e| Error::OsStringParsing(path.as_ref().to_path_buf(), e))?;
    CString::new(path_str).map_err(Error::CStringParsing)
}

fn main() {
    sanitize_process();

    let mut arg_parser = build_arg_parser();

    match arg_parser.parse_from_cmdline() {
        Err(err) => {
            println!(
                "Arguments parsing error: {} \n\n\
                 For more information try --help.",
                err
            );
            process::exit(1);
        }
        _ => {
            if let Some(help) = arg_parser.arguments().value_as_bool("help") {
                if help {
                    println!("Jailer v{}\n", JAILER_VERSION);
                    println!("{}", arg_parser.formatted_help());
                    process::exit(0);
                }
            }

            if let Some(version) = arg_parser.arguments().value_as_bool("version") {
                if version {
                    println!("Jailer v{}\n", JAILER_VERSION);
                    process::exit(0);
                }
            }
        }
    }

    Env::new(
        arg_parser.arguments(),
        utils::time::get_time(utils::time::ClockType::Monotonic) / 1000,
        utils::time::get_time(utils::time::ClockType::ProcessCpu) / 1000,
    )
    .and_then(|env| {
        fs::create_dir_all(env.chroot_dir())
            .map_err(|e| Error::CreateDir(env.chroot_dir().to_owned(), e))?;
        env.run()
    })
    .unwrap_or_else(|err| panic!("Jailer error: {}", err));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::os::unix::io::IntoRawFd;

    use utils::arg_parser;

    #[test]
    fn test_sanitize_process() {
        let n = 100;

        let tmp_dir_path = "/tmp/jailer/tests/sanitize_process";
        assert!(fs::create_dir_all(tmp_dir_path).is_ok());

        let mut fds = Vec::new();
        for i in 0..n {
            let maybe_file = File::create(format!("{}/{}", tmp_dir_path, i));
            assert!(maybe_file.is_ok());
            fds.push(maybe_file.unwrap().into_raw_fd());
        }

        sanitize_process();

        for fd in fds {
            let is_fd_opened = unsafe { libc::fcntl(fd, libc::F_GETFD) } == 0;
            assert_eq!(is_fd_opened, false);
        }

        assert!(fs::remove_dir_all(tmp_dir_path).is_ok());
    }

    #[allow(clippy::cognitive_complexity)]
    #[test]
    fn test_error_display() {
        use std::ffi::CStr;

        let path = PathBuf::from("/foo");
        let file_str = "/foo/bar";
        let file_path = PathBuf::from(file_str);
        let proc_mounts = "/proc/mounts";
        let controller = "sysfs";
        let id = "foobar";
        let err_args_parse = arg_parser::Error::UnexpectedArgument("foo".to_string());
        let err_regex = regex::Error::Syntax(id.to_string());
        let err2_str = "No such file or directory (os error 2)";

        assert_eq!(
            format!("{}", Error::ArgumentParsing(err_args_parse)),
            "Failed to parse arguments: Found argument 'foo' which wasn't expected, or isn't valid in this context."
        );
        assert_eq!(
            format!(
                "{}",
                Error::Canonicalize(path.clone(), io::Error::from_raw_os_error(2))
            ),
            format!("Failed to canonicalize path /foo: {}", err2_str)
        );
        assert_eq!(
            format!(
                "{}",
                Error::CgroupInheritFromParent(path.clone(), file_str.to_string())
            ),
            "Failed to inherit cgroups configurations from file /foo/bar in path /foo",
        );
        assert_eq!(
            format!(
                "{}",
                Error::CgroupLineNotFound(proc_mounts.to_string(), controller.to_string())
            ),
            "sysfs configurations not found in /proc/mounts",
        );
        assert_eq!(
            format!(
                "{}",
                Error::CgroupLineNotUnique(proc_mounts.to_string(), controller.to_string())
            ),
            "Found more than one cgroups configuration line in /proc/mounts for sysfs",
        );

        assert_eq!(
            format!(
                "{}",
                Error::ChangeFileOwner(
                    PathBuf::from("/dev/net/tun"),
                    io::Error::from_raw_os_error(42)
                )
            ),
            "Failed to change owner for \"/dev/net/tun\": No message of desired type (os error 42)",
        );
        assert_eq!(
            format!("{}", Error::ChdirNewRoot(io::Error::from_raw_os_error(42))),
            "Failed to chdir into chroot directory: No message of desired type (os error 42)"
        );
        assert_eq!(
            format!("{}", Error::CloseNetNsFd(io::Error::from_raw_os_error(42))),
            "Failed to close netns fd: No message of desired type (os error 42)",
        );
        assert_eq!(
            format!(
                "{}",
                Error::CloseDevNullFd(io::Error::from_raw_os_error(42))
            ),
            "Failed to close /dev/null fd: No message of desired type (os error 42)",
        );
        assert_eq!(
            format!(
                "{}",
                Error::Copy(
                    file_path.clone(),
                    path.clone(),
                    io::Error::from_raw_os_error(2)
                )
            ),
            format!("Failed to copy /foo/bar to /foo: {}", err2_str)
        );
        assert_eq!(
            format!(
                "{}",
                Error::CreateDir(path, io::Error::from_raw_os_error(2))
            ),
            format!("Failed to create directory /foo: {}", err2_str)
        );
        assert_eq!(
            format!(
                "{}",
                Error::CStringParsing(CString::new(b"f\0oo".to_vec()).unwrap_err())
            ),
            "Encountered interior \\0 while parsing a string",
        );
        assert_eq!(
            format!("{}", Error::Dup2(io::Error::from_raw_os_error(42))),
            "Failed to duplicate fd: No message of desired type (os error 42)",
        );
        assert_eq!(
            format!("{}", Error::Exec(io::Error::from_raw_os_error(2))),
            format!("Failed to exec into Firecracker: {}", err2_str)
        );
        assert_eq!(
            format!("{}", Error::FileName(file_path.clone())),
            "Failed to extract filename from path /foo/bar",
        );
        assert_eq!(
            format!(
                "{}",
                Error::FileOpen(file_path.clone(), io::Error::from_raw_os_error(2))
            ),
            format!("Failed to open file /foo/bar: {}", err2_str)
        );

        let err = CStr::from_bytes_with_nul(b"/dev").err().unwrap();
        assert_eq!(
            format!("{}", Error::FromBytesWithNul(err)),
            "Failed to decode string from byte array: data provided is not nul terminated",
        );
        assert_eq!(
            format!("{}", Error::GetOldFdFlags(io::Error::from_raw_os_error(42))),
            "Failed to get flags from fd: No message of desired type (os error 42)",
        );
        assert_eq!(
            format!("{}", Error::Gid(id.to_string())),
            "Invalid gid: foobar",
        );
        assert_eq!(
            format!(
                "{}",
                Error::InvalidInstanceId(validators::Error::InvalidChar('a', 1))
            ),
            "Invalid instance ID: invalid char (a) at position 1",
        );
        assert_eq!(
            format!("{}", Error::MissingParent(file_path.clone())),
            "File /foo/bar doesn't have a parent",
        );
        assert_eq!(
            format!("{}", Error::MkdirOldRoot(io::Error::from_raw_os_error(42))),
            "Failed to create the jail root directory before pivoting root: No message of desired \
             type (os error 42)",
        );
        assert_eq!(
            format!(
                "{}",
                Error::MknodDev(io::Error::from_raw_os_error(42), "/dev/net/tun")
            ),
            "Failed to create /dev/net/tun via mknod inside the jail: No message of desired type \
             (os error 42)",
        );
        assert_eq!(
            format!("{}", Error::MountBind(io::Error::from_raw_os_error(42))),
            "Failed to bind mount the jail root directory: No message of desired type (os error 42)",
        );
        assert_eq!(
            format!("{}", Error::MountPropagationSlave(io::Error::from_raw_os_error(42))),
            "Failed to change the propagation type to slave: No message of desired type (os error 42)",
        );
        assert_eq!(
            format!("{}", Error::NotAFile(file_path.clone())),
            "/foo/bar is not a file",
        );
        assert_eq!(
            format!("{}", Error::NotADirectory(file_path.clone())),
            "/foo/bar is not a directory",
        );
        assert_eq!(
            format!("{}", Error::NumaNode(id.to_string())),
            "Invalid numa node: foobar",
        );
        assert_eq!(
            format!("{}", Error::OpenDevNull(io::Error::from_raw_os_error(42))),
            "Failed to open /dev/null: No message of desired type (os error 42)",
        );
        assert_eq!(
            format!(
                "{}",
                Error::OsStringParsing(file_path.clone(), file_path.clone().into_os_string())
            ),
            "Failed to parse path /foo/bar into an OsString",
        );
        assert_eq!(
            format!("{}", Error::PivotRoot(io::Error::from_raw_os_error(42))),
            "Failed to pivot root: No message of desired type (os error 42)",
        );
        assert_eq!(
            format!(
                "{}",
                Error::ReadLine(file_path.clone(), io::Error::from_raw_os_error(2))
            ),
            format!("Failed to read line from /foo/bar: {}", err2_str)
        );
        assert_eq!(
            format!(
                "{}",
                Error::ReadToString(file_path.clone(), io::Error::from_raw_os_error(2))
            ),
            format!("Failed to read file /foo/bar into a string: {}", err2_str)
        );
        assert_eq!(
            format!("{}", Error::RegEx(err_regex.clone())),
            format!("Regex failed: {:?}", err_regex),
        );
        assert_eq!(
            format!("{}", Error::RmOldRootDir(io::Error::from_raw_os_error(42))),
            "Failed to remove old jail root directory: No message of desired type (os error 42)",
        );
        assert_eq!(
            format!("{}", Error::SetCurrentDir(io::Error::from_raw_os_error(2))),
            format!("Failed to change current directory: {}", err2_str),
        );
        assert_eq!(
            format!("{}", Error::SetNetNs(io::Error::from_raw_os_error(42))),
            "Failed to join network namespace: netns: No message of desired type (os error 42)",
        );
        assert_eq!(
            format!("{}", Error::SetSid(io::Error::from_raw_os_error(42))),
            "Failed to daemonize: setsid: No message of desired type (os error 42)",
        );
        assert_eq!(
            format!("{}", Error::Uid(id.to_string())),
            "Invalid uid: foobar",
        );
        assert_eq!(
            format!("{}", Error::UmountOldRoot(io::Error::from_raw_os_error(42))),
            "Failed to unmount the old jail root: No message of desired type (os error 42)",
        );
        assert_eq!(
            format!("{}", Error::UnexpectedListenerFd(42)),
            "Unexpected value for the socket listener fd: 42",
        );
        assert_eq!(
            format!("{}", Error::UnshareNewNs(io::Error::from_raw_os_error(42))),
            "Failed to unshare into new mount namespace: No message of desired type (os error 42)",
        );
        assert_eq!(
            format!("{}", Error::UnsetCloexec(io::Error::from_raw_os_error(42))),
            "Failed to unset the O_CLOEXEC flag on the socket fd: No message of desired type (os \
             error 42)",
        );
        assert_eq!(
            format!(
                "{}",
                Error::Write(file_path, io::Error::from_raw_os_error(2))
            ),
            format!("Failed to write to /foo/bar: {}", err2_str),
        );
    }
}
