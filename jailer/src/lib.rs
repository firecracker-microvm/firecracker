// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[macro_use(crate_version, crate_authors)]
extern crate clap;
extern crate libc;
extern crate regex;

extern crate fc_util;
extern crate sys_util;

mod cgroup;
mod chroot;
mod env;

use std::ffi::{CString, NulError, OsString};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::result;

use clap::{App, Arg, ArgMatches};

use env::Env;
use fc_util::validators;

const SOCKET_FILE_NAME: &str = "api.socket";

#[derive(Debug)]
pub enum Error {
    Canonicalize(PathBuf, io::Error),
    CgroupInheritFromParent(PathBuf, String),
    CgroupLineNotFound(String, String),
    CgroupLineNotUnique(String, String),
    ChangeFileOwner(sys_util::Error, &'static str),
    ChdirNewRoot(sys_util::Error),
    CloseNetNsFd(sys_util::Error),
    CloseDevNullFd(sys_util::Error),
    Copy(PathBuf, PathBuf, io::Error),
    CreateDir(PathBuf, io::Error),
    CStringParsing(NulError),
    Dup2(sys_util::Error),
    Exec(io::Error),
    FileName(PathBuf),
    FileOpen(PathBuf, io::Error),
    FromBytesWithNul(&'static [u8]),
    GetOldFdFlags(sys_util::Error),
    Gid(String),
    InvalidInstanceId(validators::Error),
    MissingArgument(&'static str),
    MissingParent(PathBuf),
    MkdirOldRoot(sys_util::Error),
    MknodDev(sys_util::Error, &'static str),
    MountBind(sys_util::Error),
    MountPropagationPrivate(sys_util::Error),
    NotAFile(PathBuf),
    NumaNode(String),
    OpenDevNull(sys_util::Error),
    OsStringParsing(PathBuf, OsString),
    PivotRoot(sys_util::Error),
    ReadLine(PathBuf, io::Error),
    ReadToString(PathBuf, io::Error),
    RegEx(regex::Error),
    RmOldRootDir(sys_util::Error),
    SeccompLevel(std::num::ParseIntError),
    SetCurrentDir(io::Error),
    SetNetNs(sys_util::Error),
    SetSid(sys_util::Error),
    Uid(String),
    UmountOldRoot(sys_util::Error),
    UnexpectedListenerFd(i32),
    UnshareNewNs(sys_util::Error),
    UnsetCloexec(sys_util::Error),
    Write(PathBuf, io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match *self {
            Canonicalize(ref path, ref io_err) => write!(
                f,
                "{}",
                format!("Failed to canonicalize path {:?}: {}", path, io_err).replace("\"", "")
            ),
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
            ChangeFileOwner(ref err, ref filename) => {
                write!(f, "Failed to change owner for {}: {}", filename, err)
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
            FromBytesWithNul(ref bytes) => {
                write!(f, "Failed to decode string from byte array: {:?}", bytes)
            }
            GetOldFdFlags(ref err) => write!(f, "Failed to get flags from fd: {}", err),
            Gid(ref gid) => write!(f, "Invalid gid: {}", gid),
            InvalidInstanceId(ref err) => write!(f, "Invalid instance ID: {}", err),
            MissingArgument(ref arg) => write!(f, "Missing argument: {}", arg),
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
            MountPropagationPrivate(ref err) => write!(
                f,
                "Failed to change the propagation type to private: {}",
                err
            ),
            NotAFile(ref path) => write!(
                f,
                "{}",
                format!("{:?} is not a file", path).replace("\"", "")
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
            SeccompLevel(ref err) => write!(f, "Failed to parse seccomp level: {:?}", err),
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

pub fn clap_app<'a, 'b>() -> App<'a, 'b> {
    // Initially, the uid and gid params had default values, but it turns out that it's quite
    // easy to shoot yourself in the foot by not setting proper permissions when preparing the
    // contents of the jail, so I think their values should be provided explicitly.
    App::new("jailer")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Jail a microVM.")
        .arg(
            Arg::with_name("id")
                .long("id")
                .help("Jail ID")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("exec_file")
                .long("exec-file")
                .help("File path to exec into.")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("numa_node")
                .long("node")
                .help("NUMA node to assign this microVM to.")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("uid")
                .long("uid")
                .help("The user identifier the jailer switches to after exec.")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("gid")
                .long("gid")
                .help("The group identifier the jailer switches to after exec.")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("chroot_base")
                .long("chroot-base-dir")
                .help("The base folder where chroot jails are located.")
                .required(false)
                .default_value("/srv/jailer")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("netns")
                .long("netns")
                .help("Path to the network namespace this microVM should join.")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("daemonize")
                .long("daemonize")
                .help("Daemonize the jailer before exec, by invoking setsid(), and redirecting the standard I/O file descriptors to /dev/null.")
                .required(false)
                .takes_value(false),
        )
        .arg(
            Arg::with_name("seccomp-level")
                .long("seccomp-level")
                .help("Level of seccomp filtering that will be passed to executed path as argument.\n
    - Level 0: No filtering.\n
    - Level 1: Seccomp filtering by syscall number.\n
    - Level 2: Seccomp filtering by syscall number and argument values.\n
")
                .required(false)
                .takes_value(true)
                .default_value("2")
                .possible_values(&["0", "1", "2"]),
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

pub fn run(args: ArgMatches, start_time_us: u64, start_time_cpu_us: u64) -> Result<()> {
    // We open /dev/kvm and create the listening socket. These file descriptors will be
    // passed on to Firecracker post exec, and used via knowing their values in advance.

    // TODO: can a malicious guest that takes over firecracker use its access to the KVM fd to
    // starve the host of resources? (cgroups should take care of that, but do they currently?)

    sanitize_process();

    let env = Env::new(args, start_time_us, start_time_cpu_us)?;

    // Ensure the folder exists.
    fs::create_dir_all(env.chroot_dir())
        .map_err(|e| Error::CreateDir(env.chroot_dir().to_owned(), e))?;

    env.run(SOCKET_FILE_NAME)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::os::unix::io::AsRawFd;

    #[test]
    fn test_sanitize_process() {
        let n = 100;

        let tmp_dir_path = "/tmp/jailer/tests/sanitize_process";
        assert!(fs::create_dir_all(tmp_dir_path).is_ok());

        let mut fds = Vec::new();
        for i in 0..n {
            let maybe_file = File::create(format!("{}/{}", tmp_dir_path, i));
            assert!(maybe_file.is_ok());
            fds.push(maybe_file.unwrap().as_raw_fd());
        }

        sanitize_process();

        for fd in fds {
            let is_fd_opened = unsafe { libc::fcntl(fd, libc::F_GETFD) } == 0;
            assert_eq!(is_fd_opened, false);
        }

        assert!(fs::remove_dir_all(tmp_dir_path).is_ok());
    }

    #[allow(clippy::cyclomatic_complexity)]
    #[test]
    fn test_error_display() {
        let path = PathBuf::from("/foo");
        let file_str = "/foo/bar";
        let file_path = PathBuf::from(file_str);
        let proc_mounts = "/proc/mounts";
        let controller = "sysfs";
        let id = "foobar";
        let err42 = sys_util::Error::new(42);
        let err_regex = regex::Error::Syntax(id.to_string());
        let err_parse = i8::from_str_radix("129", 10).unwrap_err();
        let err2_str = "No such file or directory (os error 2)";

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
            format!("{}", Error::ChangeFileOwner(err42, "/dev/net/tun")),
            "Failed to change owner for /dev/net/tun: Errno 42",
        );
        assert_eq!(
            format!("{}", Error::ChdirNewRoot(err42)),
            "Failed to chdir into chroot directory: Errno 42"
        );
        assert_eq!(
            format!("{}", Error::CloseNetNsFd(err42)),
            "Failed to close netns fd: Errno 42",
        );
        assert_eq!(
            format!("{}", Error::CloseDevNullFd(err42)),
            "Failed to close /dev/null fd: Errno 42",
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
                Error::CreateDir(path.clone(), io::Error::from_raw_os_error(2))
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
            format!("{}", Error::Dup2(err42)),
            "Failed to duplicate fd: Errno 42",
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
        assert_eq!(
            format!("{}", Error::FromBytesWithNul(b"/\0")),
            "Failed to decode string from byte array: [47, 0]",
        );
        assert_eq!(
            format!("{}", Error::GetOldFdFlags(err42)),
            "Failed to get flags from fd: Errno 42",
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
            format!("{}", Error::MissingArgument(id)),
            "Missing argument: foobar",
        );
        assert_eq!(
            format!("{}", Error::MissingParent(file_path.clone())),
            "File /foo/bar doesn't have a parent",
        );
        assert_eq!(
            format!("{}", Error::MkdirOldRoot(err42)),
            "Failed to create the jail root directory before pivoting root: Errno 42",
        );
        assert_eq!(
            format!("{}", Error::MknodDev(err42, "/dev/net/tun")),
            "Failed to create /dev/net/tun via mknod inside the jail: Errno 42",
        );
        assert_eq!(
            format!("{}", Error::MountBind(err42)),
            "Failed to bind mount the jail root directory: Errno 42",
        );
        assert_eq!(
            format!("{}", Error::MountPropagationPrivate(err42)),
            "Failed to change the propagation type to private: Errno 42",
        );
        assert_eq!(
            format!("{}", Error::NotAFile(file_path.clone())),
            "/foo/bar is not a file",
        );
        assert_eq!(
            format!("{}", Error::NumaNode(id.to_string())),
            "Invalid numa node: foobar",
        );
        assert_eq!(
            format!("{}", Error::OpenDevNull(err42)),
            "Failed to open /dev/null: Errno 42",
        );
        assert_eq!(
            format!(
                "{}",
                Error::OsStringParsing(file_path.clone(), file_path.clone().into_os_string())
            ),
            "Failed to parse path /foo/bar into an OsString",
        );
        assert_eq!(
            format!("{}", Error::PivotRoot(err42)),
            "Failed to pivot root: Errno 42",
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
            format!("{}", Error::RmOldRootDir(err42)),
            "Failed to remove old jail root directory: Errno 42",
        );
        assert_eq!(
            format!("{}", Error::SeccompLevel(err_parse.clone())),
            "Failed to parse seccomp level: ParseIntError { kind: Overflow }",
        );
        assert_eq!(
            format!("{}", Error::SetCurrentDir(io::Error::from_raw_os_error(2))),
            format!("Failed to change current directory: {}", err2_str),
        );
        assert_eq!(
            format!("{}", Error::SetNetNs(err42)),
            "Failed to join network namespace: netns: Errno 42",
        );
        assert_eq!(
            format!("{}", Error::SetSid(err42)),
            "Failed to daemonize: setsid: Errno 42",
        );
        assert_eq!(
            format!("{}", Error::Uid(id.to_string())),
            "Invalid uid: foobar",
        );
        assert_eq!(
            format!("{}", Error::UmountOldRoot(err42)),
            "Failed to unmount the old jail root: Errno 42",
        );
        assert_eq!(
            format!("{}", Error::UnexpectedListenerFd(42)),
            "Unexpected value for the socket listener fd: 42",
        );
        assert_eq!(
            format!("{}", Error::UnshareNewNs(err42)),
            "Failed to unshare into new mount namespace: Errno 42",
        );
        assert_eq!(
            format!("{}", Error::UnsetCloexec(err42)),
            "Failed to unset the O_CLOEXEC flag on the socket fd: Errno 42",
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
