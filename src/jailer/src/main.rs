// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod cgroup;
mod chroot;
mod env;
mod resource_limits;
use std::ffi::{CString, NulError, OsString};
use std::fmt::{Debug, Display};
use std::os::unix::prelude::AsRawFd;
use std::path::{Path, PathBuf};
use std::{env as p_env, fs, io, process, result};

use utils::arg_parser::{ArgParser, Argument, Error as ParsingError};
use utils::syscall::SyscallReturnCode;
use utils::validators;

use crate::env::Env;

const JAILER_VERSION: &str = env!("FIRECRACKER_VERSION");

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to parse arguments: {0}")]
    ArgumentParsing(ParsingError),
    #[error("{}", format!("Failed to canonicalize path {:?}: {}", .0, .1).replace('\"', ""))]
    Canonicalize(PathBuf, io::Error),
    #[error("{}", format!("Failed to inherit cgroups configurations from file {} in path {:?}", .1, .0).replace('\"', ""))]
    CgroupInheritFromParent(PathBuf, String),
    #[error("{1} configurations not found in {0}")]
    CgroupLineNotFound(String, String),
    #[error("Cgroup invalid file: {0}")]
    CgroupInvalidFile(String),
    #[error("Expected value {0} for {2}. Current value: {1}")]
    CgroupWrite(String, String, String),
    #[error("Invalid format for cgroups: {0}")]
    CgroupFormat(String),
    #[error("Hierarchy not found: {0}")]
    CgroupHierarchyMissing(String),
    #[error("Controller {0} is unavailable")]
    CgroupControllerUnavailable(String),
    #[error("{0} is an invalid cgroup version specifier")]
    CgroupInvalidVersion(String),
    #[error("Parent cgroup path is invalid. Path should not be absolute or contain '..' or '.'")]
    CgroupInvalidParentPath(),
    #[error("Failed to change owner for {0:?}: {1}")]
    ChangeFileOwner(PathBuf, io::Error),
    #[error("Failed to chdir into chroot directory: {0}")]
    ChdirNewRoot(io::Error),
    #[error("Failed to change permissions on {0:?}: {1}")]
    Chmod(PathBuf, io::Error),
    #[error("Failed cloning into a new child process: {0}")]
    Clone(io::Error),
    #[error("Failed to close netns fd: {0}")]
    CloseNetNsFd(io::Error),
    #[error("Failed to close /dev/null fd: {0}")]
    CloseDevNullFd(io::Error),
    #[error("Failed to call close range syscall: {0}")]
    CloseRange(io::Error),
    #[error("{}", format!("Failed to copy {:?} to {:?}: {}", .0, .1, .2).replace('\"', ""))]
    Copy(PathBuf, PathBuf, io::Error),
    #[error("{}", format!("Failed to create directory {:?}: {}", .0, .1).replace('\"', ""))]
    CreateDir(PathBuf, io::Error),
    #[error("Encountered interior \\0 while parsing a string")]
    CStringParsing(NulError),
    #[error("Failed to open directory {0}: {1}")]
    DirOpen(String, String),
    #[error("Failed to duplicate fd: {0}")]
    Dup2(io::Error),
    #[error("Failed to exec into Firecracker: {0}")]
    Exec(io::Error),
    #[error(
        "Invalid filename. The filename of `--exec-file` option must contain \"firecracker\": {0}"
    )]
    ExecFileName(String),
    #[error("{}", format!("Failed to extract filename from path {:?}", .0).replace('\"', ""))]
    ExtractFileName(PathBuf),
    #[error("{}", format!("Failed to open file {:?}: {}", .0, .1).replace('\"', ""))]
    FileOpen(PathBuf, io::Error),
    #[error("Failed to decode string from byte array: {0}")]
    FromBytesWithNul(std::ffi::FromBytesWithNulError),
    #[error("Failed to get flags from fd: {0}")]
    GetOldFdFlags(io::Error),
    #[error("Invalid gid: {0}")]
    Gid(String),
    #[error("Invalid instance ID: {0}")]
    InvalidInstanceId(validators::Error),
    #[error("{}", format!("File {:?} doesn't have a parent", .0).replace('\"', ""))]
    MissingParent(PathBuf),
    #[error("Failed to create the jail root directory before pivoting root: {0}")]
    MkdirOldRoot(io::Error),
    #[error("Failed to create {1} via mknod inside the jail: {0}")]
    MknodDev(io::Error, &'static str),
    #[error("Failed to bind mount the jail root directory: {0}")]
    MountBind(io::Error),
    #[error("Failed to change the propagation type to slave: {0}")]
    MountPropagationSlave(io::Error),
    #[error("{}", format!("{:?} is not a file", .0).replace('\"', ""))]
    NotAFile(PathBuf),
    #[error("{}", format!("{:?} is not a directory", .0).replace('\"', ""))]
    NotADirectory(PathBuf),
    #[error("Failed to open /dev/null: {0}")]
    OpenDevNull(io::Error),
    #[error("{}", format!("Failed to parse path {:?} into an OsString", .0).replace('\"', ""))]
    OsStringParsing(PathBuf, OsString),
    #[error("Failed to pivot root: {0}")]
    PivotRoot(io::Error),
    #[error("{}", format!("Failed to read line from {:?}: {}", .0, .1).replace('\"', ""))]
    ReadLine(PathBuf, io::Error),
    #[error("{}", format!("Failed to read file {:?} into a string: {}", .0, .1).replace('\"', ""))]
    ReadToString(PathBuf, io::Error),
    #[error("Regex failed: {0:?}")]
    RegEx(regex::Error),
    #[error("Invalid resource argument: {0}")]
    ResLimitArgument(String),
    #[error("Invalid format for resources limits: {0}")]
    ResLimitFormat(String),
    #[error("Invalid limit value for resource: {0}: {1}")]
    ResLimitValue(String, String),
    #[error("Failed to remove old jail root directory: {0}")]
    RmOldRootDir(io::Error),
    #[error("Failed to change current directory: {0}")]
    SetCurrentDir(io::Error),
    #[error("Failed to join network namespace: netns: {0}")]
    SetNetNs(io::Error),
    #[error("Failed to set limit for resource: {0}")]
    Setrlimit(String),
    #[error("Failed to daemonize: setsid: {0}")]
    SetSid(io::Error),
    #[error("Invalid uid: {0}")]
    Uid(String),
    #[error("Failed to unmount the old jail root: {0}")]
    UmountOldRoot(io::Error),
    #[error("Unexpected value for the socket listener fd: {0}")]
    UnexpectedListenerFd(i32),
    #[error("Failed to unshare into new mount namespace: {0}")]
    UnshareNewNs(io::Error),
    #[error("Failed to unset the O_CLOEXEC flag on the socket fd: {0}")]
    UnsetCloexec(io::Error),
    #[error("Slice contains invalid UTF-8 data : {0}")]
    UTF8Parsing(std::str::Utf8Error),
    #[error("{}", format!("Failed to write to {:?}: {}", .0, .1).replace('\"', ""))]
    Write(PathBuf, io::Error),
}

pub type Result<T> = result::Result<T, Error>;

/// Create an ArgParser object which contains info about the command line argument parser and
/// populate it with the expected arguments and their characteristics.
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
            "Daemonize the jailer before exec, by invoking setsid(), and redirecting the standard \
             I/O file descriptors to /dev/null.",
        ))
        .arg(
            Argument::new("new-pid-ns")
                .takes_value(false)
                .help("Exec into a new PID namespace."),
        )
        .arg(Argument::new("cgroup").allow_multiple(true).help(
            "Cgroup and value to be set by the jailer. It must follow this format: \
             <cgroup_file>=<value> (e.g cpu.shares=10). This argument can be used multiple times \
             to add multiple cgroups.",
        ))
        .arg(Argument::new("resource-limit").allow_multiple(true).help(
            "Resource limit values to be set by the jailer. It must follow this format: \
             <resource>=<value> (e.g no-file=1024). This argument can be used multiple times to \
             add multiple resource limits. Current available resource values are:\n\t\tfsize: The \
             maximum size in bytes for files created by the process.\n\t\tno-file: Specifies a \
             value one greater than the maximum file descriptor number that can be opened by this \
             process.",
        ))
        .arg(
            Argument::new("cgroup-version")
                .takes_value(true)
                .default_value("1")
                .help("Select the cgroup version used by the jailer."),
        )
        .arg(
            Argument::new("parent-cgroup")
                .takes_value(true)
                .help("Parent cgroup in which the cgroup of this microvm will be placed."),
        )
        .arg(
            Argument::new("version")
                .takes_value(false)
                .help("Print the binary version number."),
        )
}

// It's called writeln_special because we have to use this rather convoluted way of writing
// to special cgroup files, to avoid getting errors. It would be nice to know why that happens :-s
pub fn writeln_special<T, V>(file_path: &T, value: V) -> Result<()>
where
    T: AsRef<Path> + Debug,
    V: Display + Debug,
{
    fs::write(file_path, format!("{}\n", value))
        .map_err(|err| Error::Write(PathBuf::from(file_path.as_ref()), err))
}

pub fn readln_special<T: AsRef<Path> + Debug>(file_path: &T) -> Result<String> {
    let mut line = fs::read_to_string(file_path)
        .map_err(|err| Error::ReadToString(PathBuf::from(file_path.as_ref()), err))?;

    // Remove the newline character at the end (if any).
    line.pop();

    Ok(line)
}

fn close_fds_by_close_range() -> Result<()> {
    // First try using the close_range syscall to close all open FDs in the range of 3..UINT_MAX
    // SAFETY: if the syscall is not available then ENOSYS will be returned
    SyscallReturnCode(unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3,
            libc::c_uint::MAX,
            libc::CLOSE_RANGE_UNSHARE,
        )
    } as libc::c_int)
    .into_empty_result()
    .map_err(Error::CloseRange)
}

fn close_fds_by_reading_proc() -> Result<()> {
    // Calling this method means that close_range failed (we might be on kernel < 5.9).
    // We can't use std::fs::ReadDir here as under the hood we need access to the dirfd in order to
    // not close it twice
    let path = "/proc/self/fd";
    let mut dir = nix::dir::Dir::open(
        path,
        nix::fcntl::OFlag::O_DIRECTORY | nix::fcntl::OFlag::O_NOATIME,
        nix::sys::stat::Mode::empty(),
    )
    .map_err(|e| Error::DirOpen(path.to_string(), e.to_string()))?;

    let dirfd = dir.as_raw_fd();
    let mut c = dir.iter();

    while let Some(Ok(path)) = c.next() {
        let file_name = path.file_name();
        let fd_str = file_name.to_str().map_err(Error::UTF8Parsing)?;

        // If the entry is an INT entry, we go ahead and we treat it as an FD identifier.
        if let Ok(fd) = fd_str.parse::<i32>() {
            if fd > 2 && fd != dirfd {
                // SAFETY: Safe because close() cannot fail when passed a valid parameter.
                unsafe { libc::close(fd) };
            }
        }
    }
    Ok(())
}

// Closes all FDs other than 0 (STDIN), 1 (STDOUT) and 2 (STDERR)
fn close_inherited_fds() -> Result<()> {
    // The approach we take here is to firstly try to use the close_range syscall
    // which is available on kernels > 5.9.
    // We then fallback to using /proc/sef/fd to close open fds.
    if close_fds_by_close_range().is_err() {
        close_fds_by_reading_proc()?;
    }
    Ok(())
}

fn sanitize_process() -> Result<()> {
    // First thing to do is make sure we don't keep any inherited FDs
    // other that IN, OUT and ERR.
    close_inherited_fds()?;

    // Cleanup environment variables.
    clean_env_vars();
    Ok(())
}

fn clean_env_vars() {
    // Remove environment variables received from
    // the parent process so there are no leaks
    // inside the jailer environment
    for (key, _) in p_env::vars() {
        p_env::remove_var(key);
    }
}

/// Turns an AsRef<Path> into a CString (c style string).
/// The expect should not fail, since Linux paths only contain valid Unicode chars (do they?),
/// and do not contain null bytes (do they?).
pub fn to_cstring<T: AsRef<Path> + Debug>(path: T) -> Result<CString> {
    let path_str = path
        .as_ref()
        .to_path_buf()
        .into_os_string()
        .into_string()
        .map_err(|err| Error::OsStringParsing(path.as_ref().to_path_buf(), err))?;
    CString::new(path_str).map_err(Error::CStringParsing)
}

fn main() {
    sanitize_process()
        .unwrap_or_else(|err| panic!("Failed to sanitize the Jailer process: {}", err));

    let mut arg_parser = build_arg_parser();

    match arg_parser.parse_from_cmdline() {
        Err(err) => {
            println!(
                "Arguments parsing error: {} \n\nFor more information try --help.",
                err
            );
            process::exit(1);
        }
        _ => {
            if arg_parser.arguments().flag_present("help") {
                println!("Jailer v{}\n", JAILER_VERSION);
                println!("{}\n", arg_parser.formatted_help());
                println!(
                    "Any arguments after the -- separator will be supplied to the jailed binary.\n"
                );
                process::exit(0);
            }

            if arg_parser.arguments().flag_present("version") {
                println!("Jailer v{}\n", JAILER_VERSION);
                process::exit(0);
            }
        }
    }

    Env::new(
        arg_parser.arguments(),
        utils::time::get_time_us(utils::time::ClockType::Monotonic),
        utils::time::get_time_us(utils::time::ClockType::ProcessCpu),
    )
    .and_then(|env| {
        fs::create_dir_all(env.chroot_dir())
            .map_err(|err| Error::CreateDir(env.chroot_dir().to_owned(), err))?;
        env.run()
    })
    .unwrap_or_else(|err| panic!("Jailer error: {}", err));
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
    use std::env;
    use std::ffi::CStr;
    use std::fs::File;
    use std::os::unix::io::IntoRawFd;

    use utils::{arg_parser, rand};

    use super::*;

    fn run_close_fds_test(test_fn: fn() -> Result<()>) {
        let n = 100;

        let tmp_dir_path = format!(
            "/tmp/jailer/tests/close_fds/_{}",
            rand::rand_alphanumerics(4).into_string().unwrap()
        );
        assert!(fs::create_dir_all(&tmp_dir_path).is_ok());

        let mut fds = Vec::new();
        for i in 0..n {
            let maybe_file = File::create(format!("{}/{}", &tmp_dir_path, i));
            assert!(maybe_file.is_ok());
            fds.push(maybe_file.unwrap().into_raw_fd());
        }

        assert!(test_fn().is_ok());

        for fd in fds {
            let is_fd_opened = unsafe { libc::fcntl(fd, libc::F_GETFD) } == 0;
            assert!(!is_fd_opened);
        }

        assert!(fs::remove_dir_all(tmp_dir_path).is_ok());
    }

    #[test]
    fn test_fds_close_range() {
        // SAFETY: Always safe
        let mut n = unsafe { std::mem::zeroed() };
        // SAFETY: We check if the uname call succeeded
        assert_eq!(unsafe { libc::uname(&mut n) }, 0);
        // SAFETY: Always safe
        let release = unsafe { CStr::from_ptr(n.release.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        // Parse the major and minor version of the kernel
        let mut r = release.split('.');
        let major: i32 = str::parse(r.next().unwrap()).unwrap();
        let minor: i32 = str::parse(r.next().unwrap()).unwrap();

        // Skip this test if we're running on a too old kernel
        if major > 5 || (major == 5 && minor >= 9) {
            run_close_fds_test(close_fds_by_close_range);
        }
    }

    #[test]
    fn test_fds_proc() {
        run_close_fds_test(close_fds_by_reading_proc);
    }

    #[test]
    fn test_sanitize_process() {
        run_close_fds_test(sanitize_process);
    }

    #[test]
    fn test_clean_env_vars() {
        let env_vars: [&str; 5] = ["VAR1", "VAR2", "VAR3", "VAR4", "VAR5"];

        // Set environment variables
        for env_var in env_vars.iter() {
            env::set_var(env_var, "0");
        }

        // Cleanup the environment
        clean_env_vars();

        // Assert that the variables set beforehand
        // do not exist anymore
        for env_var in env_vars.iter() {
            assert_eq!(env::var_os(env_var), None);
        }
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
        let cgroup_file = "cpuset.mems";

        assert_eq!(
            format!("{}", Error::ArgumentParsing(err_args_parse)),
            "Failed to parse arguments: Found argument 'foo' which wasn't expected, or isn't \
             valid in this context."
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
                Error::Chmod(path.clone(), io::Error::from_raw_os_error(2))
            ),
            "Failed to change permissions on \"/foo\": No such file or directory (os error 2)",
        );
        assert_eq!(
            format!(
                "{}",
                Error::CgroupLineNotFound(proc_mounts.to_string(), controller.to_string())
            ),
            "sysfs configurations not found in /proc/mounts",
        );
        assert_eq!(
            format!("{}", Error::CgroupInvalidFile(cgroup_file.to_string())),
            "Cgroup invalid file: cpuset.mems",
        );
        assert_eq!(
            format!(
                "{}",
                Error::CgroupWrite("1".to_string(), "2".to_string(), cgroup_file.to_string())
            ),
            "Expected value 1 for cpuset.mems. Current value: 2",
        );
        assert_eq!(
            format!("{}", Error::CgroupFormat(cgroup_file.to_string())),
            "Invalid format for cgroups: cpuset.mems",
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
            format!("{}", Error::Clone(io::Error::from_raw_os_error(42))),
            "Failed cloning into a new child process: No message of desired type (os error 42)",
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
            format!("{}", Error::ExecFileName("foobarbaz".to_string())),
            "Invalid filename. The filename of `--exec-file` option must contain \"firecracker\": \
             foobarbaz",
        );
        assert_eq!(
            format!("{}", Error::ExtractFileName(file_path.clone())),
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
            "Invalid instance ID: Invalid char (a) at position 1",
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
            "Failed to bind mount the jail root directory: No message of desired type (os error \
             42)",
        );
        assert_eq!(
            format!(
                "{}",
                Error::MountPropagationSlave(io::Error::from_raw_os_error(42))
            ),
            "Failed to change the propagation type to slave: No message of desired type (os error \
             42)",
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
            format!("{}", Error::ResLimitArgument("foo".to_string())),
            "Invalid resource argument: foo",
        );
        assert_eq!(
            format!("{}", Error::ResLimitFormat("foo".to_string())),
            "Invalid format for resources limits: foo",
        );
        assert_eq!(
            format!(
                "{}",
                Error::ResLimitValue("foo".to_string(), "bar".to_string())
            ),
            "Invalid limit value for resource: foo: bar",
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
            format!("{}", Error::Setrlimit("foobar".to_string())),
            "Failed to set limit for resource: foobar",
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

    #[test]
    fn test_to_cstring() {
        let path = Path::new("some_path");
        let cstring_path = to_cstring(path).unwrap();
        assert_eq!(cstring_path, CString::new("some_path").unwrap());
        let path_with_nul = Path::new("some_path\0");
        assert_eq!(
            format!("{}", to_cstring(path_with_nul).unwrap_err()),
            "Encountered interior \\0 while parsing a string"
        );
    }
}
