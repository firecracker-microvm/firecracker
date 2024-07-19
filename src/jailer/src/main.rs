// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::{CString, NulError, OsString};
use std::fmt::{Debug, Display};
use std::path::{Path, PathBuf};
use std::{env as p_env, fs, io};

use utils::arg_parser::{ArgParser, Argument, UtilsArgParserError as ParsingError};
use utils::syscall::SyscallReturnCode;
use utils::validators;

use crate::env::Env;

mod cgroup;
mod chroot;
mod env;
mod resource_limits;

const JAILER_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, thiserror::Error)]
pub enum JailerError {
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
    #[error("Failed to write to cgroups file: {0}")]
    CgroupWrite(io::Error),
    #[error("Failed to change owner for {0}: {1}")]
    ChangeFileOwner(PathBuf, io::Error),
    #[error("Failed to chdir into chroot directory: {0}")]
    ChdirNewRoot(io::Error),
    #[error("Failed to change permissions on {0}: {1}")]
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
    #[error("Failed to daemonize: {0}")]
    Daemonize(io::Error),
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
    InvalidInstanceId(validators::ValidatorError),
    #[error("{}", format!("File {:?} doesn't have a parent", .0).replace('\"', ""))]
    MissingParent(PathBuf),
    #[error("Failed to create the jail root directory before pivoting root: {0}")]
    MkdirOldRoot(io::Error),
    #[error("Failed to create {1} via mknod inside the jail: {0}")]
    MknodDev(io::Error, String),
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
    #[error("Regex failed: {0}")]
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
pub fn writeln_special<T, V>(file_path: &T, value: V) -> Result<(), JailerError>
where
    T: AsRef<Path> + Debug,
    V: Display + Debug,
{
    fs::write(file_path, format!("{}\n", value))
        .map_err(|err| JailerError::Write(PathBuf::from(file_path.as_ref()), err))
}

pub fn readln_special<T: AsRef<Path> + Debug>(file_path: &T) -> Result<String, JailerError> {
    let mut line = fs::read_to_string(file_path)
        .map_err(|err| JailerError::ReadToString(PathBuf::from(file_path.as_ref()), err))?;

    // Remove the newline character at the end (if any).
    line.pop();

    Ok(line)
}

fn close_fds_by_close_range() -> Result<(), JailerError> {
    // First try using the close_range syscall to close all open FDs in the range of 3..UINT_MAX
    // SAFETY: if the syscall is not available then ENOSYS will be returned
    SyscallReturnCode(unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3,
            libc::c_uint::MAX,
            libc::CLOSE_RANGE_UNSHARE,
        )
    })
    .into_empty_result()
    .map_err(JailerError::CloseRange)
}

// Closes all FDs other than 0 (STDIN), 1 (STDOUT) and 2 (STDERR)
fn close_inherited_fds() -> Result<(), JailerError> {
    // We use the close_range syscall which is available on kernels > 5.9.
    close_fds_by_close_range()?;
    Ok(())
}

fn sanitize_process() -> Result<(), JailerError> {
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

/// Turns an [`AsRef<Path>`] into a [`CString`] (c style string).
/// The expect should not fail, since Linux paths only contain valid Unicode chars (do they?),
/// and do not contain null bytes (do they?).
pub fn to_cstring<T: AsRef<Path> + Debug>(path: T) -> Result<CString, JailerError> {
    let path_str = path
        .as_ref()
        .to_path_buf()
        .into_os_string()
        .into_string()
        .map_err(|err| JailerError::OsStringParsing(path.as_ref().to_path_buf(), err))?;
    CString::new(path_str).map_err(JailerError::CStringParsing)
}

fn main() -> Result<(), JailerError> {
    let result = main_exec();
    if let Err(e) = result {
        eprintln!("{}", e);
        Err(e)
    } else {
        Ok(())
    }
}

fn main_exec() -> Result<(), JailerError> {
    sanitize_process()
        .unwrap_or_else(|err| panic!("Failed to sanitize the Jailer process: {}", err));

    let mut arg_parser = build_arg_parser();
    arg_parser
        .parse_from_cmdline()
        .map_err(JailerError::ArgumentParsing)?;
    let arguments = arg_parser.arguments();

    if arguments.flag_present("help") {
        println!("Jailer v{}\n", JAILER_VERSION);
        println!("{}\n", arg_parser.formatted_help());
        println!("Any arguments after the -- separator will be supplied to the jailed binary.\n");
        return Ok(());
    }

    if arguments.flag_present("version") {
        println!("Jailer v{}\n", JAILER_VERSION);
        return Ok(());
    }

    Env::new(
        arguments,
        utils::time::get_time_us(utils::time::ClockType::Monotonic),
        utils::time::get_time_us(utils::time::ClockType::ProcessCpu),
    )
    .and_then(|env| {
        fs::create_dir_all(env.chroot_dir())
            .map_err(|err| JailerError::CreateDir(env.chroot_dir().to_owned(), err))?;
        env.run()
    })
    .unwrap_or_else(|err| panic!("Jailer error: {}", err));
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]

    use std::env;
    use std::ffi::CStr;
    use std::fs::File;
    use std::os::unix::io::IntoRawFd;

    use utils::rand;

    use super::*;

    fn run_close_fds_test(test_fn: fn() -> Result<(), JailerError>) {
        let n = 100;

        let tmp_dir_path = format!(
            "/tmp/jailer/tests/close_fds/_{}",
            rand::rand_alphanumerics(4).into_string().unwrap()
        );
        fs::create_dir_all(&tmp_dir_path).unwrap();

        let mut fds = Vec::new();
        for i in 0..n {
            let maybe_file = File::create(format!("{}/{}", &tmp_dir_path, i));
            fds.push(maybe_file.unwrap().into_raw_fd());
        }

        test_fn().unwrap();

        for fd in fds {
            let is_fd_opened = unsafe { libc::fcntl(fd, libc::F_GETFD) } == 0;
            assert!(!is_fd_opened);
        }

        fs::remove_dir_all(tmp_dir_path).unwrap();
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
