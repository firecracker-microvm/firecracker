extern crate libc;
extern crate regex;

extern crate sys_util;

mod cgroup;
mod env;

use std::ffi::OsStr;
use std::fs::{canonicalize, metadata};
use std::io;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::result;

use env::Env;

pub const KVM_FD: i32 = 3;
pub const DEV_NET_TUN_FD: i32 = 4;
pub const LISTENER_FD: i32 = 5;

const SOCKET_FILE_NAME: &str = "api.socket";

#[derive(Debug)]
pub enum Error {
    Canonicalize(PathBuf, io::Error),
    CgroupLineNotFound(String),
    CgroupLineNotUnique(String),
    Chroot(i32),
    Copy(PathBuf, PathBuf, io::Error),
    CreateDir(PathBuf, io::Error),
    Exec(io::Error),
    FileCreate(PathBuf, io::Error),
    FileName(PathBuf),
    FileOpen(PathBuf, io::Error),
    Gid(String),
    Metadata(PathBuf, io::Error),
    NotAFile(PathBuf),
    OpenDevKvm(sys_util::Error),
    OpenDevNetTun(sys_util::Error),
    ReadLine(PathBuf, io::Error),
    RegEx(regex::Error),
    Uid(String),
    UnexpectedKvmFd(i32),
    UnexpectedDevNetTunFd(i32),
    UnexpectedListenerFd(i32),
    UnixListener(io::Error),
    UnsetCloexec(sys_util::Error),
    Write(PathBuf, io::Error),
}

pub type Result<T> = result::Result<T, Error>;

pub struct JailerArgs<'a> {
    id: &'a str,
    exec_file_path: PathBuf,
    uid: u32,
    gid: u32,
}

impl<'a> JailerArgs<'a> {
    pub fn new(id: &'a str, exec_file: &'a str, uid: &str, gid: &str) -> Result<Self> {
        let exec_file_path =
            canonicalize(exec_file).map_err(|e| Error::Canonicalize(PathBuf::from(exec_file), e))?;

        if !metadata(&exec_file_path)
            .map_err(|e| Error::Metadata(exec_file_path.clone(), e))?
            .is_file()
        {
            return Err(Error::NotAFile(exec_file_path));
        }

        let uid = uid.parse::<u32>()
            .map_err(|_| Error::Uid(String::from(uid)))?;
        let gid = gid.parse::<u32>()
            .map_err(|_| Error::Gid(String::from(gid)))?;

        Ok(JailerArgs {
            id,
            exec_file_path,
            uid,
            gid,
        })
    }

    pub fn exec_file_name(&self) -> Result<&OsStr> {
        self.exec_file_path
            .file_name()
            .ok_or_else(|| Error::FileName(self.exec_file_path.clone()))
    }
}

pub fn run(args: JailerArgs) -> Result<()> {
    // We open /dev/kvm, /dev/tun, and create the listening socket. These file descriptors will be
    // passed on to Firecracker post exec, and used as file descriptors 3, 4, and 5, respectively.

    // TODO: use dup2 to make sure we're actually getting 3, 4, and 5?

    // TODO: can a malicious guest that takes over firecracker use its access to the KVM fd to
    // starve  the host of resources? (cgroups should take care of that, but do they currently?)

    // Safe because we use a constant nul-terminated string and verify the result. We should
    // get our fd = 3 here.
    let ret = unsafe { libc::open("/dev/kvm\0".as_ptr() as *const libc::c_char, libc::O_RDWR) };
    if ret < 0 {
        return Err(Error::OpenDevKvm(sys_util::Error::last()));
    }
    if ret != KVM_FD {
        return Err(Error::UnexpectedKvmFd(ret));
    }

    // TODO: is RDWR required for /dev/tun (most likely)?
    // Safe because we use a constant nul-terminated string and verify the result. We should
    // get our fd = 4 here.
    let ret = unsafe {
        libc::open(
            "/dev/net/tun\0".as_ptr() as *const libc::c_char,
            libc::O_RDWR | libc::O_NONBLOCK,
        )
    };
    if ret < 0 {
        return Err(Error::OpenDevNetTun(sys_util::Error::last()));
    }
    if ret != DEV_NET_TUN_FD {
        return Err(Error::UnexpectedDevNetTunFd(ret));
    }

    let env = Env::new(args)?;

    // We should get our fd = 5 here.
    let listener = UnixListener::bind(env.chroot_dir().join(SOCKET_FILE_NAME))
        .map_err(|e| Error::UnixListener(e))?;

    let listener_fd = listener.as_raw_fd();
    if listener_fd != LISTENER_FD {
        return Err(Error::UnexpectedListenerFd(listener_fd));
    }

    // It turns out Rust is so safe, it opens everything with CLOSE_ON_EXEC.

    // TODO: So as of today (20180612), FD_CLOEXEC is the only file descriptor flag, so setting
    // flags to 0 should clear that and only that. Maybe at some point it would make sense to
    // get the flags first, clear FD_CLOEXEC, and set the resulting flags.

    // This is safe because we know the fd is valid.
    if unsafe { libc::fcntl(listener_fd, libc::F_SETFD, 0) } < 0 {
        return Err(Error::UnsetCloexec(sys_util::Error::last()));
    }

    env.run()
}
