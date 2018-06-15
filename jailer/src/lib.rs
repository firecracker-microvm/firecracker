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
    CgroupLineNotFound(&'static str, &'static str),
    CgroupLineNotUnique(&'static str, &'static str),
    Chroot(i32),
    Copy(PathBuf, PathBuf, io::Error),
    CreateDir(PathBuf, io::Error),
    Exec(io::Error),
    FileCreate(PathBuf, io::Error),
    FileName(PathBuf),
    FileOpen(PathBuf, io::Error),
    GetOldFdFlags(sys_util::Error),
    Gid(String),
    Metadata(PathBuf, io::Error),
    NotAFile(PathBuf),
    NotAFolder(PathBuf),
    NotAlphanumeric(String),
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
    chroot_base_dir: PathBuf,
    uid: u32,
    gid: u32,
}

impl<'a> JailerArgs<'a> {
    pub fn new(
        id: &'a str,
        exec_file: &str,
        chroot_base: &str,
        uid: &str,
        gid: &str,
    ) -> Result<Self> {
        // Maybe it's a good idea to restrict the id to alphanumeric strings.
        for c in id.chars() {
            if !c.is_alphanumeric() {
                return Err(Error::NotAlphanumeric(id.to_string()));
            }
        }

        let exec_file_path =
            canonicalize(exec_file).map_err(|e| Error::Canonicalize(PathBuf::from(exec_file), e))?;

        if !metadata(&exec_file_path)
            .map_err(|e| Error::Metadata(exec_file_path.clone(), e))?
            .is_file()
        {
            return Err(Error::NotAFile(exec_file_path));
        }

        let chroot_base_dir = canonicalize(chroot_base)
            .map_err(|e| Error::Canonicalize(PathBuf::from(chroot_base), e))?;

        if !metadata(&chroot_base_dir)
            .map_err(|e| Error::Metadata(exec_file_path.clone(), e))?
            .is_dir()
        {
            return Err(Error::NotAFolder(chroot_base_dir));
        }

        let uid = uid.parse::<u32>()
            .map_err(|_| Error::Uid(String::from(uid)))?;
        let gid = gid.parse::<u32>()
            .map_err(|_| Error::Gid(String::from(gid)))?;

        Ok(JailerArgs {
            id,
            exec_file_path,
            chroot_base_dir,
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
    // passed on to Firecracker post exec, and used via knowing their values in advance.

    // TODO: use dup2 to make sure we're actually getting 3, 4, and 5?

    // TODO: can a malicious guest that takes over firecracker use its access to the KVM fd to
    // starve the host of resources? (cgroups should take care of that, but do they currently?)

    // Safe because we use a constant null-terminated string and verify the result.
    let ret = unsafe { libc::open("/dev/kvm\0".as_ptr() as *const libc::c_char, libc::O_RDWR) };
    if ret < 0 {
        return Err(Error::OpenDevKvm(sys_util::Error::last()));
    }
    if ret != KVM_FD {
        return Err(Error::UnexpectedKvmFd(ret));
    }

    // TODO: is RDWR required for /dev/tun (most likely)?
    // Safe because we use a constant null-terminated string and verify the result.
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

    // The unwrap should not fail, since the end of chroot_dir looks like ..../<id>/root
    let listener = UnixListener::bind(env.chroot_dir().parent().unwrap().join(SOCKET_FILE_NAME))
        .map_err(|e| Error::UnixListener(e))?;

    let listener_fd = listener.as_raw_fd();
    if listener_fd != LISTENER_FD {
        return Err(Error::UnexpectedListenerFd(listener_fd));
    }

    // It turns out Rust is so safe, it opens everything with FD_CLOEXEC, which we have to unset.

    // This is safe because we know fd and the cmd are valid.
    let mut fd_flags = unsafe { libc::fcntl(listener_fd, libc::F_GETFD, 0) };
    if fd_flags < 0 {
        return Err(Error::GetOldFdFlags(sys_util::Error::last()));
    }

    fd_flags &= !libc::FD_CLOEXEC;

    // This is safe because we know the fd, the cmd, and the last arg are valid.
    if unsafe { libc::fcntl(listener_fd, libc::F_SETFD, fd_flags) } < 0 {
        return Err(Error::UnsetCloexec(sys_util::Error::last()));
    }

    env.run()
}
