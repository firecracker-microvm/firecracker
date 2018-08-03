extern crate libc;
extern crate regex;

extern crate sys_util;

mod cgroup;
mod env;
mod uuid;

use std::ffi::{CString, NulError, OsStr, OsString};
use std::fs::{canonicalize, create_dir_all, metadata};
use std::io;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::result;

use env::Env;
use uuid::validate;

pub const KVM_FD: i32 = 3;
pub const LISTENER_FD: i32 = 4;

const SOCKET_FILE_NAME: &str = "api.socket";

#[derive(Debug)]
pub enum Error {
    Canonicalize(PathBuf, io::Error),
    CgroupLineNotFound(&'static str, &'static str),
    CgroupLineNotUnique(&'static str, &'static str),
    ChangeDevNetTunOwner(sys_util::Error),
    Chroot(i32),
    Copy(PathBuf, PathBuf, io::Error),
    CreateDir(PathBuf, io::Error),
    OsStringParsing(PathBuf, OsString),
    CStringParsing(String, NulError),
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
    NumaNode(String),
    OpenDevKvm(sys_util::Error),
    MknodDevNetTun(sys_util::Error),
    ReadLine(PathBuf, io::Error),
    RegEx(regex::Error),
    Uid(String),
    UnexpectedKvmFd(i32),
    UnexpectedListenerFd(i32),
    UnixListener(io::Error),
    UnsetCloexec(sys_util::Error),
    ValidateUUID(uuid::UUIDError),
    Write(PathBuf, io::Error),
}

pub type Result<T> = result::Result<T, Error>;

pub struct JailerArgs<'a> {
    id: &'a str,
    numa_node: u32,
    exec_file_path: PathBuf,
    chroot_base_dir: PathBuf,
    uid: u32,
    gid: u32,
}

impl<'a> JailerArgs<'a> {
    pub fn new(
        id: &'a str,
        node: &str,
        exec_file: &str,
        chroot_base: &str,
        uid: &str,
        gid: &str,
    ) -> Result<Self> {
        // Check that id meets the style of an UUID's.
        validate(id).map_err(Error::ValidateUUID)?;

        let numa_node = node
            .parse::<u32>()
            .map_err(|_| Error::NumaNode(String::from(node)))?;

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

        let uid = uid
            .parse::<u32>()
            .map_err(|_| Error::Uid(String::from(uid)))?;
        let gid = gid
            .parse::<u32>()
            .map_err(|_| Error::Gid(String::from(gid)))?;

        Ok(JailerArgs {
            id,
            numa_node,
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

    // TODO: use dup2 to make sure we're actually getting 3 and 4?

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

    let env = Env::new(args)?;

    // Here we are creating the /dev/net/tun device inside the jailer.
    // Following commands can be translated into bash like this:
    // $: mkdir -p $chroot_dir/dev/net
    // $: dev_net_tun_path={$chroot_dir}/"tun"
    // $: mknod $dev_net_tun_path c 10 200
    // www.kernel.org/doc/Documentation/networking/tuntap.txt specifies 10 and 200 as the minor
    // and major for the /dev/net/tun device.
    let mut chroot_dir = PathBuf::from(env.chroot_dir());
    chroot_dir.push("dev/net");
    create_dir_all(&chroot_dir).map_err(|e| Error::CreateDir(chroot_dir.clone(), e))?;

    let dev_net_tun_path: CString = into_cstring(chroot_dir.join("tun"))?;
    // As per sysstat.h:
    // S_IFCHR -> character special device
    // S_IRUSR -> read permission, owner
    // S_IWUSR -> write permission, owner
    // See www.kernel.org/doc/Documentation/networking/tuntap.txt, 'Configuration' chapter for
    // more clarity.
    let ret = unsafe {
        libc::mknod(
            dev_net_tun_path.as_ptr(),
            libc::S_IFCHR | libc::S_IRUSR | libc::S_IWUSR,
            libc::makedev(10, 200),
        )
    };

    if ret < 0 {
        return Err(Error::MknodDevNetTun(sys_util::Error::last()));
    }

    let ret = unsafe { libc::chown(dev_net_tun_path.as_ptr(), env.uid(), env.gid()) };

    if ret < 0 {
        return Err(Error::ChangeDevNetTunOwner(sys_util::Error::last()));
    }

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

/// Turns a PathBuf into a CString (c style string).
/// The expect should not fail, since Linux paths only contain valid Unicode chars (do they?),
/// and do not contain null bytes (do they?).
pub fn into_cstring(path: PathBuf) -> Result<CString> {
    let path_str = path
        .clone()
        .into_os_string()
        .into_string()
        .map_err(|e| Error::OsStringParsing(path, e))?;
    CString::new(path_str.clone()).map_err(|e| Error::CStringParsing(path_str, e))
}
