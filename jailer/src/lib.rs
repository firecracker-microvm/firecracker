#[macro_use(crate_version, crate_authors)]
extern crate clap;
extern crate libc;
extern crate regex;

extern crate sys_util;

mod cgroup;
mod env;

use std::ffi::{CString, NulError, OsString};
use std::fs::create_dir_all;
use std::io;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::result;

use clap::{App, Arg, ArgMatches};

use env::Env;

pub const KVM_FD: i32 = 3;
pub const LISTENER_FD: i32 = 4;

const SOCKET_FILE_NAME: &str = "api.socket";
const MAX_ID_LENGTH: usize = 64;

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
    InvalidCharId,
    InvalidLengthId,
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
    Write(PathBuf, io::Error),
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
            Arg::with_name("numa_node")
                .long("node")
                .help("NUMA node to assign this microVM to.")
                .required(true)
                .takes_value(true),
        )
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
            Arg::with_name("uid")
                .long("uid")
                .help("Chroot uid")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("gid")
                .long("gid")
                .help("Chroot gid")
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
}

fn open_dev_kvm() -> Result<i32> {
    // Safe because we use a constant null-terminated string and verify the result.
    let ret = unsafe { libc::open("/dev/kvm\0".as_ptr() as *const libc::c_char, libc::O_RDWR) };

    if ret < 0 {
        return Err(Error::OpenDevKvm(sys_util::Error::last()));
    }

    if ret != KVM_FD {
        return Err(Error::UnexpectedKvmFd(ret));
    }

    Ok(ret)
}

pub fn run(args: ArgMatches) -> Result<()> {
    // We open /dev/kvm and create the listening socket. These file descriptors will be
    // passed on to Firecracker post exec, and used via knowing their values in advance.

    // TODO: can a malicious guest that takes over firecracker use its access to the KVM fd to
    // starve the host of resources? (cgroups should take care of that, but do they currently?)

    if let Err(e) = open_dev_kvm() {
        if let Error::UnexpectedKvmFd(ret) = e {
            // The problem here might be that the customer did not close every fd > 2 before
            // invoking the jailer (and did not open files with the O_CLOEXEC flag to begin with).
            // Before failing, let's close all non stdio fds up to and including ret, and then try
            // one more time.
            for i in 3..=ret {
                // Safe becase we're passing a valid paramter.
                unsafe { libc::close(i) };
            }

            // Maybe now we can get the desired fd number.
            open_dev_kvm()?;
        } else {
            return Err(e);
        }
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
    if unsafe {
        libc::mknod(
            dev_net_tun_path.as_ptr(),
            libc::S_IFCHR | libc::S_IRUSR | libc::S_IWUSR,
            libc::makedev(10, 200),
        )
    } < 0
    {
        return Err(Error::MknodDevNetTun(sys_util::Error::last()));
    }

    if unsafe { libc::chown(dev_net_tun_path.as_ptr(), env.uid(), env.gid()) } < 0 {
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
fn into_cstring(path: PathBuf) -> Result<CString> {
    let path_str = path
        .clone()
        .into_os_string()
        .into_string()
        .map_err(|e| Error::OsStringParsing(path, e))?;
    CString::new(path_str.clone()).map_err(|e| Error::CStringParsing(path_str, e))
}
