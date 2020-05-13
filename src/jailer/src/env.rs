// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::CStr;
use std::fs::{self, canonicalize, File, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::IntoRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use libc;

use cgroup::Cgroup;
use chroot::chroot;
use utils::arg_parser::Error::MissingValue;
use utils::syscall::SyscallReturnCode;
use utils::{arg_parser, validators};
use {Error, Result};

const STDIN_FILENO: libc::c_int = 0;
const STDOUT_FILENO: libc::c_int = 1;
const STDERR_FILENO: libc::c_int = 2;

const DEV_KVM_WITH_NUL: &[u8] = b"/dev/kvm\0";
const DEV_NET_TUN_WITH_NUL: &[u8] = b"/dev/net/tun\0";
const DEV_NULL_WITH_NUL: &[u8] = b"/dev/null\0";
// Relevant folders inside the jail that we create or/and for which we change ownership.
// We need /dev in order to be able to create /dev/kvm and /dev/net/tun device.
// We need /run for the default location of the api socket.
// Since libc::chown is not recursive, we cannot specify only /dev/net as we want
// to walk through the entire folder hierarchy.
const FOLDER_HIERARCHY: [&[u8]; 4] = [b"/\0", b"/dev\0", b"/dev/net\0", b"/run\0"];
const FOLDER_PERMISSIONS: u32 = 0o700;

// Helper function, since we'll use libc::dup2 a bunch of times for daemonization.
fn dup2(old_fd: libc::c_int, new_fd: libc::c_int) -> Result<()> {
    // This is safe because we are using a library function with valid parameters.
    SyscallReturnCode(unsafe { libc::dup2(old_fd, new_fd) })
        .into_empty_result()
        .map_err(Error::Dup2)
}

pub struct Env {
    id: String,
    numa_node: u32,
    chroot_dir: PathBuf,
    exec_file_path: PathBuf,
    uid: u32,
    gid: u32,
    netns: Option<String>,
    daemonize: bool,
    start_time_us: u64,
    start_time_cpu_us: u64,
    extra_args: Vec<String>,
}

impl Env {
    pub fn new(
        arguments: &arg_parser::Arguments,
        start_time_us: u64,
        start_time_cpu_us: u64,
    ) -> Result<Self> {
        // All arguments are either mandatory, or have default values, so the unwraps
        // should not fail.
        let id = arguments
            .value_as_string("id")
            .ok_or_else(|| Error::ArgumentParsing(MissingValue("id".to_string())))?;

        validators::validate_instance_id(&id.as_str()).map_err(Error::InvalidInstanceId)?;

        let numa_node_str = arguments
            .value_as_string("node")
            .ok_or_else(|| Error::ArgumentParsing(MissingValue("node".to_string())))?;
        let numa_node = numa_node_str
            .parse::<u32>()
            .map_err(|_| Error::NumaNode(numa_node_str))?;

        let exec_file = arguments
            .value_as_string("exec-file")
            .ok_or_else(|| Error::ArgumentParsing(MissingValue("exec-file".to_string())))?;
        let exec_file_path = canonicalize(&exec_file)
            .map_err(|e| Error::Canonicalize(PathBuf::from(&exec_file), e))?;

        if !exec_file_path.is_file() {
            return Err(Error::NotAFile(exec_file_path));
        }

        let chroot_base = arguments
            .value_as_string("chroot-base-dir")
            .ok_or_else(|| Error::ArgumentParsing(MissingValue("chroot-base-dir".to_string())))?;
        let mut chroot_dir = canonicalize(&chroot_base)
            .map_err(|e| Error::Canonicalize(PathBuf::from(&chroot_base), e))?;

        if !chroot_dir.is_dir() {
            return Err(Error::NotADirectory(chroot_dir));
        }

        chroot_dir.push(
            exec_file_path
                .file_name()
                .ok_or_else(|| Error::FileName(exec_file_path.clone()))?,
        );
        chroot_dir.push(&id);
        chroot_dir.push("root");

        let uid_str = arguments
            .value_as_string("uid")
            .ok_or_else(|| Error::ArgumentParsing(MissingValue("uid".to_string())))?;
        let uid = uid_str.parse::<u32>().map_err(|_| Error::Uid(uid_str))?;

        let gid_str = arguments
            .value_as_string("gid")
            .ok_or_else(|| Error::ArgumentParsing(MissingValue("gid".to_string())))?;
        let gid = gid_str.parse::<u32>().map_err(|_| Error::Gid(gid_str))?;

        let netns = arguments.value_as_string("netns");

        let daemonize = arguments.value_as_bool("daemonize").unwrap_or(false);

        Ok(Env {
            id,
            numa_node,
            chroot_dir,
            exec_file_path,
            uid,
            gid,
            netns,
            daemonize,
            start_time_us,
            start_time_cpu_us,
            extra_args: arguments.extra_args(),
        })
    }

    pub fn chroot_dir(&self) -> &Path {
        self.chroot_dir.as_path()
    }

    pub fn gid(&self) -> u32 {
        self.gid
    }

    pub fn uid(&self) -> u32 {
        self.uid
    }

    fn mknod_and_own_dev(
        &self,
        dev_path_str: &'static [u8],
        dev_major: u32,
        dev_minor: u32,
    ) -> Result<()> {
        let dev_path = CStr::from_bytes_with_nul(dev_path_str).map_err(Error::FromBytesWithNul)?;
        // As per sysstat.h:
        // S_IFCHR -> character special device
        // S_IRUSR -> read permission, owner
        // S_IWUSR -> write permission, owner
        // See www.kernel.org/doc/Documentation/networking/tuntap.txt, 'Configuration' chapter for
        // more clarity.
        SyscallReturnCode(unsafe {
            libc::mknod(
                dev_path.as_ptr(),
                libc::S_IFCHR | libc::S_IRUSR | libc::S_IWUSR,
                libc::makedev(dev_major, dev_minor),
            )
        })
        .into_empty_result()
        .map_err(|e| Error::MknodDev(e, std::str::from_utf8(dev_path_str).unwrap()))?;

        SyscallReturnCode(unsafe { libc::chown(dev_path.as_ptr(), self.uid(), self.gid()) })
            .into_empty_result()
            // Safe to unwrap as we provided valid file names.
            .map_err(|e| Error::ChangeFileOwner(PathBuf::from(dev_path.to_str().unwrap()), e))
    }

    pub fn setup_jailed_folder(&self, folder: &[u8]) -> Result<()> {
        let folder_cstr = CStr::from_bytes_with_nul(folder).map_err(Error::FromBytesWithNul)?;

        // Safe to unwrap as the byte sequence is UTF-8 validated above.
        let path = folder_cstr.to_str().unwrap();
        let path_buf = PathBuf::from(path);
        fs::create_dir_all(path).map_err(|e| Error::CreateDir(path_buf.clone(), e))?;
        fs::set_permissions(path, Permissions::from_mode(FOLDER_PERMISSIONS))
            .map_err(|e| Error::Chmod(path_buf.clone(), e))?;

        #[cfg(target_arch = "x86_64")]
        let folder_bytes_ptr = folder.as_ptr() as *const i8;
        #[cfg(target_arch = "aarch64")]
        let folder_bytes_ptr = folder.as_ptr();
        SyscallReturnCode(unsafe { libc::chown(folder_bytes_ptr, self.uid(), self.gid()) })
            .into_empty_result()
            .map_err(|e| Error::ChangeFileOwner(path_buf, e))
    }

    pub fn run(mut self) -> Result<()> {
        let exec_file_name = self
            .exec_file_path
            .file_name()
            .ok_or_else(|| Error::FileName(self.exec_file_path.clone()))?;

        let chroot_exec_file = PathBuf::from("/").join(exec_file_name);

        // We do a quick push here to get the global path of the executable inside the chroot,
        // without having to create a new PathBuf. We'll then do a pop to revert to the actual
        // chroot_dir right after the copy.
        // TODO: just now wondering ... is doing a push()/pop() thing better than just creating
        // a new PathBuf, with something like chroot_dir.join(exec_file_name) ?!
        self.chroot_dir.push(exec_file_name);

        // TODO: hard link instead of copy? This would save up disk space, but hard linking is
        // not always possible :(
        fs::copy(&self.exec_file_path, &self.chroot_dir)
            .map_err(|e| Error::Copy(self.exec_file_path.clone(), self.chroot_dir.clone(), e))?;

        // Pop exec_file_name.
        self.chroot_dir.pop();

        // Join the specified network namespace, if applicable.
        if let Some(ref path) = self.netns {
            // This will take ownership of the raw fd.
            // TODO: for some reason, if we use as_raw_fd here instead, the resulting fd cannot
            // be used with setns, because we get an EBADFD error. I wonder why?
            let netns_fd = File::open(path)
                .map_err(|e| Error::FileOpen(PathBuf::from(path), e))?
                .into_raw_fd();

            // Safe because we are passing valid parameters.
            SyscallReturnCode(unsafe { libc::setns(netns_fd, libc::CLONE_NEWNET) })
                .into_empty_result()
                .map_err(Error::SetNetNs)?;

            // Since we have ownership here, we also have to close the fd after joining the
            // namespace. Safe because we are passing valid parameters.
            SyscallReturnCode(unsafe { libc::close(netns_fd) })
                .into_empty_result()
                .map_err(Error::CloseNetNsFd)?;
        }

        // We have to setup cgroups at this point, because we can't do it anymore after chrooting.
        let cgroup = Cgroup::new(self.id.as_str(), self.numa_node, exec_file_name)?;
        cgroup.attach_pid()?;

        // If daemonization was requested, open /dev/null before chrooting.
        let dev_null = if self.daemonize {
            // Safe because we use a constant null-terminated string and verify the result.
            Some(
                SyscallReturnCode(unsafe {
                    libc::open(
                        DEV_NULL_WITH_NUL.as_ptr() as *const libc::c_char,
                        libc::O_RDWR,
                    )
                })
                .into_result()
                .map_err(Error::OpenDevNull)?,
            )
        } else {
            None
        };

        // Jail self.
        chroot(self.chroot_dir())?;

        // This will not only create necessary directories, but will also change ownership
        // for all of them.
        FOLDER_HIERARCHY
            .iter()
            .map(|f| self.setup_jailed_folder(*f))
            .collect::<Result<()>>()?;

        // Here we are creating the /dev/kvm and /dev/net/tun devices inside the jailer.
        // Following commands can be translated into bash like this:
        // $: mkdir -p $chroot_dir/dev/net
        // $: dev_net_tun_path={$chroot_dir}/"tun"
        // $: mknod $dev_net_tun_path c 10 200
        // www.kernel.org/doc/Documentation/networking/tuntap.txt specifies 10 and 200 as the major
        // and minor for the /dev/net/tun device.
        self.mknod_and_own_dev(DEV_NET_TUN_WITH_NUL, 10, 200)?;
        // Do the same for /dev/kvm with (major, minor) = (10, 232).
        self.mknod_and_own_dev(DEV_KVM_WITH_NUL, 10, 232)?;

        // Daemonize before exec, if so required (when the dev_null variable != None).
        if let Some(fd) = dev_null {
            // Call setsid(). Safe because it's a library function.
            SyscallReturnCode(unsafe { libc::setsid() })
                .into_empty_result()
                .map_err(Error::SetSid)?;

            // Replace the stdio file descriptors with the /dev/null fd.
            dup2(fd, STDIN_FILENO)?;
            dup2(fd, STDOUT_FILENO)?;
            dup2(fd, STDERR_FILENO)?;

            // Safe because we are passing valid parameters, and checking the result.
            SyscallReturnCode(unsafe { libc::close(fd) })
                .into_empty_result()
                .map_err(Error::CloseDevNullFd)?;
        }

        Err(Error::Exec(
            Command::new(chroot_exec_file)
                .args(&["--id", &self.id])
                .args(&["--start-time-us", &self.start_time_us.to_string()])
                .args(&["--start-time-cpu-us", &self.start_time_cpu_us.to_string()])
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .uid(self.uid())
                .gid(self.gid())
                .args(self.extra_args)
                .exec(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use build_arg_parser;

    use std::os::linux::fs::MetadataExt;
    use std::os::unix::ffi::OsStrExt;
    use utils::tempdir::TempDir;

    #[derive(Clone)]
    struct ArgVals<'a> {
        pub node: &'a str,
        pub id: &'a str,
        pub exec_file: &'a str,
        pub uid: &'a str,
        pub gid: &'a str,
        pub chroot_base: &'a str,
        pub netns: Option<&'a str>,
        pub daemonize: bool,
    }

    impl ArgVals<'_> {
        pub fn new() -> ArgVals<'static> {
            ArgVals {
                node: "1",
                id: "bd65600d-8669-4903-8a14-af88203add38",
                exec_file: "/proc/cpuinfo",
                uid: "1001",
                gid: "1002",
                chroot_base: "/",
                netns: Some("zzzns"),
                daemonize: true,
            }
        }
    }

    fn make_args(arg_vals: &ArgVals) -> Vec<String> {
        let mut arg_vec = vec![
            "--binary-name",
            "--node",
            arg_vals.node,
            "--id",
            arg_vals.id,
            "--exec-file",
            arg_vals.exec_file,
            "--uid",
            arg_vals.uid,
            "--gid",
            arg_vals.gid,
            "--chroot-base-dir",
            arg_vals.chroot_base,
        ]
        .into_iter()
        .map(String::from)
        .collect::<Vec<String>>();

        if let Some(s) = arg_vals.netns {
            arg_vec.push("--netns".to_string());
            arg_vec.push(s.to_string());
        }

        if arg_vals.daemonize {
            arg_vec.push("--daemonize".to_string());
        }

        arg_vec
    }

    #[test]
    fn test_new_env() {
        let good_arg_vals = ArgVals::new();
        let arg_parser = build_arg_parser();
        let mut args = arg_parser.arguments().clone();
        args.parse(&make_args(&good_arg_vals)).unwrap();
        // This should be fine.
        let good_env =
            Env::new(&args, 0, 0).expect("This new environment should be created successfully.");

        let mut chroot_dir = PathBuf::from(good_arg_vals.chroot_base);
        chroot_dir.push(Path::new(good_arg_vals.exec_file).file_name().unwrap());
        chroot_dir.push(good_arg_vals.id);
        chroot_dir.push("root");

        assert_eq!(good_env.chroot_dir(), chroot_dir);
        assert_eq!(format!("{}", good_env.gid()), good_arg_vals.gid);
        assert_eq!(format!("{}", good_env.uid()), good_arg_vals.uid);

        assert_eq!(good_env.netns, good_arg_vals.netns.map(String::from));
        assert!(good_env.daemonize);

        let another_good_arg_vals = ArgVals {
            netns: None,
            daemonize: false,
            ..good_arg_vals
        };

        let arg_parser = build_arg_parser();
        args = arg_parser.arguments().clone();
        args.parse(&make_args(&another_good_arg_vals)).unwrap();
        let another_good_env = Env::new(&args, 0, 0)
            .expect("This another new environment should be created successfully.");
        assert!(!another_good_env.daemonize);

        let base_invalid_arg_vals = ArgVals {
            daemonize: true,
            ..another_good_arg_vals.clone()
        };

        let invalid_node_arg_vals = ArgVals {
            node: "zzz",
            ..base_invalid_arg_vals.clone()
        };

        let arg_parser = build_arg_parser();
        args = arg_parser.arguments().clone();
        args.parse(&make_args(&invalid_node_arg_vals)).unwrap();
        assert!(Env::new(&args, 0, 0).is_err());

        let invalid_id_arg_vals = ArgVals {
            id: "/ad./sa12",
            ..base_invalid_arg_vals.clone()
        };

        let arg_parser = build_arg_parser();
        args = arg_parser.arguments().clone();
        args.parse(&make_args(&invalid_id_arg_vals)).unwrap();
        assert!(Env::new(&args, 0, 0).is_err());

        let inexistent_exec_file_arg_vals = ArgVals {
            exec_file: "/this!/file!/should!/not!/exist!/",
            ..base_invalid_arg_vals.clone()
        };

        let arg_parser = build_arg_parser();
        args = arg_parser.arguments().clone();
        args.parse(&make_args(&inexistent_exec_file_arg_vals))
            .unwrap();
        assert!(Env::new(&args, 0, 0).is_err());

        let invalid_uid_arg_vals = ArgVals {
            uid: "zzz",
            ..base_invalid_arg_vals.clone()
        };

        let arg_parser = build_arg_parser();
        args = arg_parser.arguments().clone();
        args.parse(&make_args(&invalid_uid_arg_vals)).unwrap();
        assert!(Env::new(&args, 0, 0).is_err());

        let invalid_gid_arg_vals = ArgVals {
            gid: "zzz",
            ..base_invalid_arg_vals.clone()
        };

        let arg_parser = build_arg_parser();
        args = arg_parser.arguments().clone();
        args.parse(&make_args(&invalid_gid_arg_vals)).unwrap();
        assert!(Env::new(&args, 0, 0).is_err());

        // The chroot-base-dir param is not validated by Env::new, but rather in run, when we
        // actually attempt to create the folder structure (the same goes for netns).
    }

    #[test]
    fn test_dup2() {
        // Open /dev/kvm since it should be available anyway.
        let fd1 = fs::File::open("/dev/kvm").unwrap().into_raw_fd();
        // We open a second file to make sure its associated fd is not used by something else.
        let fd2 = fs::File::open("/dev/kvm").unwrap().into_raw_fd();

        dup2(fd1, fd2).unwrap();

        unsafe {
            libc::close(fd1);
        }
        unsafe {
            libc::close(fd2);
        }
    }

    #[test]
    fn test_setup_jailed_folder() {
        let arg_parser = build_arg_parser();
        let mut args = arg_parser.arguments().clone();
        args.parse(&make_args(&ArgVals::new())).unwrap();
        let env = Env::new(&args, 0, 0).unwrap();

        // Error case: non UTF-8 paths.
        let bad_string: &[u8] = &[0, 102, 111, 111, 0]; // A leading nul followed by 'f', 'o', 'o'
        assert_eq!(
            format!("{}", env.setup_jailed_folder(bad_string).err().unwrap()),
            "Failed to decode string from byte array: data provided contains an interior nul byte at byte pos 0"
        );

        // Error case: inaccessible path - can't be triggered with unit tests running as root.
        // assert_eq!(
        //     format!("{}", env.setup_jailed_folders(vec!["/foo/bar"]).err().unwrap()),
        //     "Failed to create directory /foo/bar: Permission denied (os error 13)"
        // );

        // Success case.
        let foo_dir = TempDir::new().unwrap();
        let mut foo_path = foo_dir.as_path().as_os_str().as_bytes().to_vec();
        foo_path.push(0);
        foo_dir.remove().unwrap();
        assert!(env.setup_jailed_folder(foo_path.as_slice()).is_ok());

        let metadata = fs::metadata(
            CStr::from_bytes_with_nul(foo_path.as_slice())
                .unwrap()
                .to_str()
                .unwrap(),
        )
        .unwrap();
        // The mode bits will also have S_IFDIR set because the path belongs to a directory.
        assert_eq!(
            metadata.permissions().mode(),
            FOLDER_PERMISSIONS | libc::S_IFDIR
        );
        assert_eq!(metadata.st_uid(), env.uid);
        assert_eq!(metadata.st_gid(), env.gid);

        // Can't safely test that permissions remain unchanged by umask settings without affecting
        // the umask of the whole unit test process.
        // This crate produces a binary, so Rust integ tests aren't an option either.
        // And changing the umask in the Python integration tests is unsafe because of pytest's
        // process management; it can't be isolated from side effects.
    }
}
