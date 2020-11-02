// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::{CStr, OsString};
use std::fs::{self, canonicalize, File, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::IntoRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::cgroup;
use crate::cgroup::Cgroup;
use crate::chroot::chroot;
use crate::{Error, Result};
use utils::arg_parser::Error::MissingValue;
use utils::syscall::SyscallReturnCode;
use utils::{arg_parser, validators};

const STDIN_FILENO: libc::c_int = 0;
const STDOUT_FILENO: libc::c_int = 1;
const STDERR_FILENO: libc::c_int = 2;

// Kernel-based virtual machine (hardware virtualization extensions)
// minor/major numbers are taken from
// https://www.kernel.org/doc/html/latest/admin-guide/devices.html
const DEV_KVM_WITH_NUL: &[u8] = b"/dev/kvm\0";
const DEV_KVM_MAJOR: u32 = 10;
const DEV_KVM_MINOR: u32 = 232;

// TUN/TAP device minor/major numbers are taken from
// www.kernel.org/doc/Documentation/networking/tuntap.txt
const DEV_NET_TUN_WITH_NUL: &[u8] = b"/dev/net/tun\0";
const DEV_NET_TUN_MAJOR: u32 = 10;
const DEV_NET_TUN_MINOR: u32 = 200;

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
    chroot_dir: PathBuf,
    exec_file_path: PathBuf,
    uid: u32,
    gid: u32,
    netns: Option<String>,
    daemonize: bool,
    start_time_us: u64,
    start_time_cpu_us: u64,
    extra_args: Vec<String>,
    cgroups: Vec<Cgroup>,
}

impl Env {
    pub fn new(
        arguments: &arg_parser::Arguments,
        start_time_us: u64,
        start_time_cpu_us: u64,
    ) -> Result<Self> {
        // Unwraps should not fail because the arguments are mandatory arguments or with default values.
        let id = arguments
            .single_value("id")
            .ok_or_else(|| Error::ArgumentParsing(MissingValue("id".to_string())))?;

        validators::validate_instance_id(id).map_err(Error::InvalidInstanceId)?;

        let exec_file = arguments
            .single_value("exec-file")
            .ok_or_else(|| Error::ArgumentParsing(MissingValue("exec-file".to_string())))?;
        let exec_file_path = canonicalize(&exec_file)
            .map_err(|e| Error::Canonicalize(PathBuf::from(&exec_file), e))?;

        if !exec_file_path.is_file() {
            return Err(Error::NotAFile(exec_file_path));
        }

        let exec_file_name = exec_file_path
            .file_name()
            .ok_or_else(|| Error::FileName(exec_file_path.clone()))?;

        let chroot_base = arguments
            .single_value("chroot-base-dir")
            .ok_or_else(|| Error::ArgumentParsing(MissingValue("chroot-base-dir".to_string())))?;
        let mut chroot_dir = canonicalize(&chroot_base)
            .map_err(|e| Error::Canonicalize(PathBuf::from(&chroot_base), e))?;

        if !chroot_dir.is_dir() {
            return Err(Error::NotADirectory(chroot_dir));
        }

        chroot_dir.push(&exec_file_name);
        chroot_dir.push(id);
        chroot_dir.push("root");

        let uid_str = arguments
            .single_value("uid")
            .ok_or_else(|| Error::ArgumentParsing(MissingValue("uid".to_string())))?;
        let uid = uid_str
            .parse::<u32>()
            .map_err(|_| Error::Uid(uid_str.to_owned()))?;

        let gid_str = arguments
            .single_value("gid")
            .ok_or_else(|| Error::ArgumentParsing(MissingValue("gid".to_string())))?;
        let gid = gid_str
            .parse::<u32>()
            .map_err(|_| Error::Gid(gid_str.to_owned()))?;

        let netns = arguments.single_value("netns").cloned();

        let daemonize = arguments.flag_present("daemonize");

        // Optional arguments.
        let mut cgroups = Vec::new();

        // If `--node` is used, the corresponding cgroups will be created.
        if let Some(numa_node_str) = arguments.single_value("node") {
            let numa_node = numa_node_str
                .parse::<u32>()
                .map_err(|_| Error::NumaNode(numa_node_str.to_owned()))?;

            if let Ok(mut numa_cgroups) =
                cgroup::cgroups_from_numa_node(numa_node, id, &exec_file_name)
            {
                cgroups.append(&mut numa_cgroups);
            }
        }

        // cgroup format: <cgroup_controller>.<cgroup_property>=<value>,...
        if let Some(cgroups_args) = arguments.multiple_values("cgroup") {
            for cg in cgroups_args {
                let aux: Vec<&str> = cg.split('=').collect();
                if aux.len() != 2 || aux[1].is_empty() {
                    return Err(Error::CgroupFormat(cg.to_string()));
                }

                let cgroup = Cgroup::new(
                    aux[0].to_string(), // cgroup file
                    aux[1].to_string(), // cgroup value
                    id,
                    &exec_file_name,
                )?;

                cgroups.push(cgroup);
            }
        }

        Ok(Env {
            id: id.to_owned(),
            chroot_dir,
            exec_file_path,
            uid,
            gid,
            netns,
            daemonize,
            start_time_us,
            start_time_cpu_us,
            extra_args: arguments.extra_args(),
            cgroups,
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
        .map_err(|e| {
            Error::MknodDev(
                e,
                std::str::from_utf8(dev_path_str).expect("Cannot convert from UTF-8"),
            )
        })?;

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

    fn copy_exec_to_chroot(&mut self) -> Result<OsString> {
        let exec_file_name = self
            .exec_file_path
            .file_name()
            .ok_or_else(|| Error::FileName(self.exec_file_path.clone()))?;
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
        Ok(exec_file_name.to_os_string())
    }

    fn join_netns(path: &str) -> Result<()> {
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
            .map_err(Error::CloseNetNsFd)
    }

    pub fn run(mut self) -> Result<()> {
        let exec_file_name = self.copy_exec_to_chroot()?;
        let chroot_exec_file = PathBuf::from("/").join(&exec_file_name);

        // Join the specified network namespace, if applicable.
        if let Some(ref path) = self.netns {
            Env::join_netns(path)?;
        }

        // We have to setup cgroups at this point, because we can't do it anymore after chrooting.
        // cgroups are iterated two times as some cgroups may require others (e.g cpuset requires
        // cpuset.mems and cpuset.cpus) to be set before attaching any pid.
        for cgroup in &self.cgroups {
            // it will panic if any cgroup fails to write
            cgroup.write_value().unwrap();
        }

        for cgroup in &self.cgroups {
            // it will panic if any cgroup fails to attach
            cgroup.attach_pid().unwrap();
        }

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
        self.mknod_and_own_dev(DEV_NET_TUN_WITH_NUL, DEV_NET_TUN_MAJOR, DEV_NET_TUN_MINOR)?;
        // Do the same for /dev/kvm with (major, minor) = (10, 232).
        self.mknod_and_own_dev(DEV_KVM_WITH_NUL, DEV_KVM_MAJOR, DEV_KVM_MINOR)?;

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
    use crate::build_arg_parser;

    use std::os::linux::fs::MetadataExt;
    use std::os::unix::ffi::OsStrExt;
    use utils::tempdir::TempDir;
    use utils::tempfile::TempFile;

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
        pub cgroups: Vec<&'a str>,
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
                cgroups: vec!["cpu.shares=2", "cpuset.mems=0"],
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

        // Append cgroups arguments
        for cg in &arg_vals.cgroups {
            arg_vec.push("--cgroup".to_string());
            arg_vec.push((*cg).to_string());
        }

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

        let invalid_cgroup_arg_vals = ArgVals {
            cgroups: vec!["zzz"],
            ..base_invalid_arg_vals.clone()
        };

        let arg_parser = build_arg_parser();
        args = arg_parser.arguments().clone();
        args.parse(&make_args(&invalid_cgroup_arg_vals)).unwrap();
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

    fn get_major(dev: u64) -> u32 {
        unsafe { libc::major(dev) }
    }

    fn get_minor(dev: u64) -> u32 {
        unsafe { libc::minor(dev) }
    }

    #[test]
    fn test_mknod_and_own_dev() {
        use std::os::unix::fs::FileTypeExt;

        // Create a standard environment.
        let arg_parser = build_arg_parser();
        let mut args = arg_parser.arguments().clone();
        args.parse(&make_args(&ArgVals::new())).unwrap();
        let env = Env::new(&args, 0, 0).unwrap();

        // Ensure path buffers without NULL-termination are handled well.
        assert!(env.mknod_and_own_dev(b"/some/path", 0, 0).is_err());

        // Ensure device nodes are created with correct major/minor numbers and permissions.
        let dev_infos: Vec<(&[u8], u32, u32)> = vec![
            (b"/dev/net/tun-test\0", DEV_NET_TUN_MAJOR, DEV_NET_TUN_MINOR),
            (b"/dev/kvm-test\0", DEV_KVM_MAJOR, DEV_KVM_MINOR),
        ];

        for (dev, major, minor) in dev_infos {
            let dev_str = CStr::from_bytes_with_nul(dev).unwrap().to_str().unwrap();

            // Checking this just to be super sure there's no file at `dev_str` path (though
            // it shouldn't be as we deleted it at the end of the previous test run).
            if Path::new(dev_str).exists() {
                fs::remove_file(dev_str).unwrap();
            }

            // Create a new device node.
            env.mknod_and_own_dev(dev, major, minor).unwrap();

            // Ensure device's properties.
            let metadata = fs::metadata(dev_str).unwrap();
            assert_eq!(metadata.file_type().is_char_device(), true);
            assert_eq!(get_major(metadata.st_rdev()), major);
            assert_eq!(get_minor(metadata.st_rdev()), minor);
            assert_eq!(
                metadata.permissions().mode(),
                libc::S_IFCHR | libc::S_IRUSR | libc::S_IWUSR
            );

            // Trying to create again the same device node is not allowed.
            assert_eq!(
                format!("{}", env.mknod_and_own_dev(dev, major, minor).unwrap_err()),
                format!(
                    "Failed to create {}\u{0} via mknod inside the jail: File exists (os error 17)",
                    dev_str
                )
            );
            // Remove the device node.
            fs::remove_file(dev_str).expect("Could not remove file.");
        }
    }

    #[test]
    fn test_copy_exec_to_chroot() {
        // Create a standard environment.
        let arg_parser = build_arg_parser();
        let mut args = arg_parser.arguments().clone();

        // Create tmp resources for `exec_file` and `chroot_base`.
        let some_file = TempFile::new_with_prefix("/tmp/").unwrap();
        let some_file_path = some_file.as_path().to_str().unwrap();
        let some_file_name = some_file.as_path().file_name().unwrap();
        let some_dir = TempDir::new().unwrap();
        let some_dir_path = some_dir.as_path().to_str().unwrap();

        let some_arg_vals = ArgVals {
            node: "1",
            id: "bd65600d-8669-4903-8a14-af88203add38",
            exec_file: some_file_path,
            uid: "1001",
            gid: "1002",
            chroot_base: some_dir_path,
            netns: Some("zzzns"),
            daemonize: false,
            cgroups: Vec::new(),
        };
        fs::write(some_file_path, "some_content").unwrap();
        args.parse(&make_args(&some_arg_vals)).unwrap();
        let mut env = Env::new(&args, 0, 0).unwrap();

        // Create the required chroot dir hierarchy.
        fs::create_dir_all(env.chroot_dir()).expect("Could not create dir hierarchy.");

        assert_eq!(
            env.copy_exec_to_chroot().unwrap(),
            some_file_name.to_os_string()
        );

        let dest_path = env.chroot_dir.join(some_file_name);
        // Check that `fs::copy()` copied src content and permission bits to destination.
        let metadata_src = fs::metadata(&env.exec_file_path).unwrap();
        let metadata_dest = fs::metadata(&dest_path).unwrap();
        let content_src = fs::read(&env.exec_file_path).unwrap();
        let content_dest = fs::read(&dest_path).unwrap();
        assert_eq!(content_src, content_dest);
        assert_eq!(content_dest, b"some_content");
        assert_eq!(metadata_src.permissions(), metadata_dest.permissions());

        // Clean up the environment.
        fs::remove_dir_all(env.chroot_dir()).expect("Could not remove dir hierarchy.");
    }

    #[test]
    fn test_join_netns() {
        let mut path = "invalid_path";
        assert_eq!(
            format!("{}", Env::join_netns(path).unwrap_err()),
            format!(
                "Failed to open file {}: No such file or directory (os error 2)",
                path
            )
        );

        let tmp_file = TempFile::new().unwrap();
        path = tmp_file.as_path().to_str().unwrap();
        assert_eq!(
            format!("{}", Env::join_netns(path).unwrap_err()),
            "Failed to join network namespace: netns: Invalid argument (os error 22)"
        );

        // Testing `join_netns()` with a valid network namespace is not that easy
        // as Rust std library doesn't offer support for creating such namespaces.
    }

    #[test]
    fn test_cgroups_parsing() {
        let arg_parser = build_arg_parser();
        let good_arg_vals = ArgVals::new();

        // Cases that should fail

        // Check string without "." (no controller)
        let mut args = arg_parser.arguments().clone();
        let invalid_cgroup_arg_vals = ArgVals {
            cgroups: vec!["cpusetcpus=2"],
            ..good_arg_vals.clone()
        };
        args.parse(&make_args(&invalid_cgroup_arg_vals)).unwrap();
        assert!(Env::new(&args, 0, 0).is_err());

        // Check string with multiple "."
        let mut args = arg_parser.arguments().clone();
        let invalid_cgroup_arg_vals = ArgVals {
            cgroups: vec!["cpu.set.cpus=2"],
            ..good_arg_vals.clone()
        };
        args.parse(&make_args(&invalid_cgroup_arg_vals)).unwrap();
        assert!(Env::new(&args, 0, 0).is_err());

        // Check empty string
        let mut args = arg_parser.arguments().clone();
        let invalid_cgroup_arg_vals = ArgVals {
            cgroups: vec![""],
            ..good_arg_vals.clone()
        };
        args.parse(&make_args(&invalid_cgroup_arg_vals)).unwrap();
        assert!(Env::new(&args, 0, 0).is_err());

        // Check valid file empty value
        let mut args = arg_parser.arguments().clone();
        let invalid_cgroup_arg_vals = ArgVals {
            cgroups: vec!["cpuset.cpus="],
            ..good_arg_vals.clone()
        };
        args.parse(&make_args(&invalid_cgroup_arg_vals)).unwrap();
        assert!(Env::new(&args, 0, 0).is_err());

        // Check valid file no value
        let mut args = arg_parser.arguments().clone();
        let invalid_cgroup_arg_vals = ArgVals {
            cgroups: vec!["cpuset.cpus"],
            ..good_arg_vals.clone()
        };
        args.parse(&make_args(&invalid_cgroup_arg_vals)).unwrap();
        assert!(Env::new(&args, 0, 0).is_err());

        // Cases that should success

        // Check value with special characters (',', '.', '-')
        let mut args = arg_parser.arguments().clone();
        let invalid_cgroup_arg_vals = ArgVals {
            cgroups: vec!["cpuset.cpus=2-4,5.3"],
            ..good_arg_vals.clone()
        };
        args.parse(&make_args(&invalid_cgroup_arg_vals)).unwrap();
        assert!(Env::new(&args, 0, 0).is_ok());

        // Check valid case
        let mut args = arg_parser.arguments().clone();
        let invalid_cgroup_arg_vals = ArgVals {
            cgroups: vec!["cpuset.cpus=2"],
            ..good_arg_vals.clone()
        };
        args.parse(&make_args(&invalid_cgroup_arg_vals)).unwrap();
        assert!(Env::new(&args, 0, 0).is_ok());
    }
}
