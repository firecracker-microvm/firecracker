// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::CStr;
use std::fs::{self, canonicalize, File};
use std::os::unix::io::IntoRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use clap::ArgMatches;
use libc;

use cgroup::Cgroup;
use chroot::chroot;
use fc_util::validators;
use sys_util::SyscallReturnCode;
use {Error, Result};

const STDIN_FILENO: libc::c_int = 0;
const STDOUT_FILENO: libc::c_int = 1;
const STDERR_FILENO: libc::c_int = 2;

const DEV_KVM_WITH_NUL: &[u8] = b"/dev/kvm\0";
const DEV_NET_TUN_WITH_NUL: &[u8] = b"/dev/net/tun\0";
const DEV_NULL_WITH_NUL: &[u8] = b"/dev/null\0";
const ROOT_PATH_WITH_NUL: &[u8] = b"/\0";

// Helper function, since we'll use libc::dup2 a bunch of times for daemonization.
fn dup2(old_fd: libc::c_int, new_fd: libc::c_int) -> Result<()> {
    // This is safe because we are using a library function with valid parameters.
    SyscallReturnCode(unsafe { libc::dup2(old_fd, new_fd) })
        .into_empty_result()
        .map_err(Error::Dup2)
}

// Extracts an argument's value or returns a specific error if the argument is missing.
fn get_value<'a>(args: &'a ArgMatches, arg_name: &'static str) -> Result<&'a str> {
    args.value_of(arg_name)
        .ok_or_else(|| Error::MissingArgument(&arg_name))
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
    seccomp_level: u32,
    start_time_us: u64,
    start_time_cpu_us: u64,
}

impl Env {
    pub fn new(args: ArgMatches, start_time_us: u64, start_time_cpu_us: u64) -> Result<Self> {
        // All arguments are either mandatory, or have default values, so the unwraps
        // should not fail.
        let id = get_value(&args, "id")?;

        validators::validate_instance_id(id).map_err(Error::InvalidInstanceId)?;

        let numa_node_str = get_value(&args, "numa_node")?;
        let numa_node = numa_node_str
            .parse::<u32>()
            .map_err(|_| Error::NumaNode(String::from(numa_node_str)))?;

        let exec_file = get_value(&args, "exec_file")?;
        let exec_file_path = canonicalize(exec_file)
            .map_err(|e| Error::Canonicalize(PathBuf::from(exec_file), e))?;

        if !exec_file_path.is_file() {
            return Err(Error::NotAFile(exec_file_path));
        }

        let chroot_base = get_value(&args, "chroot_base")?;

        let mut chroot_dir = canonicalize(chroot_base)
            .map_err(|e| Error::Canonicalize(PathBuf::from(chroot_base), e))?;

        chroot_dir.push(
            exec_file_path
                .file_name()
                .ok_or_else(|| Error::FileName(exec_file_path.clone()))?,
        );
        chroot_dir.push(id);
        chroot_dir.push("root");

        let uid_str = get_value(&args, "uid")?;
        let uid = uid_str
            .parse::<u32>()
            .map_err(|_| Error::Uid(String::from(uid_str)))?;

        let gid_str = get_value(&args, "gid")?;
        let gid = gid_str
            .parse::<u32>()
            .map_err(|_| Error::Gid(String::from(gid_str)))?;

        let netns = match args.value_of("netns") {
            Some(s) => Some(String::from(s)),
            None => None,
        };

        let daemonize = args.is_present("daemonize");

        // The value of the argument can be safely unwrapped, because a default value was specified.
        // It can be parsed into an unsigned integer since its possible values were specified and
        // they are all unsigned integers.
        let seccomp_level = get_value(&args, "seccomp-level")?
            .parse::<u32>()
            .map_err(Error::SeccompLevel)?;

        Ok(Env {
            id: id.to_string(),
            numa_node,
            chroot_dir,
            exec_file_path,
            uid,
            gid,
            netns,
            daemonize,
            seccomp_level,
            start_time_us,
            start_time_cpu_us,
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
        let dev_path = CStr::from_bytes_with_nul(dev_path_str)
            .map_err(|_| Error::FromBytesWithNul(dev_path_str))?;
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
            .map_err(|e| Error::ChangeFileOwner(e, std::str::from_utf8(dev_path_str).unwrap()))
    }

    pub fn run(mut self, socket_file_name: &str) -> Result<()> {
        // We need to create the equivalent of /dev/net inside the jail.
        self.chroot_dir.push("dev/net");

        // Create the folder tree.
        // TODO: the final part of chroot_dir ("<id>/root") should not exist, if the id is never
        // reused. Is this a reasonable assumption? Should we check for this and return an error?
        // If we choose to do that here, we should extend the same extra functionality to the Cgroup
        // module, where we also create a folder hierarchy which depends on the id.
        fs::create_dir_all(&self.chroot_dir)
            .map_err(|e| Error::CreateDir(self.chroot_dir.clone(), e))?;

        // Pop dev/net.
        self.chroot_dir.pop();
        self.chroot_dir.pop();

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

        // Change ownership of the jail root to Firecracker's UID and GID. This is necessary
        // so Firecracker can create the unix domain socket in its own jail.
        let jail_root_path = CStr::from_bytes_with_nul(ROOT_PATH_WITH_NUL)
            .map_err(|_| Error::FromBytesWithNul(ROOT_PATH_WITH_NUL))?;
        SyscallReturnCode(unsafe { libc::chown(jail_root_path.as_ptr(), self.uid(), self.gid()) })
            .into_empty_result()
            .map_err(|e| {
                Error::ChangeFileOwner(e, std::str::from_utf8(ROOT_PATH_WITH_NUL).unwrap())
            })?;

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
                .arg(format!("--id={}", self.id))
                .arg(format!("--seccomp-level={}", self.seccomp_level))
                .arg(format!("--start-time-us={}", self.start_time_us))
                .arg(format!("--start-time-cpu-us={}", self.start_time_cpu_us))
                .arg(format!("--api-sock=/{}", socket_file_name))
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .uid(self.uid())
                .gid(self.gid())
                .exec(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use clap_app;

    #[allow(clippy::too_many_arguments)]
    fn make_args<'a>(
        node: &str,
        id: &str,
        exec_file: &str,
        uid: &str,
        gid: &str,
        chroot_base: &str,
        netns: Option<&str>,
        daemonize: bool,
    ) -> ArgMatches<'a> {
        let app = clap_app();

        let mut arg_vec = vec![
            "jailer",
            "--node",
            node,
            "--id",
            id,
            "--exec-file",
            exec_file,
            "--uid",
            uid,
            "--gid",
            gid,
            "--chroot-base-dir",
            chroot_base,
        ];

        if let Some(s) = netns {
            arg_vec.push("--netns");
            arg_vec.push(s);
        }

        if daemonize {
            arg_vec.push("--daemonize");
        }

        app.get_matches_from_safe(arg_vec).unwrap()
    }

    #[test]
    fn test_new_env() {
        let node = "1";
        let id = "bd65600d-8669-4903-8a14-af88203add38";
        let exec_file = "/proc/cpuinfo";
        let uid = "1001";
        let gid = "1002";
        let chroot_base = "/";
        let netns = "zzzns";

        // This should be fine.
        let good_env = Env::new(
            make_args(
                node,
                id,
                exec_file,
                uid,
                gid,
                chroot_base,
                Some(netns),
                true,
            ),
            0,
            0,
        )
        .expect("This new environment should be created successfully.");

        let mut chroot_dir = PathBuf::from(chroot_base);
        chroot_dir.push(Path::new(exec_file).file_name().unwrap());
        chroot_dir.push(id);
        chroot_dir.push("root");

        assert_eq!(good_env.chroot_dir(), chroot_dir);
        assert_eq!(format!("{}", good_env.gid()), gid);
        assert_eq!(format!("{}", good_env.uid()), uid);
        assert_eq!(good_env.netns, Some(netns.to_string()));
        assert!(good_env.daemonize);

        let another_good_env = Env::new(
            make_args(node, id, exec_file, uid, gid, chroot_base, None, false),
            0,
            0,
        )
        .expect("This another new environment should be created successfully.");
        assert!(!another_good_env.daemonize);

        // Not fine - invalid node.
        assert!(Env::new(
            make_args("zzz", id, exec_file, uid, gid, chroot_base, None, true),
            0,
            0,
        )
        .is_err());

        // Not fine - invalid id.
        assert!(Env::new(
            make_args(
                node,
                "/ad./sa12",
                exec_file,
                uid,
                gid,
                chroot_base,
                None,
                true
            ),
            0,
            0
        )
        .is_err());

        // Not fine - inexistent (hopefully) exec_file.
        assert!(Env::new(
            make_args(
                node,
                id,
                "/this!/file!/should!/not!/exist!/",
                uid,
                gid,
                chroot_base,
                None,
                true
            ),
            0,
            0
        )
        .is_err());

        // Not fine - invalid uid.
        assert!(Env::new(
            make_args(node, id, exec_file, "zzz", gid, chroot_base, None, true),
            0,
            0
        )
        .is_err());

        // Not fine - invalid gid.
        assert!(Env::new(
            make_args(node, id, exec_file, uid, "zzz", chroot_base, None, true),
            0,
            0
        )
        .is_err());

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
}
