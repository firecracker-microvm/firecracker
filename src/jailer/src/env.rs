// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::{CStr, CString, OsString};
use std::fs::{self, File, OpenOptions, Permissions, canonicalize, read_to_string};
use std::io;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio, exit, id};

use utils::arg_parser::UtilsArgParserError::MissingValue;
use utils::time::{ClockType, get_time_us};
use utils::{arg_parser, validators};
use vmm_sys_util::syscall::SyscallReturnCode;

use crate::JailerError;
use crate::cgroup::{CgroupConfiguration, CgroupConfigurationBuilder};
use crate::chroot::chroot;
use crate::resource_limits::{FSIZE_ARG, NO_FILE_ARG, ResourceLimits};

pub const PROC_MOUNTS: &str = "/proc/mounts";

const STDIN_FILENO: libc::c_int = 0;
const STDOUT_FILENO: libc::c_int = 1;
const STDERR_FILENO: libc::c_int = 2;

// Kernel-based virtual machine (hardware virtualization extensions)
// minor/major numbers are taken from
// https://www.kernel.org/doc/html/latest/admin-guide/devices.html
const DEV_KVM: &CStr = c"/dev/kvm";
const DEV_KVM_MAJOR: u32 = 10;
const DEV_KVM_MINOR: u32 = 232;

// TUN/TAP device minor/major numbers are taken from
// www.kernel.org/doc/Documentation/networking/tuntap.txt
const DEV_NET_TUN: &CStr = c"/dev/net/tun";
const DEV_NET_TUN_MAJOR: u32 = 10;
const DEV_NET_TUN_MINOR: u32 = 200;

// Random number generator device minor/major numbers are taken from
// https://www.kernel.org/doc/Documentation/admin-guide/devices.txt
const DEV_URANDOM: &CStr = c"/dev/urandom";
const DEV_URANDOM_MAJOR: u32 = 1;
const DEV_URANDOM_MINOR: u32 = 9;

// Userfault file descriptor device path. This is a misc character device
// with a MISC_DYNAMIC_MINOR minor device:
// https://elixir.bootlin.com/linux/v6.1.51/source/fs/userfaultfd.c#L2176.
//
// This means that its minor device number will be allocated at run time,
// so we will have to find it at initialization time parsing /proc/misc.
// What we do know is the major number for misc devices:
// https://elixir.bootlin.com/linux/v6.1.51/source/Documentation/admin-guide/devices.txt
const DEV_UFFD_PATH: &CStr = c"/dev/userfaultfd";
const DEV_UFFD_MAJOR: u32 = 10;

// Relevant folders inside the jail that we create or/and for which we change ownership.
// We need /dev in order to be able to create /dev/kvm and /dev/net/tun device.
// We need /run for the default location of the api socket.
// Since libc::chown is not recursive, we cannot specify only /dev/net as we want
// to walk through the entire folder hierarchy.
const FOLDER_HIERARCHY: [&str; 4] = ["/", "/dev", "/dev/net", "/run"];
const FOLDER_PERMISSIONS: u32 = 0o700;

// When running with `--new-pid-ns` flag, the PID of the process running the exec_file differs
// from jailer's and it is stored inside a dedicated file, prefixed with the below extension.
const PID_FILE_EXTENSION: &str = ".pid";

// Helper function, since we'll use libc::dup2 a bunch of times for daemonization.
fn dup2(old_fd: libc::c_int, new_fd: libc::c_int) -> Result<(), JailerError> {
    // SAFETY: This is safe because we are using a library function with valid parameters.
    SyscallReturnCode(unsafe { libc::dup2(old_fd, new_fd) })
        .into_empty_result()
        .map_err(JailerError::Dup2)
}

// This is a wrapper for the clone system call. When we want to create a new process in a new
// pid namespace, we will call clone with a NULL stack pointer. We can do this because we will
// not use the CLONE_VM flag, this will result with the original stack replicated, in a similar
// manner to the fork syscall. The libc wrapper prevents use of a NULL stack pointer, so we will
// call the syscall directly.
fn clone(child_stack: *mut libc::c_void, flags: libc::c_int) -> Result<libc::c_int, JailerError> {
    SyscallReturnCode(
        // SAFETY: This is safe because we are using a library function with valid parameters.
        libc::c_int::try_from(unsafe {
            // Note: the order of arguments in the raw syscall differs between platforms.
            // On x86-64, for example, the parameters passed are `flags`, `stack`, `parent_tid`,
            // `child_tid`, and `tls`. But on On x86-32, and several other common architectures
            // (including score, ARM, ARM 64) the order of the last two arguments is reversed,
            // and instead we must pass `flags`, `stack`, `parent_tid`, `tls`, and `child_tid`.
            // This difference in architecture currently doesn't matter because the last 2
            // arguments are all 0 but if this were to change we should add an attribute such as
            // #[cfg(target_arch = "x86_64")] or #[cfg(target_arch = "aarch64")] for each different
            // call.
            libc::syscall(libc::SYS_clone, flags, child_stack, 0, 0, 0)
        })
        // Unwrap is needed because PIDs are 32-bit.
        .unwrap(),
    )
    .into_result()
    .map_err(JailerError::Clone)
}

#[derive(Debug, thiserror::Error)]
enum UserfaultfdParseError {
    #[error("Could not read /proc/misc: {0}")]
    ReadProcMisc(#[from] std::io::Error),
    #[error("Could not parse minor number: {0}")]
    ParseDevMinor(#[from] std::num::ParseIntError),
    #[error("userfaultfd device not loaded")]
    NotFound,
}

#[derive(Debug)]
pub struct Env {
    id: String,
    chroot_dir: PathBuf,
    exec_file_path: PathBuf,
    uid: u32,
    gid: u32,
    netns: Option<String>,
    daemonize: bool,
    new_pid_ns: bool,
    start_time_us: u64,
    start_time_cpu_us: u64,
    jailer_cpu_time_us: u64,
    extra_args: Vec<String>,
    cgroup_conf: Option<CgroupConfiguration>,
    resource_limits: ResourceLimits,
    uffd_dev_minor: Option<u32>,
}

impl Env {
    pub fn new(
        arguments: &arg_parser::Arguments,
        start_time_us: u64,
        start_time_cpu_us: u64,
        proc_mounts: &str,
    ) -> Result<Self, JailerError> {
        // Unwraps should not fail because the arguments are mandatory arguments or with default
        // values.
        let id = arguments
            .single_value("id")
            .ok_or_else(|| JailerError::ArgumentParsing(MissingValue("id".to_string())))?;

        validators::validate_instance_id(id).map_err(JailerError::InvalidInstanceId)?;

        let exec_file = arguments
            .single_value("exec-file")
            .ok_or_else(|| JailerError::ArgumentParsing(MissingValue("exec-file".to_string())))?;
        let (exec_file_path, exec_file_name) = Env::validate_exec_file(exec_file)?;

        let chroot_base = arguments.single_value("chroot-base-dir").ok_or_else(|| {
            JailerError::ArgumentParsing(MissingValue("chroot-base-dir".to_string()))
        })?;
        let mut chroot_dir = canonicalize(chroot_base)
            .map_err(|err| JailerError::Canonicalize(PathBuf::from(&chroot_base), err))?;

        if !chroot_dir.is_dir() {
            return Err(JailerError::NotADirectory(chroot_dir));
        }

        chroot_dir.push(&exec_file_name);
        chroot_dir.push(id);
        chroot_dir.push("root");

        let uid_str = arguments
            .single_value("uid")
            .ok_or_else(|| JailerError::ArgumentParsing(MissingValue("uid".to_string())))?;
        let uid = uid_str
            .parse::<u32>()
            .map_err(|_| JailerError::Uid(uid_str.to_owned()))?;

        let gid_str = arguments
            .single_value("gid")
            .ok_or_else(|| JailerError::ArgumentParsing(MissingValue("gid".to_string())))?;
        let gid = gid_str
            .parse::<u32>()
            .map_err(|_| JailerError::Gid(gid_str.to_owned()))?;

        let netns = arguments.single_value("netns").cloned();

        let daemonize = arguments.flag_present("daemonize");

        let new_pid_ns = arguments.flag_present("new-pid-ns");

        // Optional arguments.
        let mut cgroup_conf = None;
        let parent_cgroup = match arguments.single_value("parent-cgroup") {
            Some(parent_cg) => Path::new(parent_cg),
            None => Path::new(&exec_file_name),
        };
        if parent_cgroup
            .components()
            .any(|c| c == Component::CurDir || c == Component::ParentDir || c == Component::RootDir)
        {
            return Err(JailerError::CgroupInvalidParentPath());
        }

        let cgroup_ver = arguments.single_value("cgroup-version").ok_or_else(|| {
            JailerError::ArgumentParsing(MissingValue("cgroup-version".to_string()))
        })?;
        let cgroup_ver = cgroup_ver
            .parse::<u8>()
            .map_err(|_| JailerError::CgroupInvalidVersion(cgroup_ver.to_string()))?;

        let cgroups_args: &[String] = arguments.multiple_values("cgroup").unwrap_or_default();

        // If the --parent-cgroup exists, and we have no other cgroups,
        // then the intent is to move the process to that cgroup.
        // Only applies to cgroupsv2 since it's a unified hierarchy
        if cgroups_args.is_empty() && cgroup_ver == 2 {
            let builder = CgroupConfigurationBuilder::new(cgroup_ver, proc_mounts)?;
            let cg_parent = builder.get_v2_hierarchy_path()?.join(parent_cgroup);
            let cg_parent_procs = cg_parent.join("cgroup.procs");
            if cg_parent.exists() {
                fs::write(cg_parent_procs, std::process::id().to_string())
                    .map_err(|_| JailerError::CgroupWrite(io::Error::last_os_error()))?;
            }
        }

        // cgroup format: <cgroup_controller>.<cgroup_property>=<value>,...
        if let Some(cgroups_args) = arguments.multiple_values("cgroup") {
            let mut builder = CgroupConfigurationBuilder::new(cgroup_ver, proc_mounts)?;
            for cg in cgroups_args {
                let aux: Vec<&str> = cg.split('=').collect();
                if aux.len() != 2 || aux[1].is_empty() {
                    return Err(JailerError::CgroupFormat(cg.to_string()));
                }
                let file = Path::new(aux[0]);
                if file.components().any(|c| {
                    c == Component::CurDir || c == Component::ParentDir || c == Component::RootDir
                }) {
                    return Err(JailerError::CgroupInvalidFile(cg.to_string()));
                }

                builder.add_cgroup_property(
                    aux[0].to_string(), // cgroup file
                    aux[1].to_string(), // cgroup value
                    id,
                    parent_cgroup,
                )?;
            }
            cgroup_conf = Some(builder.build());
        }

        let mut resource_limits = ResourceLimits::default();
        if let Some(args) = arguments.multiple_values("resource-limit") {
            Env::parse_resource_limits(&mut resource_limits, args)?;
        }

        let uffd_dev_minor = Self::get_userfaultfd_minor_dev_number().ok();

        Ok(Env {
            id: id.to_owned(),
            chroot_dir,
            exec_file_path,
            uid,
            gid,
            netns,
            daemonize,
            new_pid_ns,
            start_time_us,
            start_time_cpu_us,
            jailer_cpu_time_us: 0,
            extra_args: arguments.extra_args(),
            cgroup_conf,
            resource_limits,
            uffd_dev_minor,
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

    fn validate_exec_file(exec_file: &str) -> Result<(PathBuf, String), JailerError> {
        let exec_file_path = canonicalize(exec_file)
            .map_err(|err| JailerError::Canonicalize(PathBuf::from(exec_file), err))?;

        if !exec_file_path.is_file() {
            return Err(JailerError::NotAFile(exec_file_path));
        }

        let exec_file_name = exec_file_path
            .file_name()
            .ok_or_else(|| JailerError::ExtractFileName(exec_file_path.clone()))?
            .to_str()
            // Safe to unwrap as the original `exec_file` is `String`.
            .unwrap()
            .to_string();

        if !exec_file_name.contains("firecracker") {
            return Err(JailerError::ExecFileName(exec_file_name));
        }

        Ok((exec_file_path, exec_file_name))
    }

    fn parse_resource_limits(
        resource_limits: &mut ResourceLimits,
        args: &[String],
    ) -> Result<(), JailerError> {
        for arg in args {
            let (name, value) = arg
                .split_once('=')
                .ok_or_else(|| JailerError::ResLimitFormat(arg.to_string()))?;

            let limit_value = value
                .parse::<u64>()
                .map_err(|err| JailerError::ResLimitValue(value.to_string(), err.to_string()))?;
            match name {
                FSIZE_ARG => resource_limits.set_file_size(limit_value),
                NO_FILE_ARG => resource_limits.set_no_file(limit_value),
                _ => return Err(JailerError::ResLimitArgument(name.to_string())),
            }
        }
        Ok(())
    }

    fn exec_into_new_pid_ns(&mut self, chroot_exec_file: PathBuf) -> Result<(), JailerError> {
        // https://man7.org/linux/man-pages/man7/pid_namespaces.7.html
        // > a process in an ancestor namespace can send signals to the "init" process of a child
        // > PID namespace only if the "init" process has established a handler for that signal.
        //
        // Firecracker (i.e. the "init" process of the new PID namespace) sets up handlers for some
        // signals including SIGHUP and jailer exits soon after spawning firecracker into a new PID
        // namespace. If the jailer process is a session leader and its exit happens after
        // firecracker configures the signal handlers, SIGHUP will be sent to firecracker and be
        // caught by the handler unexpectedly.
        //
        // In order to avoid the above issue, if jailer is a session leader, creates a new session
        // and makes the child process (i.e. firecracker) become the leader of the new session to
        // not get SIGHUP on the exit of jailer.

        // Check whether jailer is a session leader or not before clone().
        // Note that, if `--daemonize` is passed, jailer is always not a session leader. This is
        // because we use the double fork method, making itself not a session leader.
        let is_session_leader = match self.daemonize {
            true => false,
            false => {
                // SAFETY: Safe because it doesn't take any input parameters.
                let sid = SyscallReturnCode(unsafe { libc::getsid(0) })
                    .into_result()
                    .map_err(JailerError::GetSid)?;
                // SAFETY: Safe because it doesn't take any input parameters.
                let ppid = SyscallReturnCode(unsafe { libc::getpid() })
                    .into_result()
                    .map_err(JailerError::GetPid)?;
                sid == ppid
            }
        };

        // Duplicate the current process. The child process will belong to the previously created
        // PID namespace. The current process will not be moved into the newly created namespace,
        // but its first child will assume the role of init(1) in the new namespace.
        let pid = clone(std::ptr::null_mut(), libc::CLONE_NEWPID)?;
        match pid {
            0 => {
                if is_session_leader {
                    // SAFETY: Safe bacause it doesn't take any input parameters.
                    SyscallReturnCode(unsafe { libc::setsid() })
                        .into_empty_result()
                        .map_err(JailerError::SetSid)?;
                }
                Err(JailerError::Exec(self.exec_command(chroot_exec_file)))
            }
            child_pid => {
                // Save the PID of the process running the exec file provided
                // inside <chroot_exec_file>.pid file.
                self.save_exec_file_pid(child_pid, chroot_exec_file)?;
                // SAFETY: This is safe because 0 is valid input to exit.
                unsafe { libc::exit(0) }
            }
        }
    }

    fn save_exec_file_pid(
        &mut self,
        pid: i32,
        chroot_exec_file: PathBuf,
    ) -> Result<(), JailerError> {
        let chroot_exec_file_str = chroot_exec_file
            .to_str()
            .ok_or_else(|| JailerError::ExtractFileName(chroot_exec_file.clone()))?;
        let pid_file_path =
            PathBuf::from(format!("{}{}", chroot_exec_file_str, PID_FILE_EXTENSION));
        let mut pid_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(pid_file_path.clone())
            .map_err(|err| JailerError::FileOpen(pid_file_path.clone(), err))?;

        // Write PID to file.
        write!(pid_file, "{}", pid).map_err(|err| JailerError::Write(pid_file_path, err))
    }

    fn get_userfaultfd_minor_dev_number() -> Result<u32, UserfaultfdParseError> {
        let buf = read_to_string("/proc/misc")?;

        for line in buf.lines() {
            let dev: Vec<&str> = line.split(' ').collect();
            if dev.len() < 2 {
                continue;
            }

            if dev[1] == "userfaultfd" {
                return Ok(dev[0].parse::<u32>()?);
            }
        }

        Err(UserfaultfdParseError::NotFound)
    }

    fn mknod_and_own_dev(
        &self,
        dev_path: &CStr,
        dev_major: u32,
        dev_minor: u32,
    ) -> Result<(), JailerError> {
        // As per sysstat.h:
        // S_IFCHR -> character special device
        // S_IRUSR -> read permission, owner
        // S_IWUSR -> write permission, owner
        // See www.kernel.org/doc/Documentation/networking/tuntap.txt, 'Configuration' chapter for
        // more clarity.
        // SAFETY: This is safe because dev_path is CStr, and hence null-terminated.
        SyscallReturnCode(unsafe {
            libc::mknod(
                dev_path.as_ptr(),
                libc::S_IFCHR | libc::S_IRUSR | libc::S_IWUSR,
                libc::makedev(dev_major, dev_minor),
            )
        })
        .into_empty_result()
        .map_err(|err| JailerError::MknodDev(err, dev_path.to_str().unwrap().to_owned()))?;

        // SAFETY: This is safe because dev_path is CStr, and hence null-terminated.
        SyscallReturnCode(unsafe { libc::chown(dev_path.as_ptr(), self.uid(), self.gid()) })
            .into_empty_result()
            // Safe to unwrap as we provided valid file names.
            .map_err(|err| {
                JailerError::ChangeFileOwner(PathBuf::from(dev_path.to_str().unwrap()), err)
            })
    }

    fn setup_jailed_folder(&self, folder: impl AsRef<Path>) -> Result<(), JailerError> {
        let folder_path = folder.as_ref();
        fs::create_dir_all(folder_path)
            .map_err(|err| JailerError::CreateDir(folder_path.to_owned(), err))?;
        fs::set_permissions(folder_path, Permissions::from_mode(FOLDER_PERMISSIONS))
            .map_err(|err| JailerError::Chmod(folder_path.to_owned(), err))?;

        let c_path = CString::new(folder_path.to_str().unwrap()).unwrap();
        // SAFETY: This is safe because folder was checked for a null-terminator.
        SyscallReturnCode(unsafe { libc::chown(c_path.as_ptr(), self.uid(), self.gid()) })
            .into_empty_result()
            .map_err(|err| JailerError::ChangeFileOwner(folder_path.to_owned(), err))
    }

    fn copy_exec_to_chroot(&mut self) -> Result<OsString, JailerError> {
        let exec_file_name = self
            .exec_file_path
            .file_name()
            .ok_or_else(|| JailerError::ExtractFileName(self.exec_file_path.clone()))?;
        let jailer_exec_file_path = self.chroot_dir.join(exec_file_name);

        // We do a copy instead of a hard-link for 2 reasons
        // 1. hard-linking is not possible if the file is in another device
        // 2. while hardlinking would save up disk space and also memory by sharing parts of the
        //    Firecracker binary (like the executable .text section), this latter part is not
        //    desirable in Firecracker's threat model. Copying prevents 2 Firecracker processes from
        //    sharing memory.
        fs::copy(&self.exec_file_path, &jailer_exec_file_path).map_err(|err| {
            JailerError::Copy(
                self.exec_file_path.clone(),
                jailer_exec_file_path.clone(),
                err,
            )
        })?;

        Ok(exec_file_name.to_owned())
    }

    fn join_netns(path: &str) -> Result<(), JailerError> {
        // The fd backing the file will be automatically dropped at the end of the scope
        let netns =
            File::open(path).map_err(|err| JailerError::FileOpen(PathBuf::from(path), err))?;

        // SAFETY: Safe because we are passing valid parameters.
        SyscallReturnCode(unsafe { libc::setns(netns.as_raw_fd(), libc::CLONE_NEWNET) })
            .into_empty_result()
            .map_err(JailerError::SetNetNs)
    }

    fn exec_command(&self, chroot_exec_file: PathBuf) -> io::Error {
        Command::new(chroot_exec_file)
            .args(["--id", &self.id])
            .args(["--start-time-us", &self.start_time_us.to_string()])
            .args([
                "--start-time-cpu-us",
                &get_time_us(ClockType::ProcessCpu).to_string(),
            ])
            .args(["--parent-cpu-time-us", &self.jailer_cpu_time_us.to_string()])
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .uid(self.uid())
            .gid(self.gid())
            .args(&self.extra_args)
            .exec()
    }

    #[cfg(target_arch = "aarch64")]
    fn copy_cache_info(&self) -> Result<(), JailerError> {
        use crate::{readln_special, to_cstring, writeln_special};

        const HOST_CACHE_INFO: &str = "/sys/devices/system/cpu/cpu0/cache";
        // Based on https://elixir.free-electrons.com/linux/v4.9.62/source/arch/arm64/kernel/cacheinfo.c#L29.
        const MAX_CACHE_LEVEL: u8 = 7;
        // These are the files that we need to copy in the chroot so that we can create the
        // cache topology.
        const FOLDER_HIERARCHY: [&str; 6] = [
            "size",
            "level",
            "type",
            "shared_cpu_map",
            "coherency_line_size",
            "number_of_sets",
        ];

        // We create the cache folder inside the chroot and then change its permissions.
        let jailer_cache_dir =
            Path::new(self.chroot_dir()).join("sys/devices/system/cpu/cpu0/cache/");
        fs::create_dir_all(&jailer_cache_dir)
            .map_err(|err| JailerError::CreateDir(jailer_cache_dir.to_owned(), err))?;

        for index in 0..(MAX_CACHE_LEVEL + 1) {
            let index_folder = format!("index{}", index);
            let host_path = PathBuf::from(HOST_CACHE_INFO).join(&index_folder);

            if fs::metadata(&host_path).is_err() {
                // It means the folder does not exist, i.e we exhausted the number of cache levels
                // existent on the host.
                break;
            }

            // We now create the destination folder in the jailer.
            let jailer_path = jailer_cache_dir.join(&index_folder);
            fs::create_dir_all(&jailer_path)
                .map_err(|err| JailerError::CreateDir(jailer_path.to_owned(), err))?;

            // We now read the contents of the current directory and copy the files we are
            // interested in to the destination path.
            for entry in FOLDER_HIERARCHY.iter() {
                let host_cache_file = host_path.join(entry);
                let jailer_cache_file = jailer_path.join(entry);

                if let Ok(line) = readln_special(&host_cache_file) {
                    writeln_special(&jailer_cache_file, line)?;

                    // We now change the permissions.
                    let dest_path_cstr = to_cstring(&jailer_cache_file)?;
                    // SAFETY: Safe because dest_path_cstr is null-terminated.
                    SyscallReturnCode(unsafe {
                        libc::chown(dest_path_cstr.as_ptr(), self.uid(), self.gid())
                    })
                    .into_empty_result()
                    .map_err(|err| {
                        JailerError::ChangeFileOwner(jailer_cache_file.to_owned(), err)
                    })?;
                }
            }
        }
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn copy_midr_el1_info(&self) -> Result<(), JailerError> {
        use crate::{readln_special, to_cstring, writeln_special};

        const HOST_MIDR_EL1_INFO: &str = "/sys/devices/system/cpu/cpu0/regs/identification";

        let jailer_midr_el1_directory =
            Path::new(self.chroot_dir()).join("sys/devices/system/cpu/cpu0/regs/identification/");
        fs::create_dir_all(&jailer_midr_el1_directory)
            .map_err(|err| JailerError::CreateDir(jailer_midr_el1_directory.to_owned(), err))?;

        let host_midr_el1_file = PathBuf::from(format!("{}/midr_el1", HOST_MIDR_EL1_INFO));
        let jailer_midr_el1_file = jailer_midr_el1_directory.join("midr_el1");

        // Read and copy the MIDR_EL1 file to Jailer
        let line = readln_special(&host_midr_el1_file)?;
        writeln_special(&jailer_midr_el1_file, line)?;

        // Change the permissions.
        let dest_path_cstr = to_cstring(&jailer_midr_el1_file)?;
        // SAFETY: Safe because `dest_path_cstr` is null-terminated.
        SyscallReturnCode(unsafe { libc::chown(dest_path_cstr.as_ptr(), self.uid(), self.gid()) })
            .into_empty_result()
            .map_err(|err| JailerError::ChangeFileOwner(jailer_midr_el1_file.to_owned(), err))?;

        Ok(())
    }

    pub fn run(mut self) -> Result<(), JailerError> {
        let exec_file_name = self.copy_exec_to_chroot()?;
        let chroot_exec_file = PathBuf::from("/").join(exec_file_name);

        // Join the specified network namespace, if applicable.
        if let Some(ref path) = self.netns {
            Env::join_netns(path)?;
        }

        // Set limits on resources.
        self.resource_limits.install()?;

        // We have to setup cgroups at this point, because we can't do it anymore after chrooting.
        if let Some(ref conf) = self.cgroup_conf {
            conf.setup()?;
        }

        // If daemonization was requested, open /dev/null before chrooting.
        let dev_null = if self.daemonize {
            Some(File::open("/dev/null").map_err(JailerError::OpenDevNull)?)
        } else {
            None
        };
        #[cfg(target_arch = "aarch64")]
        self.copy_cache_info()?;
        #[cfg(target_arch = "aarch64")]
        self.copy_midr_el1_info()?;

        // Jail self.
        chroot(self.chroot_dir())?;

        // This will not only create necessary directories, but will also change ownership
        // for all of them.
        FOLDER_HIERARCHY
            .iter()
            .try_for_each(|f| self.setup_jailed_folder(f))?;

        // Here we are creating the /dev/kvm and /dev/net/tun devices inside the jailer.
        // Following commands can be translated into bash like this:
        // $: mkdir -p $chroot_dir/dev/net
        // $: dev_net_tun_path={$chroot_dir}/"tun"
        // $: mknod $dev_net_tun_path c 10 200
        // www.kernel.org/doc/Documentation/networking/tuntap.txt specifies 10 and 200 as the major
        // and minor for the /dev/net/tun device.
        self.mknod_and_own_dev(DEV_NET_TUN, DEV_NET_TUN_MAJOR, DEV_NET_TUN_MINOR)?;
        // Do the same for /dev/kvm with (major, minor) = (10, 232).
        self.mknod_and_own_dev(DEV_KVM, DEV_KVM_MAJOR, DEV_KVM_MINOR)?;
        // And for /dev/urandom with (major, minor) = (1, 9).
        // If the device is not accessible on the host, output a warning to inform user that MMDS
        // version 2 will not be available to use.
        let _ = self
            .mknod_and_own_dev(DEV_URANDOM, DEV_URANDOM_MAJOR, DEV_URANDOM_MINOR)
            .map_err(|err| {
                println!(
                    "Warning! Could not create /dev/urandom device inside jailer: {}.",
                    err
                );
                println!("MMDS version 2 will not be available to use.");
            });

        // If we have a minor version for /dev/userfaultfd the device is present on the host.
        // Expose the device in the jailed environment.
        if let Some(minor) = self.uffd_dev_minor {
            self.mknod_and_own_dev(DEV_UFFD_PATH, DEV_UFFD_MAJOR, minor)?;
        }

        self.jailer_cpu_time_us = get_time_us(ClockType::ProcessCpu) - self.start_time_cpu_us;

        // Daemonize before exec, if so required (when the dev_null variable != None).
        if let Some(dev_null) = dev_null {
            // We follow the double fork method to daemonize the jailer referring to
            // https://0xjet.github.io/3OHA/2022/04/11/post.html
            // setsid() will fail if the calling process is a process group leader.
            // By calling fork(), we guarantee that the newly created process inherits
            // the PGID from its parent and, therefore, is not a process group leader.
            // SAFETY: Safe because it's a library function.
            let child_pid = unsafe { libc::fork() };
            if child_pid < 0 {
                return Err(JailerError::Daemonize(io::Error::last_os_error()));
            }

            if child_pid != 0 {
                // parent exiting
                exit(0);
            }

            // Call setsid() in child
            // SAFETY: Safe because it's a library function.
            SyscallReturnCode(unsafe { libc::setsid() })
                .into_empty_result()
                .map_err(JailerError::SetSid)?;

            // Meter CPU usage after first fork()
            self.jailer_cpu_time_us += get_time_us(ClockType::ProcessCpu);

            // Daemons should not have controlling terminals.
            // If a daemon has a controlling terminal, it can receive signals
            // from it that might cause it to halt or exit unexpectedly.
            // The second fork() ensures that grandchild is not a session,
            // leader and thus cannot reacquire a controlling terminal.
            // SAFETY: Safe because it's a library function.
            let grandchild_pid = unsafe { libc::fork() };
            if grandchild_pid < 0 {
                return Err(JailerError::Daemonize(io::Error::last_os_error()));
            }

            if grandchild_pid != 0 {
                // child exiting
                exit(0);
            }

            // grandchild is the daemon
            // Replace the stdio file descriptors with the /dev/null fd.
            dup2(dev_null.as_raw_fd(), STDIN_FILENO)?;
            dup2(dev_null.as_raw_fd(), STDOUT_FILENO)?;
            dup2(dev_null.as_raw_fd(), STDERR_FILENO)?;

            // Meter CPU usage after second fork()
            self.jailer_cpu_time_us += get_time_us(ClockType::ProcessCpu);
        }

        // If specified, exec the provided binary into a new PID namespace.
        if self.new_pid_ns {
            self.exec_into_new_pid_ns(chroot_exec_file)
        } else {
            self.save_exec_file_pid(id().try_into().unwrap(), chroot_exec_file.clone())?;
            Err(JailerError::Exec(self.exec_command(chroot_exec_file)))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]

    use std::fs::create_dir_all;
    use std::os::linux::fs::MetadataExt;

    use vmm_sys_util::rand;
    use vmm_sys_util::tempdir::TempDir;
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::build_arg_parser;
    use crate::cgroup::test_util::MockCgroupFs;

    fn get_pseudo_exec_file_path() -> String {
        format!(
            "/tmp/{}/pseudo_firecracker_exec_file",
            rand::rand_alphanumerics(4).into_string().unwrap()
        )
    }

    #[derive(Debug, Clone)]
    struct ArgVals<'a> {
        pub id: &'a str,
        pub exec_file: &'a str,
        pub uid: &'a str,
        pub gid: &'a str,
        pub chroot_base: &'a str,
        pub netns: Option<&'a str>,
        pub daemonize: bool,
        pub new_pid_ns: bool,
        pub cgroups: Vec<&'a str>,
        pub resource_limits: Vec<&'a str>,
        pub parent_cgroup: Option<&'a str>,
    }

    impl<'a> ArgVals<'a> {
        pub fn new(pseudo_exec_file_path: &'a str) -> ArgVals<'a> {
            let pseudo_exec_file_dir = Path::new(&pseudo_exec_file_path).parent().unwrap();
            fs::create_dir_all(pseudo_exec_file_dir).unwrap();
            File::create(pseudo_exec_file_path).unwrap();
            ArgVals {
                id: "bd65600d-8669-4903-8a14-af88203add38",
                exec_file: pseudo_exec_file_path,
                uid: "1001",
                gid: "1002",
                chroot_base: "/",
                netns: Some("zzzns"),
                daemonize: true,
                new_pid_ns: true,
                cgroups: vec!["cpu.shares=2", "cpuset.mems=0"],
                resource_limits: vec!["no-file=1024", "fsize=1048575"],
                parent_cgroup: None,
            }
        }
    }

    fn make_args(arg_vals: &ArgVals) -> Vec<String> {
        let mut arg_vec = vec![
            "--binary-name",
            "--id",
            arg_vals.id,
            "--exec-file",
            &arg_vals.exec_file,
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

        // Append limits arguments
        for limit in &arg_vals.resource_limits {
            arg_vec.push("--resource-limit".to_string());
            arg_vec.push((*limit).to_string());
        }

        if let Some(s) = arg_vals.netns {
            arg_vec.push("--netns".to_string());
            arg_vec.push(s.to_string());
        }

        if arg_vals.daemonize {
            arg_vec.push("--daemonize".to_string());
        }

        if arg_vals.new_pid_ns {
            arg_vec.push("--new-pid-ns".to_string());
        }

        if let Some(parent_cg) = arg_vals.parent_cgroup {
            arg_vec.push("--parent-cgroup".to_string());
            arg_vec.push(parent_cg.to_string());
        }

        arg_vec
    }

    fn create_env(mock_proc_mounts: &Path) -> Env {
        // Create a standard environment.
        let arg_parser = build_arg_parser();
        let mut args = arg_parser.arguments().clone();

        let pseudo_exec_file_path = get_pseudo_exec_file_path();
        args.parse(&make_args(&ArgVals::new(pseudo_exec_file_path.as_str())))
            .unwrap();
        Env::new(&args, 0, 0, mock_proc_mounts.to_str().unwrap()).unwrap()
    }

    #[test]
    fn test_new_env() {
        let mut mock_cgroups = MockCgroupFs::new().unwrap();
        mock_cgroups.add_v1_mounts().unwrap();

        let pseudo_exec_file_path = get_pseudo_exec_file_path();
        let good_arg_vals = ArgVals::new(pseudo_exec_file_path.as_str());
        let arg_parser = build_arg_parser();
        let mut args = arg_parser.arguments().clone();
        args.parse(&make_args(&good_arg_vals)).unwrap();
        // This should be fine.
        let good_env = Env::new(&args, 0, 0, mock_cgroups.proc_mounts_path.to_str().unwrap())
            .expect("This new environment should be created successfully.");

        let mut chroot_dir = PathBuf::from(good_arg_vals.chroot_base);
        chroot_dir.push(Path::new(&good_arg_vals.exec_file).file_name().unwrap());
        chroot_dir.push(good_arg_vals.id);
        chroot_dir.push("root");

        assert_eq!(good_env.chroot_dir(), chroot_dir);
        assert_eq!(format!("{}", good_env.gid()), good_arg_vals.gid);
        assert_eq!(format!("{}", good_env.uid()), good_arg_vals.uid);

        assert_eq!(good_env.netns, good_arg_vals.netns.map(String::from));
        assert!(good_env.daemonize);
        assert!(good_env.new_pid_ns);

        let another_good_arg_vals = ArgVals {
            netns: None,
            daemonize: false,
            new_pid_ns: false,
            ..good_arg_vals
        };

        let arg_parser = build_arg_parser();
        args = arg_parser.arguments().clone();
        args.parse(&make_args(&another_good_arg_vals)).unwrap();
        let another_good_env =
            Env::new(&args, 0, 0, mock_cgroups.proc_mounts_path.to_str().unwrap())
                .expect("This another new environment should be created successfully.");
        assert!(!another_good_env.daemonize);
        assert!(!another_good_env.new_pid_ns);

        let base_invalid_arg_vals = ArgVals {
            daemonize: true,
            ..another_good_arg_vals.clone()
        };

        let invalid_cgroup_arg_vals = ArgVals {
            cgroups: vec!["zzz"],
            ..base_invalid_arg_vals.clone()
        };

        let arg_parser = build_arg_parser();
        args = arg_parser.arguments().clone();
        args.parse(&make_args(&invalid_cgroup_arg_vals)).unwrap();
        Env::new(&args, 0, 0, mock_cgroups.proc_mounts_path.to_str().unwrap()).unwrap_err();

        let invalid_res_limit_arg_vals = ArgVals {
            resource_limits: vec!["zzz"],
            ..base_invalid_arg_vals.clone()
        };

        let arg_parser = build_arg_parser();
        args = arg_parser.arguments().clone();
        args.parse(&make_args(&invalid_res_limit_arg_vals)).unwrap();
        Env::new(&args, 0, 0, mock_cgroups.proc_mounts_path.to_str().unwrap()).unwrap_err();

        let invalid_id_arg_vals = ArgVals {
            id: "/ad./sa12",
            ..base_invalid_arg_vals.clone()
        };

        let arg_parser = build_arg_parser();
        args = arg_parser.arguments().clone();
        args.parse(&make_args(&invalid_id_arg_vals)).unwrap();
        Env::new(&args, 0, 0, mock_cgroups.proc_mounts_path.to_str().unwrap()).unwrap_err();

        let inexistent_exec_file_arg_vals = ArgVals {
            exec_file: "/this!/file!/should!/not!/exist!/",
            ..base_invalid_arg_vals.clone()
        };

        let arg_parser = build_arg_parser();
        args = arg_parser.arguments().clone();
        args.parse(&make_args(&inexistent_exec_file_arg_vals))
            .unwrap();
        Env::new(&args, 0, 0, mock_cgroups.proc_mounts_path.to_str().unwrap()).unwrap_err();

        let invalid_uid_arg_vals = ArgVals {
            uid: "zzz",
            ..base_invalid_arg_vals.clone()
        };

        let arg_parser = build_arg_parser();
        args = arg_parser.arguments().clone();
        args.parse(&make_args(&invalid_uid_arg_vals)).unwrap();
        Env::new(&args, 0, 0, mock_cgroups.proc_mounts_path.to_str().unwrap()).unwrap_err();

        let invalid_gid_arg_vals = ArgVals {
            gid: "zzz",
            ..base_invalid_arg_vals.clone()
        };

        let arg_parser = build_arg_parser();
        args = arg_parser.arguments().clone();
        args.parse(&make_args(&invalid_gid_arg_vals)).unwrap();
        Env::new(&args, 0, 0, mock_cgroups.proc_mounts_path.to_str().unwrap()).unwrap_err();

        let invalid_parent_cg_vals = ArgVals {
            parent_cgroup: Some("/root"),
            ..base_invalid_arg_vals.clone()
        };

        let arg_parser = build_arg_parser();
        args = arg_parser.arguments().clone();
        args.parse(&make_args(&invalid_parent_cg_vals)).unwrap();
        Env::new(&args, 0, 0, mock_cgroups.proc_mounts_path.to_str().unwrap()).unwrap_err();

        let invalid_controller_pt = ArgVals {
            cgroups: vec!["../file_name=1", "./root=1", "/home=1"],
            ..another_good_arg_vals.clone()
        };
        let arg_parser = build_arg_parser();
        args = arg_parser.arguments().clone();
        args.parse(&make_args(&invalid_controller_pt)).unwrap();
        Env::new(&args, 0, 0, mock_cgroups.proc_mounts_path.to_str().unwrap()).unwrap_err();

        let invalid_format = ArgVals {
            cgroups: vec!["./root/", "../root"],
            ..another_good_arg_vals.clone()
        };
        let arg_parser = build_arg_parser();
        args = arg_parser.arguments().clone();
        args.parse(&make_args(&invalid_format)).unwrap();
        Env::new(&args, 0, 0, mock_cgroups.proc_mounts_path.to_str().unwrap()).unwrap_err();

        // The chroot-base-dir param is not validated by Env::new, but rather in run, when we
        // actually attempt to create the folder structure (the same goes for netns).
    }

    #[test]
    fn test_dup2() {
        // Open /dev/kvm since it should be available anyway.
        let file1 = fs::File::open("/dev/kvm").unwrap();
        // We open a second file to make sure its associated fd is not used by something else.
        let file2 = fs::File::open("/dev/kvm").unwrap();

        dup2(file1.as_raw_fd(), file2.as_raw_fd()).unwrap();
    }

    #[test]
    fn test_validate_exec_file() {
        // Success case
        let pseudo_exec_file_path = get_pseudo_exec_file_path();
        let pseudo_exec_file_dir = Path::new(&pseudo_exec_file_path).parent().unwrap();
        create_dir_all(pseudo_exec_file_dir).unwrap();
        File::create(&pseudo_exec_file_path).unwrap();
        Env::validate_exec_file(&pseudo_exec_file_path).unwrap();

        // Error case 1: No such file exists
        std::fs::remove_file(&pseudo_exec_file_path).unwrap();
        assert_eq!(
            format!(
                "{}",
                Env::validate_exec_file(&pseudo_exec_file_path).unwrap_err()
            ),
            format!(
                "Failed to canonicalize path {}: No such file or directory (os error 2)",
                pseudo_exec_file_path
            )
        );

        // Error case 2: Not a file
        std::fs::create_dir_all("/tmp/firecracker_test_dir").unwrap();
        assert_eq!(
            format!(
                "{}",
                Env::validate_exec_file("/tmp/firecracker_test_dir").unwrap_err()
            ),
            "/tmp/firecracker_test_dir is not a file"
        );

        // Error case 3: Filename without "firecracker"
        File::create("/tmp/firecracker_test_dir/foobarbaz").unwrap();
        assert_eq!(
            format!(
                "{}",
                Env::validate_exec_file("/tmp/firecracker_test_dir/foobarbaz").unwrap_err()
            ),
            "Invalid filename. The filename of `--exec-file` option must contain \"firecracker\": \
             foobarbaz"
        );
        std::fs::remove_file("/tmp/firecracker_test_dir/foobarbaz").unwrap();
        std::fs::remove_dir_all("/tmp/firecracker_test_dir").unwrap();
    }

    #[test]
    fn test_setup_jailed_folder() {
        let mut mock_cgroups = MockCgroupFs::new().unwrap();
        mock_cgroups.add_v1_mounts().unwrap();
        let env = create_env(&mock_cgroups.proc_mounts_path);

        // Error case: non UTF-8 paths.
        let bad_string_bytes: Vec<u8> = vec![0, 102, 111, 111, 0]; // A leading nul followed by 'f', 'o', 'o'
        let bad_string = String::from_utf8(bad_string_bytes).unwrap();
        assert_eq!(
            format!("{}", env.setup_jailed_folder(bad_string).err().unwrap()),
            format!(
                "Failed to create directory \\0foo\\0: file name contained an unexpected NUL byte"
            )
        );

        // Error case: inaccessible path - can't be triggered with unit tests running as root.
        // assert_eq!(
        //     format!("{}", env.setup_jailed_folders(vec!["/foo/bar"]).err().unwrap()),
        //     "Failed to create directory /foo/bar: Permission denied (os error 13)"
        // );

        // Success case.
        let foo_dir = TempDir::new().unwrap().as_path().to_owned();
        env.setup_jailed_folder(foo_dir.as_path()).unwrap();

        let metadata = fs::metadata(&foo_dir).unwrap();
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

    fn ensure_mknod_and_own_dev(env: &Env, dev_path: &CStr, major: u32, minor: u32) {
        use std::os::unix::fs::FileTypeExt;

        // Create a new device node.
        env.mknod_and_own_dev(dev_path, major, minor).unwrap();

        // Ensure device's properties.
        let metadata = fs::metadata(dev_path.to_str().unwrap()).unwrap();
        assert!(metadata.file_type().is_char_device());
        assert_eq!(libc::major(metadata.st_rdev()), major);
        assert_eq!(libc::minor(metadata.st_rdev()), minor);
        assert_eq!(
            metadata.permissions().mode(),
            libc::S_IFCHR | libc::S_IRUSR | libc::S_IWUSR
        );

        // Trying to create again the same device node is not allowed.
        assert_eq!(
            format!(
                "{}",
                env.mknod_and_own_dev(dev_path, major, minor).unwrap_err()
            ),
            format!(
                "Failed to create {} via mknod inside the jail: File exists (os error 17)",
                dev_path.to_str().unwrap()
            )
        );
    }

    #[test]
    fn test_mknod_and_own_dev() {
        let mut mock_cgroups = MockCgroupFs::new().unwrap();
        mock_cgroups.add_v1_mounts().unwrap();
        let env = create_env(&mock_cgroups.proc_mounts_path);

        let mock_dev_dir = TempDir::new().unwrap();

        // Ensure device nodes are created with correct major/minor numbers and permissions.
        let mut dev_infos: Vec<(PathBuf, u32, u32)> = vec![
            (
                mock_dev_dir.as_path().join("net/tun-test"),
                DEV_NET_TUN_MAJOR,
                DEV_NET_TUN_MINOR,
            ),
            (
                mock_dev_dir.as_path().join("kvm-test"),
                DEV_KVM_MAJOR,
                DEV_KVM_MINOR,
            ),
        ];

        if let Some(uffd_dev_minor) = env.uffd_dev_minor {
            dev_infos.push((
                mock_dev_dir.as_path().join("userfaultfd-test"),
                DEV_UFFD_MAJOR,
                uffd_dev_minor,
            ));
        }

        for (dev, major, minor) in dev_infos {
            // Ensure the folder where we are creating the node exists
            fs::create_dir_all(dev.parent().unwrap()).unwrap();
            let dev_path = dev.to_str().map(CString::new).unwrap().unwrap();
            ensure_mknod_and_own_dev(&env, &dev_path, major, minor);
        }
    }

    #[test]
    fn test_userfaultfd_dev() {
        let mut mock_cgroups = MockCgroupFs::new().unwrap();
        mock_cgroups.add_v1_mounts().unwrap();
        let env = create_env(&mock_cgroups.proc_mounts_path);

        if !Path::new(DEV_UFFD_PATH.to_str().unwrap()).exists() {
            assert_eq!(env.uffd_dev_minor, None);
        } else {
            assert!(env.uffd_dev_minor.is_some());
        }
    }

    #[test]
    fn test_copy_exec_to_chroot() {
        // Create a standard environment.
        let arg_parser = build_arg_parser();
        let mut args = arg_parser.arguments().clone();
        let mut mock_cgroups = MockCgroupFs::new().unwrap();
        mock_cgroups.add_v1_mounts().unwrap();

        // Create tmp resources for `exec_file` and `chroot_base`.
        let exec_file_path = get_pseudo_exec_file_path();
        let exec_file_dir = Path::new(&exec_file_path).parent().unwrap();
        fs::create_dir_all(exec_file_dir).unwrap();
        File::create(&exec_file_path).unwrap();
        let some_dir = TempDir::new().unwrap();
        let some_dir_path = some_dir.as_path().to_str().unwrap();

        fs::write(&exec_file_path, "some_content").unwrap();
        let some_arg_vals = ArgVals {
            id: "bd65600d-8669-4903-8a14-af88203add38",
            exec_file: exec_file_path.as_str(),
            uid: "1001",
            gid: "1002",
            chroot_base: some_dir_path,
            netns: Some("zzzns"),
            daemonize: false,
            new_pid_ns: false,
            cgroups: Vec::new(),
            resource_limits: Vec::new(),
            parent_cgroup: None,
        };
        let exec_file_name = Path::new(&some_arg_vals.exec_file).file_name().unwrap();
        fs::write(some_arg_vals.exec_file, "some_content").unwrap();
        args.parse(&make_args(&some_arg_vals)).unwrap();
        let mut env =
            Env::new(&args, 0, 0, mock_cgroups.proc_mounts_path.to_str().unwrap()).unwrap();

        // Create the required chroot dir hierarchy.
        fs::create_dir_all(env.chroot_dir()).expect("Could not create dir hierarchy.");

        assert_eq!(
            env.copy_exec_to_chroot().unwrap(),
            exec_file_name.to_os_string()
        );

        let dest_path = env.chroot_dir.join(exec_file_name);
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
        let pseudo_exec_file_path = get_pseudo_exec_file_path();
        let good_arg_vals = ArgVals::new(pseudo_exec_file_path.as_str());
        let mut mock_cgroups = MockCgroupFs::new().unwrap();
        mock_cgroups.add_v1_mounts().unwrap();

        // Cases that should fail

        // Check string without "." (no controller)
        let mut args = arg_parser.arguments().clone();
        let invalid_cgroup_arg_vals = ArgVals {
            cgroups: vec!["cpusetcpus=2"],
            ..good_arg_vals.clone()
        };
        args.parse(&make_args(&invalid_cgroup_arg_vals)).unwrap();
        Env::new(&args, 0, 0, mock_cgroups.proc_mounts_path.to_str().unwrap()).unwrap_err();

        // Check empty string
        let mut args = arg_parser.arguments().clone();
        let invalid_cgroup_arg_vals = ArgVals {
            cgroups: vec![""],
            ..good_arg_vals.clone()
        };
        args.parse(&make_args(&invalid_cgroup_arg_vals)).unwrap();
        Env::new(&args, 0, 0, mock_cgroups.proc_mounts_path.to_str().unwrap()).unwrap_err();

        // Check valid file empty value
        let mut args = arg_parser.arguments().clone();
        let invalid_cgroup_arg_vals = ArgVals {
            cgroups: vec!["cpuset.cpus="],
            ..good_arg_vals.clone()
        };
        args.parse(&make_args(&invalid_cgroup_arg_vals)).unwrap();
        Env::new(&args, 0, 0, mock_cgroups.proc_mounts_path.to_str().unwrap()).unwrap_err();

        // Check valid file no value
        let mut args = arg_parser.arguments().clone();
        let invalid_cgroup_arg_vals = ArgVals {
            cgroups: vec!["cpuset.cpus"],
            ..good_arg_vals.clone()
        };
        args.parse(&make_args(&invalid_cgroup_arg_vals)).unwrap();
        Env::new(&args, 0, 0, mock_cgroups.proc_mounts_path.to_str().unwrap()).unwrap_err();

        // Cases that should succeed

        // Check value with special characters (',', '.', '-')
        let mut args = arg_parser.arguments().clone();
        let invalid_cgroup_arg_vals = ArgVals {
            cgroups: vec!["cpuset.cpus=2-4,5.3"],
            ..good_arg_vals.clone()
        };
        args.parse(&make_args(&invalid_cgroup_arg_vals)).unwrap();
        Env::new(&args, 0, 0, mock_cgroups.proc_mounts_path.to_str().unwrap()).unwrap();

        // Check valid case
        let mut args = arg_parser.arguments().clone();
        let invalid_cgroup_arg_vals = ArgVals {
            cgroups: vec!["cpuset.cpus=2"],
            ..good_arg_vals.clone()
        };
        args.parse(&make_args(&invalid_cgroup_arg_vals)).unwrap();
        Env::new(&args, 0, 0, mock_cgroups.proc_mounts_path.to_str().unwrap()).unwrap();

        // Check file with multiple "."
        let mut args = arg_parser.arguments().clone();
        let invalid_cgroup_arg_vals = ArgVals {
            cgroups: vec!["memory.swap.high=2"],
            ..good_arg_vals.clone()
        };
        args.parse(&make_args(&invalid_cgroup_arg_vals)).unwrap();
        Env::new(&args, 0, 0, mock_cgroups.proc_mounts_path.to_str().unwrap()).unwrap();
    }

    #[test]
    fn test_parse_resource_limits() {
        let mut resource_limits = ResourceLimits::default();

        // Cases that should fail

        // Check invalid formats
        let invalid_formats = ["", "foo"];
        for format in invalid_formats.iter() {
            let arg = vec![format.to_string()];
            assert_eq!(
                format!(
                    "{:?}",
                    Env::parse_resource_limits(&mut resource_limits, &arg)
                        .err()
                        .unwrap()
                ),
                format!("{:?}", JailerError::ResLimitFormat(format.to_string()))
            );
        }

        // Check invalid resource arguments
        let invalid_resources = ["foo", "", " "];
        for res in invalid_resources.iter() {
            let arg = format!("{}=2", res);
            assert_eq!(
                format!(
                    "{:?}",
                    Env::parse_resource_limits(&mut resource_limits, &[arg])
                        .err()
                        .unwrap()
                ),
                format!("{:?}", JailerError::ResLimitArgument(res.to_string()))
            );
        }

        // Check invalid limit values
        let invalid_values = ["foo", "2.3", "2-3", " "];
        for val in invalid_values.iter() {
            let arg = format!("fsize={}", val);
            assert_eq!(
                format!(
                    "{:?}",
                    Env::parse_resource_limits(&mut resource_limits, &[arg])
                        .err()
                        .unwrap()
                ),
                format!(
                    "{:?}",
                    JailerError::ResLimitValue(
                        val.to_string(),
                        "invalid digit found in string".to_string()
                    )
                )
            );
        }

        // Check valid cases
        let resources = [FSIZE_ARG, NO_FILE_ARG];
        for resource in resources.iter() {
            let arg = vec![resource.to_string() + "=4098"];
            Env::parse_resource_limits(&mut resource_limits, &arg).unwrap();
        }
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_copy_cache_info() {
        let mut mock_cgroups = MockCgroupFs::new().unwrap();
        mock_cgroups.add_v1_mounts().unwrap();

        let env = create_env(&mock_cgroups.proc_mounts_path);

        // Create the required chroot dir hierarchy.
        fs::create_dir_all(env.chroot_dir()).expect("Could not create dir hierarchy.");

        env.copy_cache_info().unwrap();

        // Make sure that the needed files truly exist.
        const JAILER_CACHE_INFO: &str = "sys/devices/system/cpu/cpu0/cache";

        let dest_path = env.chroot_dir.join(JAILER_CACHE_INFO);
        fs::metadata(&dest_path).unwrap();
        let index_dest_path = dest_path.join("index0");
        fs::metadata(&index_dest_path).unwrap();
        let entries = fs::read_dir(&index_dest_path).unwrap();
        assert_eq!(entries.enumerate().count(), 6);
    }

    #[test]
    fn test_save_exec_file_pid() {
        let exec_file_name = "file";
        let pid_file_name = "file.pid";
        let pid = 1;

        let mut mock_cgroups = MockCgroupFs::new().unwrap();
        mock_cgroups.add_v1_mounts().unwrap();

        let mut env = create_env(&mock_cgroups.proc_mounts_path);
        env.save_exec_file_pid(pid, PathBuf::from(exec_file_name))
            .unwrap();

        let stored_pid = fs::read_to_string(pid_file_name);
        fs::remove_file(pid_file_name).unwrap();
        assert_eq!(stored_pid.unwrap(), "1");
    }
}
