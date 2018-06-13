use std::ffi::CString;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use libc;

use super::{Error, JailerArgs, Result};

const CHROOT_DIR_BASE: &str = "/srv/jailer";

pub struct Env {
    chroot_dir: PathBuf,
    chroot_exec_file: PathBuf,
    uid: u32,
    gid: u32,
}

impl Env {
    pub fn new(args: JailerArgs) -> Result<Self> {
        let exec_file_name = args.exec_file_name()?;

        let mut chroot_dir = PathBuf::from(CHROOT_DIR_BASE);
        chroot_dir.push(exec_file_name);
        chroot_dir.push(args.id);
        chroot_dir.push("root");

        // Create the jail folder.
        fs::create_dir_all(&chroot_dir).map_err(|e| Error::CreateDir(chroot_dir.clone(), e))?;

        // We do a quick push here to get the global path of the executable inside the chroot,
        // without having to create a new PathBuf. We'll then do a pop to revert to the actual
        // chroot_dir right after the copy.
        chroot_dir.push(exec_file_name);
        // TODO: hard link instead of copy? This would save up disk space, but hard linking is
        // not always possible :(
        fs::copy(&args.exec_file_path, &chroot_dir)
            .map_err(|e| Error::Copy(args.exec_file_path.clone(), chroot_dir.clone(), e))?;
        chroot_dir.pop();

        let mut chroot_exec_file = PathBuf::from("/");
        chroot_exec_file.push(exec_file_name);

        Ok(Env {
            chroot_dir,
            chroot_exec_file,
            uid: args.uid,
            gid: args.gid,
        })
    }

    pub fn chroot_dir(&self) -> &Path {
        self.chroot_dir.as_path()
    }

    pub fn run(self) -> Result<()> {
        // Turn self.chroot_dir into a CString. The expect should not fail, since Linux paths
        // only contain valid Unicode chars (do they?), and do not contain null bytes (do they?).
        let chroot_dir = CString::new(
            self.chroot_dir
                .into_os_string()
                .into_string()
                .expect("Could not convert chroot_dir to String."),
        ).expect("Could not convert chroot_dir String to CString.");
        let ret = unsafe { libc::chroot(chroot_dir.as_ptr()) };
        if ret < 0 {
            return Err(Error::Chroot(ret));
        }

        Err(Error::Exec(
            Command::new(&self.chroot_exec_file)
                .arg("--jailed")
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .uid(self.uid)
                .gid(self.gid)
                .exec(),
        ))
    }
}
