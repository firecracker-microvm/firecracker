use std::env::set_current_dir;
use std::fs::{canonicalize, copy, create_dir_all};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio, exit};

mod cgroup;
use self::cgroup::Cgroup;

pub struct Env {
    cgroup: Cgroup,
    run_dir: String,
    chroot_exec_file: String,
}

impl Env {
    pub fn new(id: &str, exec_file: &str) -> Env {
        let src_exec_file = match canonicalize(exec_file) {
            Ok(c) => c,
            Err(_) => {
                println!("failed to canonicalize {}", exec_file);
                exit(1);
            },
        };
        let exec_file_name_ = match src_exec_file.file_name() {
            Some(c) => c,
            None => {
                println!("failed to get the filename for {}", exec_file);
                exit(1);
            },
        };
        let exec_file_name = match exec_file_name_.to_str() {
            Some(c) => c,
            None => {
                println!("failed to get the filename for {}", exec_file);
                exit(1);
            },
        };
        let mut run_dir = PathBuf::from("/srv/jailer");
        run_dir.push(exec_file_name);
        run_dir.push(id);
        let mut chroot_dir = PathBuf::from(&run_dir);
        chroot_dir.push("root");
        match create_dir_all(&chroot_dir) {
            Ok(_) => (),
            Err(_) => {
                println!("failed to create {}", chroot_dir.to_str().unwrap());
                exit(1);
            },
        }
        let mut dst_exec_file = PathBuf::from(&chroot_dir);
        dst_exec_file.push(exec_file_name);
        match copy(&src_exec_file, &dst_exec_file) {
            Ok(_) => (),
            Err(_) => {
                println!("failed to copy from {} to {}", src_exec_file.to_str().unwrap(), dst_exec_file.to_str().unwrap());
                exit(1);
            },
        }
        let chroot_exec_file = PathBuf::from(&dst_exec_file);
        let cgroup = Cgroup::new(&id, &exec_file_name);
        Env { cgroup: cgroup,
              run_dir: run_dir.to_str().unwrap().to_string(),
              chroot_exec_file: chroot_exec_file.to_str().unwrap().to_string(), }
    }

    pub fn run(self) {
        self.cgroup.run();
        match set_current_dir(&self.run_dir) {
            Ok(_) => (),
            Err(_) => {
                println!("failed to set the current working directory to {}", self.run_dir);
                exit(1);
            },
        }
        Command::new(&self.chroot_exec_file).stdin(Stdio::inherit()).stdout(Stdio::inherit()).stderr(Stdio::inherit()).exec();
        println!("failed to execute {}", self.chroot_exec_file);
        exit(1);
    }
}
