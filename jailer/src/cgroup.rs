use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process;

use regex::Regex;

use super::{Error, Result};

const PROC_MOUNTS: &str = "/proc/mounts";

pub struct Cgroup {
    tasks_file: PathBuf,
}

fn cgroup_root() -> Result<PathBuf> {
    let f = File::open(PROC_MOUNTS).map_err(|e| Error::FileOpen(PathBuf::from(PROC_MOUNTS), e))?;

    // Regex courtesy of Filippo.
    let re = Regex::new(
        r"^cgroup[[:space:]](?P<dir>.*)[[:space:]]cgroup[[:space:]](?P<options>.*)[[:space:]]0[[:space:]]0$",
    ).map_err(Error::RegEx)?;

    let mut cgroup_root = None;

    for l in BufReader::new(f).lines() {
        let l = l.map_err(|e| Error::ReadLine(PathBuf::from(PROC_MOUNTS), e))?;

        if let Some(c) = re.captures(&l) {
            // We could do the search in a more efficient manner but eh.
            let v: Vec<&str> = c["options"].split(',').collect();

            if v.contains(&"cpu") && v.contains(&"cpuset") && v.contains(&"pids") {
                if cgroup_root.is_none() {
                    cgroup_root = Some(PathBuf::from(&c["dir"]));
                } else {
                    return Err(Error::CgroupLineNotUnique(PROC_MOUNTS.to_string()));
                }
            }
        }
    }

    cgroup_root.ok_or_else(|| Error::CgroupLineNotFound(PROC_MOUNTS.to_string()))
}

impl Cgroup {
    pub fn new(id: &str, exec_file_name: &OsStr) -> Result<Self> {
        let mut path = cgroup_root()?;

        path.push(exec_file_name);
        path.push(id);

        // The cpuset.cpus and cpuset.mems files appear to be inherited automatically :-s
        fs::create_dir_all(&path).map_err(|e| Error::CreateDir(path.clone(), e))?;

        path.push("tasks");

        Ok(Cgroup { tasks_file: path })
    }

    // This write the pid of the current process to the tasks_file. That's a special file, that
    // when written to, will assign the process associated with the pid to the respective cgroup.
    pub fn attach_pid(&self) -> Result<()> {
        let mut f = File::create(&self.tasks_file)
            .map_err(|e| Error::FileCreate(self.tasks_file.clone(), e))?;

        // For some reason, using write!("{}\n", ...) doesn't work :( I wonder why ...
        let mut bytes = format!("{}\n", process::id()).into_bytes();
        f.write_all(bytes.as_mut())
            .map_err(|e| Error::Write(self.tasks_file.clone(), e))
    }
}
