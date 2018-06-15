use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process;

use regex::Regex;

use super::{Error, Result};

// The list of cgroup controllers we're interested in.
const CONTROLLERS: [&'static str; 3] = ["cpu", "cpuset", "pids"];
const PROC_MOUNTS: &str = "/proc/mounts";

pub struct Cgroup {
    tasks_files: Vec<PathBuf>,
}

// This is called writeln_special because we have to use this rather convoluted way of writing
// to avoid getting all sorts of weird errors. I would be nice to know why that happens.
fn writeln_special<T, V>(file_path: T, value: V) -> Result<()>
where
    T: AsRef<Path>,
    V: ::std::fmt::Display,
{
    // Open does not work here, or so it seemed at one point :-s
    let mut f = File::create(file_path.as_ref())
        .map_err(|e| Error::FileCreate(PathBuf::from(file_path.as_ref()), e))?;

    // For some reason, using writeln!(f, "{}", pid) doesn't work :(
    let mut bytes = format!("{}\n", value).into_bytes();
    f.write_all(bytes.as_mut())
        .map_err(|e| Error::Write(PathBuf::from(file_path.as_ref()), e))
}

fn inherit_from_parent(path: &mut PathBuf, what: &'static str) -> Result<()> {
    // This unwrap() is safe because path_buf is guaranteed to have a parent.
    let mut parent_what = PathBuf::from(path.parent().unwrap());
    parent_what.push(what);

    let f = OpenOptions::new()
        .read(true)
        .open(&parent_what)
        .map_err(|e| Error::FileOpen(parent_what.clone(), e))?;

    let mut line = String::new();
    BufReader::new(f)
        .read_line(&mut line)
        .map_err(|e| Error::ReadLine(parent_what.clone(), e))?;

    path.push(what);
    writeln_special(&path, &line)?;
    path.pop();

    Ok(())
}

impl Cgroup {
    pub fn new(id: &str, numa_node: u32, exec_file_name: &OsStr) -> Result<Self> {
        let f =
            File::open(PROC_MOUNTS).map_err(|e| Error::FileOpen(PathBuf::from(PROC_MOUNTS), e))?;

        let mut found_controllers: HashMap<&'static str, PathBuf> =
            HashMap::with_capacity(CONTROLLERS.len());

        // Regex courtesy of Filippo.
        let re = Regex::new(
            r"^cgroup[[:space:]](?P<dir>.*)[[:space:]]cgroup[[:space:]](?P<options>.*)[[:space:]]0[[:space:]]0$",
        ).map_err(Error::RegEx)?;

        for l in BufReader::new(f).lines() {
            let l = l.map_err(|e| Error::ReadLine(PathBuf::from(PROC_MOUNTS), e))?;
            if let Some(capture) = re.captures(&l) {
                // We could do the search in a more efficient manner but eh.
                let v: Vec<&str> = capture["options"].split(',').collect();

                for controller in CONTROLLERS.into_iter() {
                    if v.contains(controller) {
                        if let Some(_) =
                            found_controllers.insert(controller, PathBuf::from(&capture["dir"]))
                        {
                            return Err(Error::CgroupLineNotUnique(PROC_MOUNTS, controller));
                        }
                    }
                }
            }
        }

        let keys_len = found_controllers.keys().len();

        if keys_len < CONTROLLERS.len() {
            // We return an error about the first one we didn't find.
            for controller in CONTROLLERS.into_iter() {
                if !found_controllers.contains_key(controller) {
                    return Err(Error::CgroupLineNotFound(PROC_MOUNTS, controller));
                }
            }
        }

        // This is a just sanity check.
        assert_eq!(keys_len, CONTROLLERS.len());

        // We now both create the cgroup subfolders, and fill the tasks_files vector.
        let mut tasks_files = Vec::with_capacity(keys_len);

        for (controller, mut path_buf) in found_controllers.drain() {
            path_buf.push(exec_file_name);

            // TODO: fix this racy thing.
            if controller == "cpuset" && !path_buf.exists() {
                fs::create_dir_all(&path_buf).map_err(|e| Error::CreateDir(path_buf.clone(), e))?;

                inherit_from_parent(&mut path_buf, "cpuset.mems")?;
                inherit_from_parent(&mut path_buf, "cpuset.cpus")?;
            }

            path_buf.push(id);

            fs::create_dir_all(&path_buf).map_err(|e| Error::CreateDir(path_buf.clone(), e))?;

            if controller == "cpuset" {
                // Enforce NUMA node restriction.
                path_buf.push("cpuset.mems");
                writeln_special(&path_buf, numa_node)?;
                path_buf.pop();

                // Inherit cpuset
                inherit_from_parent(&mut path_buf, "cpuset.cpus")?;
            }

            // And now add "tasks" to get the path of the corresponding tasks file.
            path_buf.push("tasks");

            if !tasks_files.contains(&path_buf) {
                tasks_files.push(path_buf);
            }
        }

        Ok(Cgroup { tasks_files })
    }

    // This writes the pid of the current process to each tasks file. These are special files that,
    // when written to, will assign the process associated with the pid to the respective cgroup.
    pub fn attach_pid(&self) -> Result<()> {
        let pid = process::id();
        for tasks_file in &self.tasks_files {
            writeln_special(tasks_file, pid)?;
        }
        Ok(())
    }
}
