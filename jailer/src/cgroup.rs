// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process;

use regex::Regex;

use super::{Error, Result};

const CONTROLLER_CPU: &str = "cpu";

const CONTROLLER_CPUSET: &str = "cpuset";
const CPUSET_CPUS: &str = "cpuset.cpus";
const CPUSET_MEMS: &str = "cpuset.mems";

const CONTROLLER_PIDS: &str = "pids";

// The list of cgroup controllers we're interested in.
const CONTROLLERS: [&str; 3] = [CONTROLLER_CPU, CONTROLLER_CPUSET, CONTROLLER_PIDS];
const PROC_MOUNTS: &str = "/proc/mounts";
const NODE_TO_CPULIST: &str = "/sys/devices/system/node/node";

pub struct Cgroup {
    tasks_files: Vec<PathBuf>,
}

// It's called writeln_special because we have to use this rather convoluted way of writing
// to special cgroup files, to avoid getting errors. It would be nice to know why that happens :-s
fn writeln_special<T, V>(file_path: &T, value: V) -> Result<()>
where
    T: AsRef<Path>,
    V: ::std::fmt::Display,
{
    fs::write(file_path, format!("{}\n", value))
        .map_err(|e| Error::Write(PathBuf::from(file_path.as_ref()), e))
}

fn readln_special<T: AsRef<Path>>(file_path: &T) -> Result<String> {
    let mut line = fs::read_to_string(file_path)
        .map_err(|e| Error::ReadToString(PathBuf::from(file_path.as_ref()), e))?;

    // Remove the newline character at the end (if any).
    line.pop();

    Ok(line)
}

// If we call inherit_from_parent_aux(.../A/B/C, file, condition), the following will happen:
// 1) If .../A/B/C/file does not exist, or if .../A/B/file does not exist, return an error.
// 2) If .../A/B/file is not empty, write the first line of .../A/B/file into .../A/B/C/file
// and return.
// 3) If ../A/B/file exists but it is empty, call inherit_from_parent_aux(.../A/B, file, false).
// 4) If .../A/B/file is no longer empty, write the first line of .../A/B/file into
// .../A/B/C/file, and return.
// 5) Otherwise, return an error.

// How is this helpful? When creating cgroup folders for the jailer Firecracker instance, the jailer
// will create a hierarchy that looks like <cgroup_base>/firecracker/<id>. Depending on each
// particular cgroup controller, <cgroup_base> contains a number of configuration files. These are
// not actually present on a disk; they are special files exposed by the controller, and they
// usually contain a single line with some configuration value(s). When the "firecracker" and <id>
// subfolders are created, configuration files with the same name appear automatically in the new
// folders, but their contents are not always automatically populated. Moreover,
// if <cgroup_base>/firecracker/some_file is empty, then we cannot have a non-empty file with
// at <cgroup_base>/firecracker/<id>/some_file. The inherit_from_parent function (which is based
// on the following helper function) helps with propagating the values.

// There is also a potential race condition mentioned below. Here is what it refers to: let's say we
// start multiple jailer processes, and one of them calls
// inherit_from_parent_aux(/A/firecracker/id1, file, true), and hits case number 3) from the list
// above, thus recursively calling inherit_from_parent_aux(/A/firecracker, file, false). It's
// entirely possible there was another process in the exact same situations, and that process
// gets to write something to /A/firecracker/file first. In this case, the recursive call made by
// the first process to inherit_from_parent_aux(/A/firecracker, file, false) may fail when writing
// to /A/firecracker/file, but we can still continue, because step 4) only cares about the file
// no longer being empty, regardless of who actually got to populated its contents.

fn inherit_from_parent_aux(
    path: &mut PathBuf,
    file_name: &str,
    retry_one_level_up: bool,
) -> Result<()> {
    // The function with_file_name() replaces the last component of a path with the given name.
    let parent_file = path.with_file_name(file_name);

    let mut line = readln_special(&parent_file)?;
    if line.is_empty() {
        if retry_one_level_up {
            // We have to borrow "parent" from "parent_file" as opposed to "path", because then
            // we wouldn't be able to mutably borrow path at the end of this function (at least not
            // according to how the Rust borrow checker operates right now :-s)
            let parent = parent_file
                .parent()
                .ok_or_else(|| Error::MissingParent(parent_file.clone()))?;

            // Trying to avoid the race condition described above. We don't care about the result,
            // because we check once more if line.is_empty() after the end of this block.
            let _ = inherit_from_parent_aux(&mut parent.to_path_buf(), file_name, false);
            line = readln_special(&parent_file)?;
        }

        if line.is_empty() {
            return Err(Error::CgroupInheritFromParent(
                path.to_path_buf(),
                file_name.to_string(),
            ));
        }
    }

    path.push(file_name);
    writeln_special(&path, &line)?;
    path.pop();

    Ok(())
}

// The path reference is &mut here because we do a push to get the destination file name. However,
// a pop follows shortly after (see fn inherit_from_parent_aux), reverting to the original value.
fn inherit_from_parent(path: &mut PathBuf, file_name: &str) -> Result<()> {
    inherit_from_parent_aux(path, file_name, true)
}

impl Cgroup {
    pub fn new(id: &str, numa_node: u32, exec_file_name: &OsStr) -> Result<Self> {
        let f =
            File::open(PROC_MOUNTS).map_err(|e| Error::FileOpen(PathBuf::from(PROC_MOUNTS), e))?;

        let mut found_controllers: HashMap<&'static str, PathBuf> =
            HashMap::with_capacity(CONTROLLERS.len());

        // Regex courtesy of Filippo.
        let re = Regex::new(
            r"^([a-z]*)[[:space:]](?P<dir>.*)[[:space:]]cgroup[[:space:]](?P<options>.*)[[:space:]]0[[:space:]]0$",
        ).map_err(Error::RegEx)?;
        for l in BufReader::new(f).lines() {
            let l = l.map_err(|e| Error::ReadLine(PathBuf::from(PROC_MOUNTS), e))?;
            if let Some(capture) = re.captures(&l) {
                // We could do the search in a more efficient manner but eh.
                let v: Vec<&str> = capture["options"].split(',').collect();

                for controller in CONTROLLERS.iter() {
                    if v.contains(controller)
                        && found_controllers
                            .insert(controller, PathBuf::from(&capture["dir"]))
                            .is_some()
                    {
                        return Err(Error::CgroupLineNotUnique(
                            PROC_MOUNTS.to_string(),
                            controller.to_string(),
                        ));
                    }
                }
            }
        }

        let keys_len = found_controllers.keys().len();

        if keys_len < CONTROLLERS.len() {
            // We return an error about the first one we didn't find.
            for controller in CONTROLLERS.iter() {
                if !found_controllers.contains_key(controller) {
                    return Err(Error::CgroupLineNotFound(
                        PROC_MOUNTS.to_string(),
                        controller.to_string(),
                    ));
                }
            }
        }

        // This is just a sanity check.
        assert_eq!(keys_len, CONTROLLERS.len());

        // We now both create the cgroup subfolders, and fill the tasks_files vector.
        let mut tasks_files = Vec::with_capacity(keys_len);

        for (controller, mut path_buf) in found_controllers.drain() {
            path_buf.push(exec_file_name);
            path_buf.push(id);

            fs::create_dir_all(&path_buf).map_err(|e| Error::CreateDir(path_buf.clone(), e))?;

            // For now, the jailer is only populating configuration values for the cpuset
            // controller, related to the cpu cores we are allowed to run on, and the numa node we
            // want to restrict to. The jailer only creates the folder hierarchy for other cgroups,
            // and the customer has to provide any desired configuration explicitly (if any).

            if controller == CONTROLLER_CPUSET {
                inherit_from_parent(&mut path_buf, CPUSET_CPUS)?;

                // TODO: this does make an unnecessary write, as we change the value of the
                // "cpuset.mems" file again at the end of the for block. Maybe fix this sometime.
                inherit_from_parent(&mut path_buf, CPUSET_MEMS)?;

                // Enforce NUMA node restriction.
                // The cpuset subsystem assigns individual CPUs and memory nodes to cgroups.
                // CPUSET_MEMS specifies the memory nodes that tasks in this cgroup are permitted to
                // access.
                path_buf.push(CPUSET_MEMS);
                writeln_special(&path_buf, numa_node)?;
                path_buf.pop();
                // Similar to how numactl library does, we are copying the contents of
                // /sys/devices/system/node/nodeX/cpulist to the cpuset.cpus file for ensuring
                // correct numa cpu assignment.
                let line = readln_special(&PathBuf::from(format!(
                    "{}{}/cpulist",
                    NODE_TO_CPULIST, numa_node
                )))?;
                path_buf.push(CPUSET_CPUS);
                writeln_special(&path_buf, line)?;
                path_buf.pop();
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

#[cfg(test)]
mod tests {
    extern crate tempfile;

    use self::tempfile::{tempdir, tempdir_in, NamedTempFile};
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    #[test]
    fn test_inherit_from_parent() {
        // 1. If parent file does not exist, return an error.

        // This is /A/B/ .
        let dir = tempdir().expect("Cannot create temporary directory.");
        // This is /A/B/C .
        let dir2 = tempdir_in(dir.path()).expect("Cannot create temporary directory.");
        let mut path2 = PathBuf::from(dir2.path());
        let result = inherit_from_parent(&mut PathBuf::from(&path2), "inexistent");
        assert!(result.is_err());
        assert!(format!("{:?}", result).contains("ReadToString"));

        // 2. If parent file exists and is empty, will go one level up, and return error because
        // the grandparent file does not exist.
        let mut named_file = NamedTempFile::new_in(dir.path()).expect("Cannot create named file.");
        let result = inherit_from_parent(
            &mut path2.clone(),
            named_file.path().file_name().unwrap().to_str().unwrap(),
        );
        assert!(result.is_err());
        assert!(format!("{:?}", result).contains("CgroupInheritFromParent"));

        let child_file = dir2
            .path()
            .join(named_file.path().file_name().unwrap().to_str().unwrap());

        // 3. If parent file exists and is not empty, will return ok and child file will have its
        // contents.
        let some_line = "Parent line";
        writeln!(named_file, "{}", some_line).expect("Cannot write to file.");
        let result = inherit_from_parent(
            &mut path2,
            named_file.path().file_name().unwrap().to_str().unwrap(),
        );
        assert!(result.is_ok());
        let res = readln_special(&child_file).expect("Cannot read from file.");
        assert!(res == some_line);
    }
}
