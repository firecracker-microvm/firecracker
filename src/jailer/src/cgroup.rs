// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process;

use regex::Regex;

use super::{Error, Result};

const PROC_MOUNTS: &str = "/proc/mounts";
const NODE_TO_CPULIST: &str = "/sys/devices/system/node/node"; // This constant should be removed once the `--node` argument is removed.

pub struct Cgroup {
    file: String,      // file representing the cgroup (e.g cpuset.mems).
    value: String,     // value that will be written into the file.
    location: PathBuf, // microVM cgroup location for the specific controller.
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

// This function should be removed once the `--node` argument is removed.
// This function generates the corresponding cgroups for isolating the process in the specified
// NUMA node.
pub fn cgroups_from_numa_node(
    numa_node: u32,
    microvm_id: &str,
    exec_file_name: &OsStr,
) -> Result<Vec<Cgroup>> {
    // Retrieve the CPUs which belongs to the specific node.
    // Similar to how numactl library does, we are copying the contents of
    // /sys/devices/system/node/nodeX/cpulist to the cpuset.cpus file for ensuring
    // correct numa cpu assignment.
    let cpus = readln_special(&PathBuf::from(format!(
        "{}{}/cpulist",
        NODE_TO_CPULIST, numa_node
    )))?;

    // Isolate the process in the specified numa_node CPUs.
    let cpuset_cpus = Cgroup::new("cpuset.cpus".to_string(), cpus, microvm_id, exec_file_name)?;

    // Isolate the process in the specified numa_node memory.
    let cpuset_mems = Cgroup::new(
        "cpuset.mems".to_string(),
        numa_node.to_string(),
        microvm_id,
        exec_file_name,
    )?;

    Ok(vec![cpuset_cpus, cpuset_mems])
}

impl Cgroup {
    pub fn new(file: String, value: String, id: &str, exec_file_name: &OsStr) -> Result<Self> {
        let cgroup_location = Self::get_location(&file, exec_file_name, id)?;

        Ok(Cgroup {
            file,
            value,
            location: cgroup_location,
        })
    }

    // Write the cgroup value into the cgroup property file.
    pub fn write_value(&self) -> Result<()> {
        let location = &mut self.location.clone();

        // Create the cgroup directory for the controller.
        fs::create_dir_all(&self.location)
            .map_err(|e| Error::CreateDir(self.location.clone(), e))?;

        // Write the corresponding cgroup value. inherit_from_parent is used to
        // correctly propagate the value if not defined.
        inherit_from_parent(location, &self.file)?;
        location.push(&self.file);
        writeln_special(location, &self.value)?;

        Ok(())
    }

    // This writes the pid of the current process to the tasks file. Tasks files are special files,
    // that when written to, will assign the process associated with the pid to the respective cgroup.
    pub fn attach_pid(&self) -> Result<()> {
        let pid = process::id();
        let location = &self.location.join("tasks");

        writeln_special(location, pid)?;

        Ok(())
    }

    // Extract the controller name from the cgroup file. The cgroup file must follow
    // this format: <cgroup_controller>.<cgroup_property>.
    fn get_controller(file: &str) -> Result<&str> {
        let v: Vec<&str> = file.split('.').collect();

        // Check format <cgroup_controller>.<cgroup_property>
        if v.len() != 2 {
            return Err(Error::CgroupInvalidFile(file.to_string()));
        }

        Ok(v[0])
    }

    // Return the path of the cgroup subfolder for a specific controller.
    // (<mountpoint>/<controller>/<exec_file_name>/<id>).
    fn get_location(file: &str, exec_file_name: &OsStr, id: &str) -> Result<PathBuf> {
        let controller = Self::get_controller(file)?;
        let f =
            File::open(PROC_MOUNTS).map_err(|e| Error::FileOpen(PathBuf::from(PROC_MOUNTS), e))?;

        // Regex courtesy of Filippo.
        let re = Regex::new(
            r"^([a-z]*)[[:space:]](?P<dir>.*)[[:space:]]cgroup[[:space:]](?P<options>.*)[[:space:]]0[[:space:]]0$",
        ).map_err(Error::RegEx)?;
        for l in BufReader::new(f).lines() {
            let l = l.map_err(|e| Error::ReadLine(PathBuf::from(PROC_MOUNTS), e))?;
            if let Some(capture) = re.captures(&l) {
                let v: Vec<&str> = capture["options"].split(',').collect();

                if v.contains(&controller) {
                    let mut path = PathBuf::from(&capture["dir"]);
                    path.push(exec_file_name);
                    path.push(id);

                    return Ok(path);
                }
            }
        }

        Err(Error::CgroupLineNotFound(
            PROC_MOUNTS.to_string(),
            controller.to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::path::PathBuf;

    use super::*;
    use utils::tempdir::TempDir;
    use utils::tempfile::TempFile;

    #[test]
    fn test_inherit_from_parent() {
        // 1. If parent file does not exist, return an error.

        // This is /A/B/ .
        let dir = TempDir::new().expect("Cannot create temporary directory.");
        // This is /A/B/C .
        let dir2 = TempDir::new_in(dir.as_path()).expect("Cannot create temporary directory.");
        let mut path2 = PathBuf::from(dir2.as_path());
        let result = inherit_from_parent(&mut PathBuf::from(&path2), "inexistent");
        assert!(result.is_err());
        assert!(format!("{:?}", result).contains("ReadToString"));

        // 2. If parent file exists and is empty, will go one level up, and return error because
        // the grandparent file does not exist.
        let named_file = TempFile::new_in(dir.as_path()).expect("Cannot create named file.");
        let result =
            inherit_from_parent(&mut path2.clone(), named_file.as_path().to_str().unwrap());
        assert!(result.is_err());
        assert!(format!("{:?}", result).contains("CgroupInheritFromParent"));

        let child_file = dir2.as_path().join(named_file.as_path().to_str().unwrap());

        // 3. If parent file exists and is not empty, will return ok and child file will have its
        // contents.
        let some_line = "Parent line";
        writeln!(named_file.as_file(), "{}", some_line).expect("Cannot write to file.");
        let result = inherit_from_parent(&mut path2, named_file.as_path().to_str().unwrap());
        assert!(result.is_ok());
        let res = readln_special(&child_file).expect("Cannot read from file.");
        assert!(res == some_line);
    }

    #[test]
    fn test_get_controller() {
        let mut file = "cpuset.cpu";

        // Check valid file.
        let mut result = Cgroup::get_controller(file);
        assert!(result.is_ok());
        assert!(matches!(result, Ok(ctrl) if ctrl == "cpuset"));

        // Check invalid file
        file = "cpusetcpu";
        result = Cgroup::get_controller(file);
        assert!(result.is_err());
        assert!(format!("{:?}", result).contains("CgroupInvalidFile"));

        // Check invalid file
        file = "cpu.set.cpu";
        result = Cgroup::get_controller(file);
        assert!(result.is_err());
        assert!(format!("{:?}", result).contains("CgroupInvalidFile"));

        // Check empty file
        file = "";
        result = Cgroup::get_controller(file);
        assert!(result.is_err());
        assert!(format!("{:?}", result).contains("CgroupInvalidFile"));
    }

    #[test]
    fn test_get_location() {
        // Asumming cgroups are mounted on /sys/fs/cgroup
        let cgroup_path = "/sys/fs/cgroup";
        let id = "microvm-id";
        let exec_file_name = "firecracker";
        let mut file = "cpuset.cpu";

        // Check valid file
        let controller = "cpuset"; // defined to avoid calling get_controller.
        assert!(&std::path::Path::new(&format!("{}/{}", cgroup_path, controller)).exists());
        let expected_path = PathBuf::from(format!(
            "{}/{}/{}/{}",
            &cgroup_path, &controller, &exec_file_name, &id
        ));
        let mut result = Cgroup::get_location(file, OsStr::new(exec_file_name), id);
        assert!(result.is_ok());
        assert!(matches!(result, Ok(path) if path == expected_path));

        // Check file with invalid controller
        file = "invalid.cpu";
        result = Cgroup::get_location(file, OsStr::new(exec_file_name), id);
        assert!(result.is_err());
        assert!(format!("{:?}", result).contains("CgroupLineNotFound"));

        // Check empty file
        file = "";
        result = Cgroup::get_location(file, OsStr::new(exec_file_name), id);
        assert!(result.is_err());
        assert!(format!("{:?}", result).contains("CgroupInvalidFile"));
    }
}
