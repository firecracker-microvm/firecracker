// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process;

use regex::Regex;

use crate::{readln_special, writeln_special, Error, Result};

const PROC_MOUNTS: &str = if cfg!(test) {
    "/tmp/firecracker/test/jailer/proc/mounts"
} else {
    "/proc/mounts"
};

const NODE_TO_CPULIST: &str = "/sys/devices/system/node/node"; // This constant should be removed once the `--node` argument is removed.

// Holds information on a cgroup mount point discovered on the system
struct CgroupMountPoint {
    dir: String,
    options: String,
}

// Allows creation of cgroups on the system for both versions
pub struct CgroupBuilder {
    version: u8,
    hierarchies: HashMap<String, PathBuf>,
    mount_points: Vec<CgroupMountPoint>,
}

impl CgroupBuilder {
    // Creates the builder object
    // It will discover cgroup mount points and hierarchies configured
    // on the system and cache the info required to create cgroups later
    // within this hierarchies
    pub fn new(ver: u8) -> Result<Self> {
        if ver != 1 && ver != 2 {
            return Err(Error::CgroupInvalidVersion(ver.to_string()));
        }

        let mut b = CgroupBuilder {
            version: ver,
            hierarchies: HashMap::new(),
            mount_points: Vec::new(),
        };

        // search PROC_MOUNTS for cgroup mount points
        let f =
            File::open(PROC_MOUNTS).map_err(|e| Error::FileOpen(PathBuf::from(PROC_MOUNTS), e))?;

        // Regex courtesy of Filippo.
        // This will match on each line from /proc/mounts for both v1 and v2 mount points.
        //
        // /proc/mounts cointains lines that look like this:
        // cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime,nsdelegate 0 0
        // cgroup /sys/fs/cgroup/cpu,cpuacct cgroup rw,nosuid,nodev,noexec,relatime,cpu,cpuacct 0 0
        //
        // This Regex will extract:
        //      * "/sys/fs/cgroup/unified" in the "dir" capture group.
        //      * "2" in the "ver" capture group as the cgroup version taken from "cgroup2";
        //          for v1, the "ver" capture group will be empty (len = 0).
        //      * "[...],relatime,cpu,cpuacct" in the "options" capture group; this is used for
        //          cgroupv1 to determine what controllers are mounted at the location.
        let re = Regex::new(
            r"^([a-z2]*)[[:space:]](?P<dir>.*)[[:space:]]cgroup(?P<ver>2?)[[:space:]](?P<options>.*)[[:space:]]0[[:space:]]0$",
        ).map_err(Error::RegEx)?;

        for l in BufReader::new(f).lines() {
            let l = l.map_err(|e| Error::ReadLine(PathBuf::from(PROC_MOUNTS), e))?;
            if let Some(capture) = re.captures(&l) {
                if ver == 2 && capture["ver"].len() == 1 {
                    // Found the cgroupv2 unified mountpoint; with cgroupsv2 there is only one
                    // hierarchy so we insert it in the hashmap to use it later when creating
                    // cgroups
                    b.hierarchies
                        .insert("unified".to_string(), PathBuf::from(&capture["dir"]));
                    break;
                } else if ver == 1 && capture["ver"].is_empty() {
                    // Found a cgroupv1 mountpoint; with cgroupsv1 we can have multiple hierarchies.
                    // Since we don't know which one will be used, we cache the mountpoints now,
                    // and will create the hierachies on demand when a cgroup is built.
                    b.mount_points.push(CgroupMountPoint {
                        dir: String::from(&capture["dir"]),
                        options: String::from(&capture["options"]),
                    });
                }
            }
        }

        if b.hierarchies.is_empty() && b.mount_points.is_empty() {
            Err(Error::CgroupHierarchyMissing(
                "No hierarchy found for this cgroup version.".to_string(),
            ))
        } else {
            Ok(b)
        }
    }

    // Creates a new cggroup and returns it
    pub fn new_cgroup(
        &mut self,
        file: String,
        value: String,
        id: &str,
        exec_file_name: &OsStr,
    ) -> Result<Box<dyn Cgroup>> {
        match self.version {
            1 => {
                let controller = get_controller_from_filename(&file)?;
                let path = self.get_v1_hierarchy_path(&controller)?;

                let cgroup = CgroupV1::new(file, value, id, &exec_file_name, &path)?;
                Ok(Box::new(cgroup))
            }
            2 => {
                // since all cgroups are unified for v2 and the path was discovered when
                // the builder was constructed, we try and get it right away
                let path = self
                    .hierarchies
                    .get("unified")
                    .ok_or_else(|| Error::CgroupHierarchyMissing("unified".to_string()))?;

                let cgroup = CgroupV2::new(file, value, id, &exec_file_name, &path)?;
                Ok(Box::new(cgroup))
            }
            _ => Err(Error::CgroupInvalidVersion(self.version.to_string())),
        }
    }

    // Returns the path to the root of the hierarchy for the controller specified
    // Cgroups for a controller are arranged in a hierarchy; multiple controllers
    // may share the same hierarchy
    fn get_v1_hierarchy_path(&mut self, controller: &str) -> Result<&PathBuf> {
        // First try and see if the path is alrady discovered
        match self.hierarchies.entry(controller.to_string()) {
            Occupied(e) => Ok(e.into_mut()),
            Vacant(e) => {
                // Since the path for this controller type was not already discovered
                // we need to search through the mount points to find it
                let mut path = None;
                for m in self.mount_points.iter() {
                    let v: Vec<&str> = m.options.split(',').collect();
                    if v.contains(&controller) {
                        path = Some(PathBuf::from(&m.dir));
                        break;
                    }
                }
                // It's possible that the controller is not mounted or a bad controller
                // name was specified. Return an error in this case
                match path {
                    Some(p) => Ok(e.insert(p)),
                    None => Err(Error::CgroupControllerUnavailable(controller.to_string())),
                }
            }
        }
    }

    // This function should be removed once the `--node` argument is removed.
    // This function generates the corresponding cgroups for isolating the process in the specified
    // NUMA node.
    pub fn cgroups_from_numa_node(
        &mut self,
        numa_node: u32,
        microvm_id: &str,
        exec_file_name: &OsStr,
    ) -> Result<Vec<Box<dyn Cgroup>>> {
        // Retrieve the CPUs which belongs to the specific node.
        // Similar to how numactl library does, we are copying the contents of
        // /sys/devices/system/node/nodeX/cpulist to the cpuset.cpus file for ensuring
        // correct numa cpu assignment.
        let cpus = readln_special(&PathBuf::from(format!(
            "{}{}/cpulist",
            NODE_TO_CPULIST, numa_node
        )))?;

        // Isolate the process in the specified numa_node CPUs.
        let cpuset_cpus =
            self.new_cgroup("cpuset.cpus".to_string(), cpus, microvm_id, exec_file_name)?;

        // Isolate the process in the specified numa_node memory.
        let cpuset_mems = self.new_cgroup(
            "cpuset.mems".to_string(),
            numa_node.to_string(),
            microvm_id,
            exec_file_name,
        )?;

        Ok(vec![cpuset_cpus, cpuset_mems])
    }
}

struct CgroupBase {
    file: String,      // file representing the cgroup (e.g cpuset.mems).
    value: String,     // value that will be written into the file.
    location: PathBuf, // microVM cgroup location for the specific controller.
}

pub struct CgroupV1(CgroupBase);
pub struct CgroupV2(CgroupBase);

pub trait Cgroup {
    // Write the cgroup value into the cgroup property file.
    fn write_value(&self) -> Result<()>;

    // This function will assign the process associated with the pid to the respective cgroup.
    fn attach_pid(&self) -> Result<()>;
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

// Extract the controller name from the cgroup file. The cgroup file must follow
// this format: <cgroup_controller>.<cgroup_property>.
fn get_controller_from_filename(file: &str) -> Result<&str> {
    let v: Vec<&str> = file.split('.').collect();

    // Check format <cgroup_controller>.<cgroup_property>
    if v.len() != 2 {
        return Err(Error::CgroupInvalidFile(file.to_string()));
    }

    Ok(v[0])
}

impl CgroupV1 {
    // Create a new cgroupsv1 controller
    pub fn new(
        file: String,
        value: String,
        id: &str,
        exec_file_name: &OsStr,
        controller_path: &Path,
    ) -> Result<Self> {
        let mut path = controller_path.to_path_buf();
        path.push(exec_file_name);
        path.push(id);

        Ok(CgroupV1(CgroupBase {
            file,
            value,
            location: path,
        }))
    }
}

impl Cgroup for CgroupV1 {
    fn write_value(&self) -> Result<()> {
        let location = &mut self.0.location.clone();

        // Create the cgroup directory for the controller.
        fs::create_dir_all(&self.0.location)
            .map_err(|e| Error::CreateDir(self.0.location.clone(), e))?;

        // Write the corresponding cgroup value. inherit_from_parent is used to
        // correctly propagate the value if not defined.
        inherit_from_parent(location, &self.0.file)?;
        location.push(&self.0.file);
        writeln_special(location, &self.0.value)?;

        Ok(())
    }

    fn attach_pid(&self) -> Result<()> {
        let pid = process::id();
        let location = &self.0.location.join("tasks");

        writeln_special(location, pid)?;

        Ok(())
    }
}

impl CgroupV2 {
    // Enables the specified controller along the cgroup nested path.
    // To be able to use a leaf controller within a nested cgroup hierarchy,
    // the controller needs to be enabled by writing to the cgroup.subtree_control
    // of it's parent. This rule applies recursivelly.
    fn write_all_subtree_control<P>(path: P, controller: &str) -> Result<()>
    where
        P: AsRef<Path>,
    {
        let cg_subtree_ctrl = path.as_ref().join("cgroup.subtree_control");
        if !cg_subtree_ctrl.exists() {
            return Ok(());
        }
        let parent = match path.as_ref().parent() {
            Some(p) => p,
            None => {
                writeln_special(&cg_subtree_ctrl, format!("+{}", &controller))?;
                return Ok(());
            }
        };

        Self::write_all_subtree_control(&parent, &controller)?;
        writeln_special(&cg_subtree_ctrl, format!("+{}", &controller))
    }

    // Returns true if the controller is available to be enabled from a
    // cgroup path specified by the mount_point parameter
    fn controller_available<P>(controller: &str, mount_point: P) -> bool
    where
        P: AsRef<Path>,
    {
        let controller_list_file = mount_point.as_ref().join("cgroup.controllers");
        let f = match File::open(controller_list_file) {
            Ok(f) => f,
            Err(_) => return false,
        };

        for l in BufReader::new(f).lines().flatten() {
            let controllers: Vec<&str> = l.split(' ').collect();
            if controllers.contains(&controller) {
                return true;
            }
        }
        false
    }

    // Create a new cgroupsv2 controller
    pub fn new(
        file: String,
        value: String,
        id: &str,
        exec_file_name: &OsStr,
        unified_path: &Path,
    ) -> Result<Self> {
        let controller = get_controller_from_filename(&file)?;
        let mut path = unified_path.to_path_buf();
        if CgroupV2::controller_available(controller, unified_path) {
            path.push(exec_file_name);
            path.push(id);
            Ok(CgroupV2(CgroupBase {
                file,
                value,
                location: path,
            }))
        } else {
            Err(Error::CgroupControllerUnavailable(controller.to_string()))
        }
    }
}

impl Cgroup for CgroupV2 {
    fn write_value(&self) -> Result<()> {
        let location = &mut self.0.location.clone();
        let controller = get_controller_from_filename(&self.0.file)?;

        // Create the cgroup directory for the controller.
        fs::create_dir_all(&self.0.location)
            .map_err(|e| Error::CreateDir(self.0.location.clone(), e))?;

        // Ok to unwrap since the path was just created.
        let parent = location.parent().unwrap();
        // Enable the controller in all parent directories
        CgroupV2::write_all_subtree_control(&parent, &controller)?;

        location.push(&self.0.file);
        writeln_special(location, &self.0.value)?;

        Ok(())
    }

    fn attach_pid(&self) -> Result<()> {
        let pid = process::id();
        let location = &self.0.location.join("cgroup.procs");

        writeln_special(location, pid)?;

        Ok(())
    }
}

#[cfg(test)]
pub mod test_util {
    use std::fs::{self, File, OpenOptions};
    use std::io::Write;
    use std::path::{Path, PathBuf};

    use super::PROC_MOUNTS;

    pub struct MockCgroupFs {
        mounts_file: File,
    }

    // Helper object that simulates the layout of the cgroup file system
    // This can be used for testing regardless of the availablity of a particular
    // version of cgroups on the system
    impl MockCgroupFs {
        const MOCK_PROCDIR: &'static str = "/tmp/firecracker/test/jailer/proc";
        pub const MOCK_SYS_CGROUPS_DIR: &'static str = "/tmp/firecracker/test/jailer/sys_cgroup";

        pub fn create_file_with_contents<P>(
            filename: P,
            contents: &str,
        ) -> std::result::Result<(), std::io::Error>
        where
            P: AsRef<Path>,
        {
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&filename)?;

            writeln!(file, "{}", contents)?;
            Ok(())
        }

        pub fn new() -> std::result::Result<MockCgroupFs, std::io::Error> {
            // create a mock /proc/mounts file in a temporary directory
            fs::create_dir_all(Self::MOCK_PROCDIR)?;
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(PROC_MOUNTS)?;

            Ok(MockCgroupFs { mounts_file: file })
        }

        // Populate the mocked proc/mounts file with cgroupv2 entries
        // Also create a directory structure that simulates cgroupsv2 layout
        pub fn add_v2_mounts(&mut self) -> std::result::Result<(), std::io::Error> {
            writeln!(
                self.mounts_file,
                "cgroupv2 {}/unified cgroup2 rw,nosuid,nodev,noexec,relatime,nsdelegate 0 0",
                Self::MOCK_SYS_CGROUPS_DIR
            )?;
            let cg_unified_path = PathBuf::from(format!("{}/unified", Self::MOCK_SYS_CGROUPS_DIR));
            let _ = fs::create_dir_all(&cg_unified_path)?;
            Self::create_file_with_contents(
                cg_unified_path.join("cgroup.controllers"),
                "cpuset cpu io memory pids",
            )?;
            Self::create_file_with_contents(cg_unified_path.join("cgroup.subtree_control"), "")?;
            Ok(())
        }

        // Populate the mocked proc/mounts file with cgroupv1 entries
        pub fn add_v1_mounts(&mut self) -> std::result::Result<(), std::io::Error> {
            let controllers = vec![
                "memory",
                "net_cls,net_prio",
                "pids",
                "cpuset",
                "cpu,cpuacct",
            ];

            for c in &controllers {
                writeln!(
                    self.mounts_file,
                    "cgroup {}/{} cgroup rw,nosuid,nodev,noexec,relatime,{} 0 0",
                    Self::MOCK_SYS_CGROUPS_DIR,
                    c,
                    c,
                )?;
            }
            Ok(())
        }
    }

    // Cleanup created files when object goes out of scope
    impl Drop for MockCgroupFs {
        fn drop(&mut self) {
            let _ = fs::remove_file(PROC_MOUNTS);
            let _ = fs::remove_dir_all("/tmp/firecracker/test");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Write};
    use std::path::PathBuf;

    use super::*;
    use crate::cgroup::test_util::MockCgroupFs;
    use utils::tempdir::TempDir;
    use utils::tempfile::TempFile;

    // Utility function to read the first line in a file
    fn read_first_line<P>(filename: P) -> std::result::Result<String, std::io::Error>
    where
        P: AsRef<Path>,
    {
        let file = File::open(filename)?;
        let mut reader = BufReader::new(file);
        let mut buf = String::new();
        reader.read_line(&mut buf)?;

        Ok(buf)
    }

    #[test]
    fn test_cgroup_builder_no_mounts() {
        let builder = CgroupBuilder::new(1);
        assert!(builder.is_err());
    }

    #[test]
    fn test_cgroup_builder_v1() {
        let mut mock_cgroups = MockCgroupFs::new().unwrap();
        assert!(!mock_cgroups.add_v1_mounts().is_err());
        let builder = CgroupBuilder::new(1);
        assert!(!builder.is_err());
    }

    #[test]
    fn test_cgroup_builder_v2() {
        let mut mock_cgroups = MockCgroupFs::new().unwrap();
        assert!(!mock_cgroups.add_v2_mounts().is_err());
        let builder = CgroupBuilder::new(2);
        assert!(!builder.is_err());
    }

    #[test]
    fn test_cgroup_builder_v2_with_v1_mounts() {
        let mut mock_cgroups = MockCgroupFs::new().unwrap();
        assert!(!mock_cgroups.add_v1_mounts().is_err());
        let builder = CgroupBuilder::new(2);
        assert!(builder.is_err());
    }

    #[test]
    fn test_cgroup_builder_v1_with_v2_mounts() {
        let mut mock_cgroups = MockCgroupFs::new().unwrap();
        assert!(!mock_cgroups.add_v2_mounts().is_err());
        let builder = CgroupBuilder::new(1);
        assert!(builder.is_err());
    }

    #[test]
    fn test_cgroup_build() {
        let mut mock_cgroups = MockCgroupFs::new().unwrap();
        assert!(!mock_cgroups.add_v1_mounts().is_err());
        assert!(!mock_cgroups.add_v2_mounts().is_err());

        for v in &[1, 2] {
            let mut builder = CgroupBuilder::new(*v).unwrap();

            let cg = builder.new_cgroup(
                "cpuset.mems".to_string(),
                "1".to_string(),
                "101",
                OsStr::new("fc_test_cg"),
            );
            assert!(!cg.is_err());
        }
    }

    #[test]
    fn test_cgroup_build_invalid() {
        let mut mock_cgroups = MockCgroupFs::new().unwrap();
        assert!(!mock_cgroups.add_v1_mounts().is_err());
        assert!(!mock_cgroups.add_v2_mounts().is_err());

        for v in &[1, 2] {
            let mut builder = CgroupBuilder::new(*v).unwrap();
            let cg = builder.new_cgroup(
                "invalid.cg".to_string(),
                "1".to_string(),
                "101",
                OsStr::new("fc_test_cg"),
            );
            assert!(cg.is_err());
        }
    }

    #[test]
    fn test_cgroup_v2_write_value() {
        let mut mock_cgroups = MockCgroupFs::new().unwrap();
        assert!(!mock_cgroups.add_v2_mounts().is_err());
        let builder = CgroupBuilder::new(2);
        assert!(!builder.is_err());

        let mut builder = CgroupBuilder::new(2).unwrap();
        let cg = builder.new_cgroup(
            "cpuset.mems".to_string(),
            "1".to_string(),
            "101",
            OsStr::new("fc_test_cgv2"),
        );
        assert!(!cg.is_err());
        let cg = cg.unwrap();

        let cg_root = PathBuf::from(format!("{}/unified", MockCgroupFs::MOCK_SYS_CGROUPS_DIR));

        // with real cgroups these files are created automatically
        // since the mock will not do it automatically, we create it here
        fs::create_dir_all(cg_root.join("fc_test_cgv2/101")).unwrap();
        MockCgroupFs::create_file_with_contents(
            cg_root.join("fc_test_cgv2/cgroup.subtree_control"),
            "",
        )
        .unwrap();
        MockCgroupFs::create_file_with_contents(
            cg_root.join("fc_test_cgv2/101/cgroup.subtree_control"),
            "",
        )
        .unwrap();

        assert!(!cg.write_value().is_err());

        // check that the value was written correctly
        assert!(cg_root.join("fc_test_cgv2/101/cpuset.mems").exists());
        assert_eq!(
            read_first_line(cg_root.join("fc_test_cgv2/101/cpuset.mems")).unwrap(),
            "1\n"
        );

        // check that the controller was enabled in all parent dirs
        assert!(read_first_line(cg_root.join("cgroup.subtree_control"))
            .unwrap()
            .contains("cpuset"));
        assert!(
            read_first_line(cg_root.join("fc_test_cgv2/cgroup.subtree_control"))
                .unwrap()
                .contains("cpuset")
        );
        assert!(
            !read_first_line(cg_root.join("fc_test_cgv2/101/cgroup.subtree_control"))
                .unwrap()
                .contains("cpuset")
        );
    }

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
        let mut result = get_controller_from_filename(file);
        assert!(result.is_ok());
        assert!(matches!(result, Ok(ctrl) if ctrl == "cpuset"));

        // Check invalid file
        file = "cpusetcpu";
        result = get_controller_from_filename(file);
        assert!(result.is_err());
        assert!(format!("{:?}", result).contains("CgroupInvalidFile"));

        // Check invalid file
        file = "cpu.set.cpu";
        result = get_controller_from_filename(file);
        assert!(result.is_err());
        assert!(format!("{:?}", result).contains("CgroupInvalidFile"));

        // Check empty file
        file = "";
        result = get_controller_from_filename(file);
        assert!(result.is_err());
        assert!(format!("{:?}", result).contains("CgroupInvalidFile"));
    }
}
