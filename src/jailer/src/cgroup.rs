// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process;

use regex::Regex;

use crate::{JailerError, readln_special, writeln_special};

// Holds information on a cgroup mount point discovered on the system
#[derive(Debug)]
struct CgroupMountPoint {
    dir: String,
    options: String,
}

// Holds a cache of discovered mount points and cgroup hierarchies
#[derive(Debug)]
struct CgroupHierarchies {
    hierarchies: HashMap<String, PathBuf>,
    mount_points: Vec<CgroupMountPoint>,
}

impl CgroupHierarchies {
    // Constructs a new cache of hierarchies and mount points
    // It will discover cgroup mount points and hierarchies configured
    // on the system and cache the info required to create cgroups later
    // within this hierarchies
    fn new(ver: u8, proc_mounts_path: &str) -> Result<Self, JailerError> {
        let mut h = CgroupHierarchies {
            hierarchies: HashMap::new(),
            mount_points: Vec::new(),
        };

        // search PROC_MOUNTS for cgroup mount points
        let f = File::open(proc_mounts_path)
            .map_err(|err| JailerError::FileOpen(PathBuf::from(proc_mounts_path), err))?;

        // Regex courtesy of Filippo.
        // This will match on each line from /proc/mounts for both v1 and v2 mount points.
        //
        // /proc/mounts cointains lines that look like this:
        // cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime,nsdelegate 0 0
        // cgroup /sys/fs/cgroup/cpu,cpuacct cgroup rw,nosuid,nodev,noexec,relatime,cpu,cpuacct 0 0
        //
        // This Regex will extract:
        //      * "/sys/fs/cgroup/unified" in the "dir" capture group.
        //      * "2" in the "ver" capture group as the cgroup version taken from "cgroup2"; for v1,
        //        the "ver" capture group will be empty (len = 0).
        //      * "[...],relatime,cpu,cpuacct" in the "options" capture group; this is used for
        //        cgroupv1 to determine what controllers are mounted at the location.
        let re = Regex::new(
            r"^([a-z2]*)[[:space:]](?P<dir>.*)[[:space:]]cgroup(?P<ver>2?)[[:space:]](?P<options>.*)[[:space:]]0[[:space:]]0$",
        ).map_err(JailerError::RegEx)?;

        for l in BufReader::new(f).lines() {
            let l = l.map_err(|err| JailerError::ReadLine(PathBuf::from(proc_mounts_path), err))?;
            if let Some(capture) = re.captures(&l) {
                if ver == 2 && capture["ver"].len() == 1 {
                    // Found the cgroupv2 unified mountpoint; with cgroupsv2 there is only one
                    // hierarchy so we insert it in the hashmap to use it later when creating
                    // cgroups
                    h.hierarchies
                        .insert("unified".to_string(), PathBuf::from(&capture["dir"]));
                    break;
                } else if ver == 1 && capture["ver"].is_empty() {
                    // Found a cgroupv1 mountpoint; with cgroupsv1 we can have multiple hierarchies.
                    // Since we don't know which one will be used, we cache the mountpoints now,
                    // and will create the hierarchies on demand when a cgroup is built.
                    h.mount_points.push(CgroupMountPoint {
                        dir: String::from(&capture["dir"]),
                        options: String::from(&capture["options"]),
                    });
                }
            }
        }

        if h.hierarchies.is_empty() && h.mount_points.is_empty() {
            Err(JailerError::CgroupHierarchyMissing(
                "No hierarchy found for this cgroup version.".to_string(),
            ))
        } else {
            Ok(h)
        }
    }

    // Returns the path to the root of the hierarchy for the controller specified
    // Cgroups for a controller are arranged in a hierarchy; multiple controllers
    // may share the same hierarchy
    fn get_v1_hierarchy_path(&mut self, controller: &str) -> Result<&PathBuf, JailerError> {
        // First try and see if the path is already discovered.
        match self.hierarchies.entry(controller.to_string()) {
            Occupied(entry) => Ok(entry.into_mut()),
            Vacant(entry) => {
                // Since the path for this controller type was not already discovered
                // we need to search through the mount points to find it
                let mut path = None;
                for m in self.mount_points.iter() {
                    if m.options.split(',').any(|x| x == controller) {
                        path = Some(PathBuf::from(&m.dir));
                        break;
                    }
                }
                // It's possible that the controller is not mounted or a bad controller
                // name was specified. Return an error in this case
                match path {
                    Some(p) => Ok(entry.insert(p)),
                    None => Err(JailerError::CgroupControllerUnavailable(
                        controller.to_string(),
                    )),
                }
            }
        }
    }

    // Returns the path to the root of the hierarchy
    pub fn get_v2_hierarchy_path(&self) -> Result<&PathBuf, JailerError> {
        match self.hierarchies.get("unified") {
            Some(entry) => Ok(entry),
            None => Err(JailerError::CgroupHierarchyMissing(
                "cgroupsv2 hierarchy missing".to_string(),
            )),
        }
    }
}

// Allows creation of cgroups on the system for both versions
#[derive(Debug)]
pub struct CgroupConfigurationBuilder {
    hierarchies: CgroupHierarchies,
    cgroup_conf: CgroupConfiguration,
}

impl CgroupConfigurationBuilder {
    // Creates the builder object
    // It will initialize the CgroupHierarchy cache.
    pub fn new(ver: u8, proc_mounts_path: &str) -> Result<Self, JailerError> {
        Ok(CgroupConfigurationBuilder {
            hierarchies: CgroupHierarchies::new(ver, proc_mounts_path)?,
            cgroup_conf: match ver {
                1 => Ok(CgroupConfiguration::V1(HashMap::new())),
                2 => Ok(CgroupConfiguration::V2(HashMap::new())),
                _ => Err(JailerError::CgroupInvalidVersion(ver.to_string())),
            }?,
        })
    }

    // Adds a cgroup property to the configuration
    pub fn add_cgroup_property(
        &mut self,
        file: String,
        value: String,
        id: &str,
        parent_cg: &Path,
    ) -> Result<(), JailerError> {
        match self.cgroup_conf {
            CgroupConfiguration::V1(ref mut cgroup_conf_v1) => {
                let controller = get_controller_from_filename(&file)?;
                let path = self.hierarchies.get_v1_hierarchy_path(controller)?;
                let cgroup = cgroup_conf_v1
                    .entry(String::from(controller))
                    .or_insert(CgroupV1::new(id, parent_cg, path)?);
                cgroup.add_property(file, value)?;
                Ok(())
            }
            CgroupConfiguration::V2(ref mut cgroup_conf_v2) => {
                let path = self.hierarchies.get_v2_hierarchy_path()?;
                let cgroup = cgroup_conf_v2
                    .entry(String::from("unified"))
                    .or_insert(CgroupV2::new(id, parent_cg, path)?);
                cgroup.add_property(file, value)?;
                Ok(())
            }
        }
    }

    pub fn build(self) -> CgroupConfiguration {
        self.cgroup_conf
    }

    // Returns the path to the unified controller
    pub fn get_v2_hierarchy_path(&self) -> Result<&PathBuf, JailerError> {
        self.hierarchies.get_v2_hierarchy_path()
    }
}

#[derive(Debug)]
struct CgroupProperty {
    file: String,  // file representing the cgroup (e.g cpuset.mems).
    value: String, // value that will be written into the file.
}

#[derive(Debug)]
struct CgroupBase {
    properties: Vec<CgroupProperty>,
    location: PathBuf, // microVM cgroup location for the specific controller.
}

#[derive(Debug)]
pub struct CgroupV1 {
    base: CgroupBase,
    cg_parent_depth: u16, // depth of the nested cgroup hierarchy
}

#[derive(Debug)]
pub struct CgroupV2 {
    base: CgroupBase,
    available_controllers: HashSet<String>,
}

pub trait Cgroup: Debug {
    // Adds a property (file-value) to the group
    fn add_property(&mut self, file: String, value: String) -> Result<(), JailerError>;

    // Write the all cgroup property values into the cgroup property files.
    fn write_values(&self) -> Result<(), JailerError>;

    // This function will assign the process associated with the pid to the respective cgroup.
    fn attach_pid(&self) -> Result<(), JailerError>;
}

#[derive(Debug)]
pub enum CgroupConfiguration {
    V1(HashMap<String, CgroupV1>),
    V2(HashMap<String, CgroupV2>),
}

impl CgroupConfiguration {
    pub fn setup(&self) -> Result<(), JailerError> {
        match self {
            Self::V1(conf) => setup_cgroup_conf(conf),
            Self::V2(conf) => setup_cgroup_conf(conf),
        }
    }
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
// will create a hierarchy that looks like <cgroup_base>/<parent_cgroup>/<id>. Depending on each
// particular cgroup controller, <cgroup_base> contains a number of configuration files. These are
// not actually present on a disk; they are special files exposed by the controller, and they
// usually contain a single line with some configuration value(s). When the "parent_cgroup" and <id>
// subfolders are created, configuration files with the same name appear automatically in the new
// folders, but their contents are not always automatically populated. Moreover,
// if <cgroup_base>/<parent_cgroup>/some_file is empty, then we cannot have a non-empty file with
// at <cgroup_base>/<parent_cgroup>/<id>/some_file. The inherit_from_parent function (which is based
// on the following helper function) helps with propagating the values.

// There is also a potential race condition mentioned below. Here is what it refers to: let's say we
// start multiple jailer processes, and one of them calls
// inherit_from_parent_aux(/A/<parent_cgroup>/id1, file, true), and hits case number 3) from the
// list above, thus recursively calling inherit_from_parent_aux(/A/<parent_cgroup>, file, false).
// It's entirely possible there was another process in the exact same situations, and that process
// gets to write something to /A/<parent_cgroup>/file first. In this case, the recursive call made
// by the first process to inherit_from_parent_aux(/A/<parent_cgroup>, file, false) may fail when
// writing to /A/<parent_cgroup>/file, but we can still continue, because step 4) only cares about
// the file no longer being empty, regardless of who actually got to populated its contents.

fn inherit_from_parent_aux(
    path: &Path,
    file_name: &str,
    retry_depth: u16,
) -> Result<(), JailerError> {
    // The function with_file_name() replaces the last component of a path with the given name.
    let parent_file = path.with_file_name(file_name);

    let mut line = readln_special(&parent_file)?;
    if line.is_empty() {
        if retry_depth > 0 {
            // We have to borrow "parent" from "parent_file" as opposed to "path", because then
            // we wouldn't be able to mutably borrow path at the end of this function (at least not
            // according to how the Rust borrow checker operates right now :-s)
            let parent = parent_file
                .parent()
                .ok_or_else(|| JailerError::MissingParent(parent_file.clone()))?;

            // Trying to avoid the race condition described above. We don't care about the result,
            // because we check once more if line.is_empty() after the end of this block.
            let _ = inherit_from_parent_aux(parent, file_name, retry_depth - 1);
            line = readln_special(&parent_file)?;
        }

        if line.is_empty() {
            return Err(JailerError::CgroupInheritFromParent(
                path.to_path_buf(),
                file_name.to_string(),
            ));
        }
    }

    writeln_special(&path.join(file_name), &line)?;

    Ok(())
}

fn inherit_from_parent(path: &Path, file_name: &str, depth: u16) -> Result<(), JailerError> {
    inherit_from_parent_aux(path, file_name, depth)
}

// Extract the controller name from the cgroup file. The cgroup file must follow
// this format: <cgroup_controller>.<cgroup_property>.
fn get_controller_from_filename(file: &str) -> Result<&str, JailerError> {
    let v: Vec<&str> = file.split('.').collect();

    // Check format <cgroup_controller>.<cgroup_property>
    if v.len() < 2 {
        return Err(JailerError::CgroupInvalidFile(file.to_string()));
    }

    Ok(v[0])
}

impl CgroupV1 {
    // Create a new cgroupsv1 controller
    pub fn new(id: &str, parent_cg: &Path, controller_path: &Path) -> Result<Self, JailerError> {
        let mut path = controller_path.to_path_buf();
        path.push(parent_cg);
        path.push(id);
        let mut depth = 0;
        for _ in parent_cg.components() {
            depth += 1;
        }

        Ok(CgroupV1 {
            base: CgroupBase {
                properties: Vec::new(),
                location: path,
            },
            cg_parent_depth: depth,
        })
    }
}

impl Cgroup for CgroupV1 {
    fn add_property(&mut self, file: String, value: String) -> Result<(), JailerError> {
        self.base.properties.push(CgroupProperty { file, value });
        Ok(())
    }

    fn write_values(&self) -> Result<(), JailerError> {
        // Create the cgroup directory for the controller.
        fs::create_dir_all(&self.base.location)
            .map_err(|err| JailerError::CreateDir(self.base.location.clone(), err))?;

        for property in self.base.properties.iter() {
            // Write the corresponding cgroup value. inherit_from_parent is used to
            // correctly propagate the value if not defined.
            inherit_from_parent(&self.base.location, &property.file, self.cg_parent_depth)?;
            writeln_special(&self.base.location.join(&property.file), &property.value)?;
        }

        Ok(())
    }

    fn attach_pid(&self) -> Result<(), JailerError> {
        let pid = process::id();
        let location = &self.base.location.join("tasks");

        writeln_special(location, pid)?;

        Ok(())
    }
}

impl CgroupV2 {
    // Enables the specified controller along the cgroup nested path.
    // To be able to use a leaf controller within a nested cgroup hierarchy,
    // the controller needs to be enabled by writing to the cgroup.subtree_control
    // of it's parent. This rule applies recursively.
    fn write_all_subtree_control<P>(path: P, controller: &str) -> Result<(), JailerError>
    where
        P: AsRef<Path> + Debug,
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

        Self::write_all_subtree_control(parent, controller)?;
        writeln_special(&cg_subtree_ctrl, format!("+{}", &controller))
    }

    // Returns controllers that can be enabled from the cgroup path specified
    // by the mount_point parameter
    fn detect_available_controllers<P>(mount_point: P) -> HashSet<String>
    where
        P: AsRef<Path> + Debug,
    {
        let mut controllers = HashSet::new();
        let controller_list_file = mount_point.as_ref().join("cgroup.controllers");
        let f = match File::open(controller_list_file) {
            Ok(f) => f,
            Err(_) => return controllers,
        };

        for l in BufReader::new(f).lines().map_while(Result::ok) {
            for controller in l.split(' ') {
                controllers.insert(controller.to_string());
            }
        }
        controllers
    }

    // Create a new cgroupsv2 controller
    pub fn new(id: &str, parent_cg: &Path, unified_path: &Path) -> Result<Self, JailerError> {
        let mut path = unified_path.to_path_buf();

        path.push(parent_cg);
        path.push(id);
        Ok(CgroupV2 {
            base: CgroupBase {
                properties: Vec::new(),
                location: path,
            },
            available_controllers: Self::detect_available_controllers(unified_path),
        })
    }
}

impl Cgroup for CgroupV2 {
    fn add_property(&mut self, file: String, value: String) -> Result<(), JailerError> {
        let controller = get_controller_from_filename(&file)?;
        if self.available_controllers.contains(controller) {
            self.base.properties.push(CgroupProperty { file, value });
            Ok(())
        } else {
            Err(JailerError::CgroupControllerUnavailable(
                controller.to_string(),
            ))
        }
    }

    fn write_values(&self) -> Result<(), JailerError> {
        let mut enabled_controllers: HashSet<&str> = HashSet::new();

        // Create the cgroup directory for the controller.
        fs::create_dir_all(&self.base.location)
            .map_err(|err| JailerError::CreateDir(self.base.location.clone(), err))?;

        // Ok to unwrap since the path was just created.
        let parent = self.base.location.parent().unwrap();

        for property in self.base.properties.iter() {
            let controller = get_controller_from_filename(&property.file)?;
            // enable controllers only once
            if !enabled_controllers.contains(controller) {
                // Enable the controller in all parent directories
                CgroupV2::write_all_subtree_control(parent, controller)?;
                enabled_controllers.insert(controller);
            }
            writeln_special(&self.base.location.join(&property.file), &property.value)?;
        }

        Ok(())
    }

    fn attach_pid(&self) -> Result<(), JailerError> {
        let pid = process::id();
        let location = &self.base.location.join("cgroup.procs");

        writeln_special(location, pid)?;

        Ok(())
    }
}

pub fn setup_cgroup_conf(conf: &HashMap<String, impl Cgroup>) -> Result<(), JailerError> {
    // cgroups are iterated two times as some cgroups may require others (e.g cpuset requires
    // cpuset.mems and cpuset.cpus) to be set before attaching any pid.
    for cgroup in conf.values() {
        cgroup.write_values()?;
    }
    for cgroup in conf.values() {
        cgroup.attach_pid()?;
    }
    Ok(())
}

#[cfg(test)]
pub mod test_util {
    use std::fmt::Debug;
    use std::fs::{self, File, OpenOptions};
    use std::io::Write;
    use std::path::{Path, PathBuf};

    use vmm_sys_util::tempdir::TempDir;

    #[derive(Debug)]
    pub struct MockCgroupFs {
        mounts_file: File,
        // kept to clean up on Drop
        _mock_jailer_dir: TempDir,
        pub proc_mounts_path: PathBuf,
        pub sys_cgroups_path: PathBuf,
    }

    // Helper object that simulates the layout of the cgroup file system
    // This can be used for testing regardless of the availability of a particular
    // version of cgroups on the system
    impl MockCgroupFs {
        pub fn create_file_with_contents<P: AsRef<Path> + Debug>(
            filename: P,
            contents: &str,
        ) -> std::result::Result<(), std::io::Error> {
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
            let mock_jailer_dir = TempDir::new().unwrap();
            let mock_proc_mounts = mock_jailer_dir.as_path().join("proc/mounts");
            let mock_sys_cgroups = mock_jailer_dir.as_path().join("sys_cgroup");

            // create a mock /proc/mounts file in a temporary directory
            fs::create_dir_all(mock_proc_mounts.parent().unwrap())?;
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(mock_proc_mounts.clone())?;
            Ok(MockCgroupFs {
                mounts_file: file,
                _mock_jailer_dir: mock_jailer_dir,
                proc_mounts_path: mock_proc_mounts,
                sys_cgroups_path: mock_sys_cgroups,
            })
        }

        // Populate the mocked proc/mounts file with cgroupv2 entries
        // Also create a directory structure that simulates cgroupsv2 layout
        pub fn add_v2_mounts(&mut self) -> std::result::Result<(), std::io::Error> {
            writeln!(
                self.mounts_file,
                "cgroupv2 {}/unified cgroup2 rw,nosuid,nodev,noexec,relatime,nsdelegate 0 0",
                self.sys_cgroups_path.to_str().unwrap(),
            )?;
            let cg_unified_path = self.sys_cgroups_path.join("unified");
            fs::create_dir_all(&cg_unified_path)?;
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
                    self.sys_cgroups_path.to_str().unwrap(),
                    c,
                    c,
                )?;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;
    use std::io::{BufReader, Write};
    use std::path::PathBuf;

    use vmm_sys_util::tempdir::TempDir;
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::cgroup::test_util::MockCgroupFs;

    // Utility function to read the first line in a file
    fn read_first_line<P>(filename: P) -> std::result::Result<String, std::io::Error>
    where
        P: AsRef<Path> + Debug,
    {
        let file = File::open(filename)?;
        let mut reader = BufReader::new(file);
        let mut buf = String::new();
        reader.read_line(&mut buf)?;

        Ok(buf)
    }

    #[test]
    fn test_cgroup_conf_builder_invalid_version() {
        let mock_cgroups = MockCgroupFs::new().unwrap();
        let builder =
            CgroupConfigurationBuilder::new(0, mock_cgroups.proc_mounts_path.to_str().unwrap());
        builder.unwrap_err();
    }

    #[test]
    fn test_cgroup_conf_builder_no_mounts() {
        let mock_cgroups = MockCgroupFs::new().unwrap();
        let builder =
            CgroupConfigurationBuilder::new(1, mock_cgroups.proc_mounts_path.to_str().unwrap());
        builder.unwrap_err();
    }

    #[test]
    fn test_cgroup_conf_builder_v1() {
        let mut mock_cgroups = MockCgroupFs::new().unwrap();
        mock_cgroups.add_v1_mounts().unwrap();
        let builder =
            CgroupConfigurationBuilder::new(1, mock_cgroups.proc_mounts_path.to_str().unwrap());
        builder.unwrap();
    }

    #[test]
    fn test_cgroup_conf_builder_v2() {
        let mut mock_cgroups = MockCgroupFs::new().unwrap();
        mock_cgroups.add_v2_mounts().unwrap();
        let builder =
            CgroupConfigurationBuilder::new(2, mock_cgroups.proc_mounts_path.to_str().unwrap());
        builder.unwrap();
    }

    #[test]
    fn test_cgroup_conf_builder_v2_with_v1_mounts() {
        let mut mock_cgroups = MockCgroupFs::new().unwrap();
        mock_cgroups.add_v1_mounts().unwrap();
        let builder =
            CgroupConfigurationBuilder::new(2, mock_cgroups.proc_mounts_path.to_str().unwrap());
        builder.unwrap_err();
    }

    #[test]
    fn test_cgroup_conf_builder_v2_no_mounts() {
        let mock_cgroups = MockCgroupFs::new().unwrap();
        let builder =
            CgroupConfigurationBuilder::new(2, mock_cgroups.proc_mounts_path.to_str().unwrap());
        builder.unwrap_err();
    }

    #[test]
    fn test_cgroup_conf_builder_v1_with_v2_mounts() {
        let mut mock_cgroups = MockCgroupFs::new().unwrap();
        mock_cgroups.add_v2_mounts().unwrap();
        let builder =
            CgroupConfigurationBuilder::new(1, mock_cgroups.proc_mounts_path.to_str().unwrap());
        builder.unwrap_err();
    }

    #[test]
    fn test_cgroup_conf_build() {
        let mut mock_cgroups = MockCgroupFs::new().unwrap();
        mock_cgroups.add_v1_mounts().unwrap();
        mock_cgroups.add_v2_mounts().unwrap();

        for v in &[1, 2] {
            let mut builder = CgroupConfigurationBuilder::new(
                *v,
                mock_cgroups.proc_mounts_path.to_str().unwrap(),
            )
            .unwrap();

            builder
                .add_cgroup_property(
                    "cpuset.mems".to_string(),
                    "1".to_string(),
                    "101",
                    Path::new("fc_test_cg"),
                )
                .unwrap();
            builder.build();
        }
    }

    #[test]
    fn test_cgroup_conf_build_invalid() {
        let mut mock_cgroups = MockCgroupFs::new().unwrap();
        mock_cgroups.add_v1_mounts().unwrap();
        mock_cgroups.add_v2_mounts().unwrap();

        for v in &[1, 2] {
            let mut builder = CgroupConfigurationBuilder::new(
                *v,
                mock_cgroups.proc_mounts_path.to_str().unwrap(),
            )
            .unwrap();
            builder
                .add_cgroup_property(
                    "invalid.cg".to_string(),
                    "1".to_string(),
                    "101",
                    Path::new("fc_test_cg"),
                )
                .unwrap_err();
        }
    }

    #[test]
    fn test_cgroup_conf_v1_write_value() {
        let mut mock_cgroups = MockCgroupFs::new().unwrap();
        mock_cgroups.add_v1_mounts().unwrap();

        let mut builder =
            CgroupConfigurationBuilder::new(1, mock_cgroups.proc_mounts_path.to_str().unwrap())
                .unwrap();
        builder
            .add_cgroup_property(
                "cpuset.mems".to_string(),
                "1".to_string(),
                "101",
                Path::new("fc_test_cgv1"),
            )
            .unwrap();
        let cg_conf = builder.build();

        let cg_root = mock_cgroups.sys_cgroups_path.join("cpuset");

        // with real cgroups these files are created automatically
        // since the mock will not do it automatically, we create it here
        fs::create_dir_all(cg_root.join("fc_test_cgv1/101")).unwrap();
        writeln_special(&cg_root.join("cpuset.mems"), "0-1").unwrap();
        writeln_special(&cg_root.join("fc_test_cgv1/cpuset.mems"), "0-1").unwrap();
        writeln_special(&cg_root.join("fc_test_cgv1/101/cpuset.mems"), "0-1").unwrap();

        cg_conf.setup().unwrap();

        // check that the value was written correctly
        assert!(cg_root.join("fc_test_cgv1/101/cpuset.mems").exists());
        assert_eq!(
            read_first_line(cg_root.join("fc_test_cgv1/101/cpuset.mems")).unwrap(),
            "1\n"
        );
    }

    #[test]
    fn test_cgroup_conf_v2_write_value() {
        let mut mock_cgroups = MockCgroupFs::new().unwrap();
        mock_cgroups.add_v2_mounts().unwrap();
        let builder =
            CgroupConfigurationBuilder::new(2, mock_cgroups.proc_mounts_path.to_str().unwrap());
        builder.unwrap();

        let mut builder =
            CgroupConfigurationBuilder::new(2, mock_cgroups.proc_mounts_path.to_str().unwrap())
                .unwrap();
        builder
            .add_cgroup_property(
                "cpuset.mems".to_string(),
                "1".to_string(),
                "101",
                Path::new("fc_test_cgv2"),
            )
            .unwrap();

        let cg_root = mock_cgroups.sys_cgroups_path.join("unified");

        assert_eq!(builder.get_v2_hierarchy_path().unwrap(), &cg_root);

        let cg_conf = builder.build();

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

        cg_conf.setup().unwrap();

        // check that the value was written correctly
        assert!(cg_root.join("fc_test_cgv2/101/cpuset.mems").exists());
        assert_eq!(
            read_first_line(cg_root.join("fc_test_cgv2/101/cpuset.mems")).unwrap(),
            "1\n"
        );

        // check that the controller was enabled in all parent dirs
        assert!(
            read_first_line(cg_root.join("cgroup.subtree_control"))
                .unwrap()
                .contains("cpuset")
        );
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
        let path2 = PathBuf::from(dir2.as_path());
        let result = inherit_from_parent(&path2, "inexistent", 1);
        assert!(
            matches!(result, Err(JailerError::ReadToString(_, _))),
            "{:?}",
            result
        );

        // 2. If parent file exists and is empty, will go one level up, and return error because
        // the grandparent file does not exist.
        let named_file = TempFile::new_in(dir.as_path()).expect("Cannot create named file.");
        let result = inherit_from_parent(&path2, named_file.as_path().to_str().unwrap(), 1);
        assert!(
            matches!(result, Err(JailerError::CgroupInheritFromParent(_, _))),
            "{:?}",
            result
        );

        let child_file = dir2.as_path().join(named_file.as_path().to_str().unwrap());

        // 3. If parent file exists and is not empty, will return ok and child file will have its
        // contents.
        let some_line = "Parent line";
        writeln!(named_file.as_file(), "{}", some_line).expect("Cannot write to file.");
        let result = inherit_from_parent(&path2, named_file.as_path().to_str().unwrap(), 1);
        result.unwrap();
        let res = readln_special(&child_file).expect("Cannot read from file.");
        assert!(res == some_line);
    }

    #[test]
    fn test_get_controller() {
        let mut file = "cpuset.cpu";

        // Check valid file.
        let mut result = get_controller_from_filename(file);
        assert!(
            matches!(result, Ok(ctrl) if ctrl == "cpuset"),
            "{:?}",
            result
        );

        // Check valid file with multiple '.'.
        file = "memory.swap.high";
        result = get_controller_from_filename(file);
        assert!(
            matches!(result, Ok(ctrl) if ctrl == "memory"),
            "{:?}",
            result
        );

        // Check invalid file
        file = "cpusetcpu";
        result = get_controller_from_filename(file);
        assert!(
            matches!(result, Err(JailerError::CgroupInvalidFile(_))),
            "{:?}",
            result
        );

        // Check empty file
        file = "";
        result = get_controller_from_filename(file);
        assert!(
            matches!(result, Err(JailerError::CgroupInvalidFile(_))),
            "{:?}",
            result
        );
    }
}
