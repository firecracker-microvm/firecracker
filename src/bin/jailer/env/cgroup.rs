extern crate regex;

use std::fs::{File, create_dir_all};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{exit, id};

fn search_option(options: &str, option: &str) -> bool {
    let mut option_ = String::from(option);
    option_.push(',');
    match options.find(&option_) {
        Some(_) => return true,
        None => (),
    }
    option_ = String::from(",");
    option_.push_str(option);
    match options.find(&option_) {
        Some(_) => return true,
        None => return false,
    }
}

fn validate_options(options: &str) -> bool {
    search_option(options, "cpu") && search_option(options, "cpuset") && search_option(options, "pids")
}

fn get_line(file: &str) -> String {
    let f = match File::open(file) {
        Ok(c) => c,
        Err(_) => {
            println!("failed to open {}", file);
            exit(1);
        },
    };
    let mut stream = BufReader::new(f);
    let mut line = String::new();
    let _ = match stream.read_line(&mut line) {
        Ok(c) => c,
        Err(_) => {
            println!("failed to read {}", file);
            exit(1);
        },
    };
    line
}

fn set_line(file: &str, line: &str) {
    let mut f = match File::create(file) {
        Ok(c) => c,
        Err(_) => {
            println!("failed to open {}", file);
            exit(1);
        },
    };
    match f.write(line.as_bytes()) {
        Ok(c) => c,
        Err(_) => {
            println!("failed to write {}", file);
            exit(1);
        },
    };
    ()
}

fn create_cgroup(dir: &PathBuf) {
    // FIXUP: Handle the race with another jailer that is attempting to create the exec file root
    // cgroup (e.g., /sys/fs/cgroup/firecracker) and populating it.
    if dir.exists() == true {
        return ();
    }

    // create the cgroup (e.g., /sys/fs/cgroup/firecracker
    match create_dir_all(&dir) {
        Ok(_) => (),
        Err(_) => {
            println!("failed to create {}", dir.to_str().unwrap());
            exit(1);
        },
    }

    // read the content of the parent cgroup cpuset.cpus and cpuset.mems files (e.g.,
    // /sys/fs/cgroup/firecracker/..)
    let mut cpus_file = PathBuf::from(dir);
    cpus_file.push("../cpuset.cpus");
    let cpus = get_line(cpus_file.to_str().unwrap());
    let mut mems_file = PathBuf::from(dir);
    mems_file.push("../cpuset.mems");
    let mems = get_line(mems_file.to_str().unwrap());

    // write the content of the cgroup cpuset.cpus and cpuset.mems files
    cpus_file = PathBuf::from(dir);
    cpus_file.push("cpuset.cpus");
    set_line(cpus_file.to_str().unwrap(), &cpus);
    mems_file = PathBuf::from(dir);
    mems_file.push("cpuset.mems");
    set_line(mems_file.to_str().unwrap(), &mems);
}

pub struct Cgroup {
    dir: PathBuf,
}

impl Cgroup {
    pub fn new(id: &str, exec_file: &str) -> Cgroup {
        let f = match File::open("/proc/mounts") {
            Ok(c) => c,
            Err(_) => {
                println!("failed to open /proc/mounts");
                exit(1);
            },
        };
        let stream = BufReader::new(f);
        let re = regex::Regex::new(r"^cgroup[[:space:]](?P<dir>.*)[[:space:]]cgroup[[:space:]](?P<options>.*)[[:space:]]0[[:space:]]0$").unwrap();
        let mut base_dir = String::new();
        for l in stream.lines() {
            let line = l.unwrap();
            let m = match re.captures(&line) {
                Some(c) => c,
                None => continue,
            };
            if validate_options(&m["options"]) == false {
                continue;
            }
            if base_dir.is_empty() == false {
                println!("cannot handle more than one cgroupfs mount point");
                exit(1);
            }
            base_dir = String::from(&m["dir"]);
        }
        if base_dir.is_empty() == true {
            println!("failed to find a suitable cgroupfs mount point");
            exit(1);
        }
        let mut dir = PathBuf::from(&base_dir);
        dir.push(exec_file);
        create_cgroup(&dir);
        dir.push(id);
        create_cgroup(&dir);
        Cgroup { dir: dir, }
    }

    pub fn run(self) {
        let mut tasks_file = PathBuf::from(self.dir);
        tasks_file.push("tasks");
        let mut pid = id().to_string();
        pid.push('\n');
        set_line(tasks_file.to_str().unwrap(), &pid);
    }
}
