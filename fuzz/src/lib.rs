// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod block;
pub mod panic;
pub mod virtio;

use std::fs::File;
use std::os::fd::FromRawFd;
use std::path::{Path, PathBuf};

/// Creates an anonymous in-memory file via `memfd_create`, returning the `File` and a
/// `/proc/self/fd/N` path that can be passed to APIs expecting a filesystem path.
/// This avoids creating entries in `/tmp`, preventing inode exhaustion during long fuzz campaigns.
pub fn make_memfd(name: &str) -> (File, String) {
    let c_name = std::ffi::CString::new(name).unwrap();
    let fd = unsafe { libc::memfd_create(c_name.as_ptr(), 0) };
    assert!(
        0 <= fd,
        "memfd_create failed: {}",
        std::io::Error::last_os_error()
    );
    let file = unsafe { File::from_raw_fd(fd) };
    let path = format!("/proc/self/fd/{fd}");
    (file, path)
}

/// Remove leftover dirs from crashed processes and generate new dir name for this PID.
///
/// Each fuzzer process gets its own directory under `/tmp` named `<prefix>_<pid>`. On startup,
/// we scan for directories from dead processes and remove them. This prevents inode exhaustion
/// in `/tmp` during long fuzz campaigns where crashes leave behind orphaned temp files.
pub fn remove_old_and_determine_new_work_dir(prefix: &str) -> PathBuf {
    let tmp = Path::new("/tmp");
    let pattern = format!("{prefix}_");
    if let Ok(entries) = std::fs::read_dir(tmp) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if let Some(pid_str) = name.strip_prefix(&pattern) {
                if let Ok(pid) = pid_str.parse::<i32>() {
                    // kill(pid, 0) checks existence without sending a signal.
                    if unsafe { libc::kill(pid, 0) } == -1 {
                        let _ = std::fs::remove_dir_all(entry.path());
                    }
                }
            }
        }
    }

    tmp.join(format!("{pattern}{}", std::process::id()))
}

/// Returns true if sufficient hugepages are available for the given memory size.
pub fn check_hugepages_available(mem_size: usize) -> bool {
    let meminfo = std::fs::read_to_string("/proc/meminfo").expect("Failed to read /proc/meminfo");

    let free_hugepages = meminfo
        .lines()
        .find(|line| line.starts_with("HugePages_Free:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|n| n.parse::<usize>().ok())
        .unwrap_or(0);

    // Each hugepage is 2MB
    let required_hugepages = mem_size.div_ceil(0x200000);
    let ret = free_hugepages >= required_hugepages;
    if !ret {
        eprintln!(
            "Lack of hugepages: required {}, free {}",
            required_hugepages, free_hugepages
        );
    }
    ret
}

#[macro_export]
macro_rules! afl_main {
    ($target_function: path) => {
        afl_main!($target_function[]);
    };

    ($target_function: path, $prefix: expr) => {
        fn main() {
            // no need to clean up, since the fuzzer loop will
            // run forever / until first crash
            let work_dir_path = $crate::remove_old_and_determine_new_work_dir($prefix);

            fuzz!(|data: &[u8]| {
                let _ = std::fs::remove_dir_all(&work_dir_path);
                std::fs::create_dir_all(&work_dir_path).expect("failed to create fuzzer work dir");

                let _ = $target_function(data, &work_dir_path);
            });
        }
    };

    // Have to use brackets instead of parenthesis due to rust macro rules not allowing `(` after a 'path'
    ($target_function: path[$($name: ident: $typ: ty),*]) => {
        fn main() {
            $(
                let mut $name: Option<$typ> = None;
            )*

            fuzz!(|data: &[u8]| {
                let _ = $target_function(data, $(&mut $name),*);
            });
        }
    };
}

#[macro_export]
macro_rules! stdin_main {
    ($target_function: path) => {
        stdin_main!($target_function[]);
    };

    ($target_function: path, $prefix: expr) => {
        fn main() {
            use std::io::Read;
            use env_logger::{Builder, Env};
            Builder::from_env(Env::default().default_filter_or("off")).init();

            $crate::panic::setup_post_mortem_hook();

            let work_dir_path = $crate::remove_old_and_determine_new_work_dir($prefix);

            let _ = std::fs::remove_dir_all(&work_dir_path);
            std::fs::create_dir_all(&work_dir_path).expect("failed to create fuzzer work dir");

            let mut data = Vec::new();
            std::io::stdin().read_to_end(&mut data).unwrap();
            let _ = $target_function(&data, &work_dir_path);

            let _ = std::fs::remove_dir_all(&work_dir_path);
        }
    };

    ($target_function: path[$($name: ident: $typ: ty),*]) => {
        fn main() {
            use std::io::Read;
            use env_logger::{Builder, Env};
            Builder::from_env(Env::default().default_filter_or("off")).init();

            $crate::panic::setup_post_mortem_hook();

            let mut data = Vec::new();
            std::io::stdin().read_to_end(&mut data).unwrap();
            let _ = $target_function(&data, $(&mut None::<$typ>),*);
        }
    };
}
