// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use seccomp::{
    allow_syscall, allow_syscall_if, deserialize_binary, BpfProgram, BpfThreadMap,
    DeserializationError, Error, SeccompAction, SeccompCmpArgLen as ArgLen, SeccompCmpOp::Eq,
    SeccompCondition as Cond, SeccompFilter, SeccompRule,
};
use std::convert::TryInto;
use std::fmt;
use std::fs::File;
use utils::signal::sigrtmin;

const THREAD_CATEGORIES: [&str; 3] = ["vmm", "api", "vcpu"];

/// Error retrieving seccomp filters.
#[derive(fmt::Debug)]
pub enum FilterError {
    /// Filter deserialitaion error.
    Deserialization(DeserializationError),
    /// Invalid thread categories.
    ThreadCategories(String),
    /// Missing Thread Category.
    MissingThreadCategory(String),
    /// Seccomp error occurred.
    Seccomp(Error),
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::FilterError::*;

        match *self {
            Deserialization(ref err) => write!(f, "Filter (de)serialization failed: {}", err),
            ThreadCategories(ref categories) => {
                write!(f, "Invalid thread categories: {}", categories)
            }
            MissingThreadCategory(ref category) => {
                write!(f, "Missing thread category: {}", category)
            }
            Seccomp(ref err) => write!(f, "Seccomp error: {}", err),
        }
    }
}

/// Return an error if the BpfThreadMap contains invalid thread categories.
fn filter_thread_categories(map: BpfThreadMap) -> Result<BpfThreadMap, FilterError> {
    let (filters, invalid_filters): (BpfThreadMap, BpfThreadMap) = map
        .into_iter()
        .partition(|(k, _)| THREAD_CATEGORIES.contains(&k.as_str()));
    if !invalid_filters.is_empty() {
        // build the error message
        let mut thread_categories_string =
            invalid_filters
                .keys()
                .fold("".to_string(), |mut acc, elem| {
                    acc.push_str(elem);
                    acc.push_str(",");
                    acc
                });
        thread_categories_string.pop();
        return Err(FilterError::ThreadCategories(thread_categories_string));
    }

    for &category in THREAD_CATEGORIES.iter() {
        let category_string = category.to_string();
        if !filters.contains_key(&category_string) {
            return Err(FilterError::MissingThreadCategory(category_string));
        }
    }

    Ok(filters)
}

/// The default filter containing the allowed syscall rules required by `Firecracker` to
/// function.
/// Any non-trivial modification to this allow list needs a proper comment to specify its source
/// or why the sycall/condition is needed.
pub fn get_default_filters() -> Result<BpfThreadMap, Error> {
    let mut filters = BpfThreadMap::new();

    let filter: BpfProgram = SeccompFilter::new(
        vec![
            // Called by the api thread to receive data on socket
            allow_syscall_if(
                libc::SYS_accept4,
                or![and![Cond::new(
                    3,
                    ArgLen::DWORD,
                    Eq,
                    libc::SOCK_CLOEXEC as u64
                )?],],
            ),
            // Called for expanding the heap
            allow_syscall(libc::SYS_brk),
            // Used for metrics and logging, via the helpers in utils/src/time.rs
            // It's not called on some platforms, because of vdso optimisations. In those cases,
            // musl falls back to the regular syscall.
            allow_syscall(libc::SYS_clock_gettime),
            allow_syscall(libc::SYS_close),
            // Needed for vsock
            allow_syscall(libc::SYS_connect),
            allow_syscall(libc::SYS_epoll_ctl),
            allow_syscall(libc::SYS_epoll_pwait),
            #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
            allow_syscall(libc::SYS_epoll_wait),
            allow_syscall(libc::SYS_exit),
            allow_syscall(libc::SYS_exit_group),
            // Used by snapshotting, drive patching and rescanning
            allow_syscall_if(
                libc::SYS_fcntl,
                or![and![
                    Cond::new(1, ArgLen::DWORD, Eq, super::FCNTL_F_SETFD)?,
                    Cond::new(2, ArgLen::DWORD, Eq, super::FCNTL_FD_CLOEXEC)?,
                ],],
            ),
            // Used for drive patching & rescanning, for reading the local timezone
            allow_syscall(libc::SYS_fstat),
            // Used for snapshotting
            allow_syscall(libc::SYS_ftruncate),
            // Used for synchronization
            allow_syscall_if(
                libc::SYS_futex,
                or![
                    and![Cond::new(1, ArgLen::DWORD, Eq, super::FUTEX_WAIT_PRIVATE)?],
                    and![Cond::new(1, ArgLen::DWORD, Eq, super::FUTEX_WAKE_PRIVATE)?],
                    #[cfg(target_env = "gnu")]
                    and![Cond::new(
                        1,
                        ArgLen::DWORD,
                        Eq,
                        super::FUTEX_CMP_REQUEUE_PRIVATE
                    )?],
                ],
            ),
            // Used by glibc's tgkill
            #[cfg(target_env = "gnu")]
            allow_syscall(libc::SYS_getpid),
            allow_syscall_if(libc::SYS_ioctl, super::create_ioctl_seccomp_rule()?),
            // Used by the block device
            allow_syscall(libc::SYS_lseek),
            // Triggered by musl for some customer workloads
            #[cfg(target_env = "musl")]
            allow_syscall_if(
                libc::SYS_madvise,
                or![and![Cond::new(
                    2,
                    ArgLen::DWORD,
                    Eq,
                    libc::MADV_DONTNEED as u64
                )?],],
            ),
            // Used for re-allocating large memory regions, for example vectors
            allow_syscall(libc::SYS_mremap),
            // Used for freeing memory
            allow_syscall(libc::SYS_munmap),
            allow_syscall_if(
                libc::SYS_mmap,
                or![
                    // Used for reading the timezone in LocalTime::now()
                    and![Cond::new(3, ArgLen::DWORD, Eq, libc::MAP_SHARED as u64)?],
                    // Used by the balloon device
                    and![Cond::new(
                        3,
                        ArgLen::DWORD,
                        Eq,
                        (libc::MAP_FIXED | libc::MAP_ANONYMOUS | libc::MAP_PRIVATE) as u64
                    )?],
                ],
            ),
            #[cfg(target_arch = "x86_64")]
            allow_syscall(libc::SYS_open),
            #[cfg(target_arch = "aarch64")]
            allow_syscall(libc::SYS_openat),
            allow_syscall(libc::SYS_read),
            // Used by the API thread and vsock
            allow_syscall(libc::SYS_recvfrom),
            // SYS_rt_sigreturn is needed in case a fault does occur, so that the signal handler
            // can return. Otherwise we get stuck in a fault loop.
            allow_syscall(libc::SYS_rt_sigreturn),
            // Used by the API thread and vsock
            allow_syscall_if(
                libc::SYS_socket,
                or![and![
                    Cond::new(0, ArgLen::DWORD, Eq, libc::AF_UNIX as u64)?,
                    Cond::new(
                        1,
                        ArgLen::DWORD,
                        Eq,
                        (libc::SOCK_STREAM as u64) | (libc::SOCK_CLOEXEC as u64)
                    )?,
                    Cond::new(2, ArgLen::DWORD, Eq, 0u64)?
                ],],
            ),
            // Used to kick vcpus
            allow_syscall_if(
                libc::SYS_tkill,
                or![and![Cond::new(
                    1,
                    ArgLen::DWORD,
                    Eq,
                    (sigrtmin() + super::super::vstate::vcpu::VCPU_RTSIG_OFFSET) as u64
                )?]],
            ),
            // Used to kick vcpus, on gnu
            #[cfg(target_env = "gnu")]
            allow_syscall(libc::SYS_tgkill),
            // Needed for rate limiting
            allow_syscall_if(
                libc::SYS_timerfd_create,
                or![and![
                    Cond::new(0, ArgLen::DWORD, Eq, libc::CLOCK_MONOTONIC as u64)?,
                    Cond::new(
                        1,
                        ArgLen::DWORD,
                        Eq,
                        (libc::TFD_CLOEXEC as u64) | (libc::TFD_NONBLOCK as u64)
                    )?,
                ],],
            ),
            // Needed for rate limiting
            allow_syscall_if(
                libc::SYS_timerfd_settime,
                or![and![Cond::new(1, ArgLen::DWORD, Eq, 0u64)?],],
            ),
            allow_syscall(libc::SYS_fsync),
            allow_syscall(libc::SYS_write),
        ]
        .into_iter()
        .collect(),
        SeccompAction::Trap,
        std::env::consts::ARCH,
    )?
    .try_into()?;

    filters.insert("api".to_string(), filter.clone());
    filters.insert("vmm".to_string(), filter.clone());
    filters.insert("vcpu".to_string(), filter);

    Ok(filters)
}

/// Retrieve empty seccomp filters.
pub fn get_empty_filters() -> BpfThreadMap {
    let mut map = BpfThreadMap::new();
    map.insert("vmm".to_string(), vec![]);
    map.insert("api".to_string(), vec![]);
    map.insert("vcpu".to_string(), vec![]);
    map
}

/// Retrieve custom seccomp filters.
pub fn get_custom_filters(mut file: File) -> Result<BpfThreadMap, FilterError> {
    let map = deserialize_binary(&mut file).map_err(FilterError::Deserialization)?;
    filter_thread_categories(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use seccomp::BpfThreadMap;

    #[test]
    fn get_filters() {
        assert!(get_default_filters().is_ok());
    }

    #[test]
    fn test_filter_thread_categories() {
        // correct categories
        let mut map = BpfThreadMap::new();
        map.insert("vcpu".to_string(), vec![]);
        map.insert("vmm".to_string(), vec![]);
        map.insert("api".to_string(), vec![]);

        assert_eq!(filter_thread_categories(map).unwrap().len(), 3);

        // invalid categories
        let mut map = BpfThreadMap::new();
        map.insert("vcpu".to_string(), vec![]);
        map.insert("vmm".to_string(), vec![]);
        map.insert("thread1".to_string(), vec![]);
        map.insert("thread2".to_string(), vec![]);

        match filter_thread_categories(map).unwrap_err() {
            FilterError::ThreadCategories(err) => {
                assert!(err == "thread2,thread1" || err == "thread1,thread2")
            }
            _ => panic!("Expected ThreadCategories error."),
        }

        // missing category
        let mut map = BpfThreadMap::new();
        map.insert("vcpu".to_string(), vec![]);
        map.insert("vmm".to_string(), vec![]);

        match filter_thread_categories(map).unwrap_err() {
            FilterError::MissingThreadCategory(name) => assert_eq!(name, "api"),
            _ => panic!("Expected MissingThreadCategory error."),
        }
    }
}
