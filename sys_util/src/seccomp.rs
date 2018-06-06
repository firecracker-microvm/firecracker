// Copyright 2018 Amazon.com, Inc. or its affiliates.  All Rights Reserved.

extern crate libc;

/// BPF instruction structure definition.
/// See /usr/include/linux/filter.h .
#[repr(C)]
#[derive(Debug, PartialEq)]
struct sock_filter {
    pub code: ::std::os::raw::c_ushort,
    pub jt: ::std::os::raw::c_uchar,
    pub jf: ::std::os::raw::c_uchar,
    pub k: ::std::os::raw::c_uint,
}

/// BPF structure definition for filter array.
/// See /usr/include/linux/filter.h .
#[repr(C)]
#[derive(Debug)]
struct sock_fprog {
    pub len: ::std::os::raw::c_ushort,
    pub filter: *const sock_filter,
}

/// BPF filter machine instructions
///  See /usr/include/linux/bpf_common.h .
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_JMP: u16 = 0x05;
const BPF_K: u16 = 0x00;
const BPF_LD: u16 = 0x00;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;

/// Return codes for BPF programs.
///  See /usr/include/linux/seccomp.h .
const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;
const SECCOMP_RET_KILL: u32 = 0x00000000;
const SECCOMP_RET_TRAP: u32 = 0x00030000;

/// x86_64 architecture identifier.
/// See /usr/include/linux/audit.h .
/// Defined as:
/// `#define AUDIT_ARCH_X86_64	(EM_X86_64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)`
const AUDIT_ARCH_X86_64: u32 = 62 | 0x80000000 | 0x40000000;

/// List of allowed syscalls, necessary for Firecracker to function correctly.
const ALLOWED_SYSCALLS: &[i64] = &[
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_open,
    libc::SYS_close,
    libc::SYS_stat,
    libc::SYS_fstat,
    libc::SYS_lseek,
    libc::SYS_mmap,
    libc::SYS_mprotect,
    libc::SYS_munmap,
    libc::SYS_brk,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_ioctl,
    libc::SYS_readv,
    libc::SYS_writev,
    libc::SYS_pipe,
    libc::SYS_dup,
    libc::SYS_socket,
    libc::SYS_accept,
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_clone,
    libc::SYS_execve,
    libc::SYS_exit,
    libc::SYS_fcntl,
    libc::SYS_readlink,
    libc::SYS_sigaltstack,
    libc::SYS_prctl,
    libc::SYS_arch_prctl,
    libc::SYS_futex,
    libc::SYS_sched_getaffinity,
    libc::SYS_set_tid_address,
    libc::SYS_epoll_ctl,
    libc::SYS_epoll_pwait,
    libc::SYS_eventfd2,
    libc::SYS_epoll_create1,
    libc::SYS_getrandom,
];

/// Builds a "jump" BPF instruction.
#[allow(non_snake_case)]
fn BPF_JUMP(code: u16, k: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter { code, jt, jf, k }
}

/// Builds a "statement" BPF instruction.
#[allow(non_snake_case)]
fn BPF_STMT(code: u16, k: u32) -> sock_filter {
    sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

/// Builds a sequence of BPF instructions that validate the underlying architecture.
#[allow(non_snake_case)]
fn VALIDATE_ARCHITECTURE() -> Vec<sock_filter> {
    vec![
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 4),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
    ]
}

/// Builds a sequence of BPF instructions that are followed by syscall examination.
#[allow(non_snake_case)]
fn EXAMINE_SYSCALL() -> Vec<sock_filter> {
    vec![BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 0)]
}

/// Builds a sequence of BPF instructions that allow a syscall to go through.
#[allow(non_snake_case)]
fn ALLOW_SYSCALL(syscall_number: i64) -> Vec<sock_filter> {
    vec![
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, syscall_number as u32, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
    ]
}

/// Builds a sequence of BPF instructions that emit SISYS when a syscall is denied.
#[allow(non_snake_case)]
fn SIGNAL_PROCESS() -> Vec<sock_filter> {
    vec![BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRAP)]
}

/// Builds the array of filter instructions and sends them to the kernel.
pub fn setup_seccomp() -> Result<(), i32> {
    let mut filters = Vec::new();

    filters.extend(VALIDATE_ARCHITECTURE());
    filters.extend(EXAMINE_SYSCALL());
    for &syscall in ALLOWED_SYSCALLS {
        filters.extend(ALLOW_SYSCALL(syscall));
    }
    filters.extend(SIGNAL_PROCESS());

    unsafe {
        {
            let rc = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            if rc != 0 {
                return Err(*libc::__errno_location());
            }
        }

        let filter = sock_fprog {
            len: filters.len() as u16,
            filter: filters.as_ptr(),
        };
        let filter_ptr = &filter as *const sock_fprog;

        {
            let rc = libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, filter_ptr);
            if rc != 0 {
                return Err(*libc::__errno_location());
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bpf_functions() {
        {
            let ret = VALIDATE_ARCHITECTURE();
            let instructions = vec![
                sock_filter {
                    code: 32,
                    jt: 0,
                    jf: 0,
                    k: 4,
                },
                sock_filter {
                    code: 21,
                    jt: 1,
                    jf: 0,
                    k: 0xC000003E,
                },
                sock_filter {
                    code: 6,
                    jt: 0,
                    jf: 0,
                    k: 0,
                },
            ];
            assert_eq!(ret, instructions);
        }

        {
            let ret = EXAMINE_SYSCALL();
            let instructions = vec![sock_filter {
                code: 32,
                jt: 0,
                jf: 0,
                k: 0,
            }];
            assert_eq!(ret, instructions);
        }

        {
            let ret = ALLOW_SYSCALL(123);
            let instructions = vec![
                sock_filter {
                    code: 21,
                    jt: 0,
                    jf: 1,
                    k: 123,
                },
                sock_filter {
                    code: 6,
                    jt: 0,
                    jf: 0,
                    k: 0x7FFF0000,
                },
            ];
            assert_eq!(ret, instructions);
        }

        {
            let ret = SIGNAL_PROCESS();
            let instructions = vec![sock_filter {
                code: 6,
                jt: 0,
                jf: 0,
                k: 0x30000,
            }];
            assert_eq!(ret, instructions);
        }
    }
}
