// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Regression test for the fatal-signal-handler async-signal-safety contract
//! (issues #6416, #6417, #6418, #6419; musl report #6435).
//!
//! The kernel delivers a synchronous fault signal (SIGSEGV, SIGSYS, ...) to the
//! *same* thread that faulted, so the handler can run on a frame that already
//! holds a non-reentrant libc lock, most importantly the allocator lock. Any
//! allocation on the handler path then re-enters that lock and deadlocks the
//! thread. #6425 fixes this by formatting the shutdown line into a stack buffer
//! in [`Logger::log_from_signal_handler`] instead of going through the
//! allocating [`log`] macros.
//!
//! This is a *supplementary* test to #6425, not a replacement for its
//! functional test: it asserts the property the fix exists for — the
//! signal-handler log path performs **zero heap allocations** — directly, with
//! an allocation-detecting global allocator. It is its own integration-test
//! binary precisely so that the custom `#[global_allocator]` is scoped to this
//! test and never perturbs the crate's other unit tests or production builds.
//!
//! It guards specifically against the regression that would re-break musl
//! (#6435), where the allocator slow path is hit more often than on glibc: a
//! future edit passing an argument whose `Display`/`Debug` allocates into
//! `log_from_signal_handler` would still format into the stack buffer but would
//! allocate while evaluating `format_args!`, re-introducing the deadlock. This
//! test fails if that happens.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use vmm::logger::{LOGGER, LoggerConfig};

/// Global allocator that forwards to the system allocator but, while *armed*,
/// records any allocation and aborts the test. Arming is per-process and used
/// only around the narrow region under test, after all setup allocations are
/// done.
struct AllocGuard;

static ARMED: AtomicBool = AtomicBool::new(false);
static ALLOC_WHILE_ARMED: AtomicUsize = AtomicUsize::new(0);

// SAFETY: `AllocGuard` forwards every call unchanged to `System`, which is a
// correct `GlobalAlloc`; the extra bookkeeping only reads/writes atomics and
// never touches the returned memory, so all `GlobalAlloc` invariants hold.
unsafe impl GlobalAlloc for AllocGuard {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.load(Ordering::SeqCst) {
            // Record rather than panic: unwinding out of the allocator is UB.
            // The test thread checks the counter after disarming.
            ALLOC_WHILE_ARMED.fetch_add(1, Ordering::SeqCst);
        }
        // SAFETY: forwarded unchanged to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded unchanged to the system allocator.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if ARMED.load(Ordering::SeqCst) {
            ALLOC_WHILE_ARMED.fetch_add(1, Ordering::SeqCst);
        }
        // SAFETY: forwarded unchanged to the system allocator.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if ARMED.load(Ordering::SeqCst) {
            ALLOC_WHILE_ARMED.fetch_add(1, Ordering::SeqCst);
        }
        // SAFETY: forwarded unchanged to the system allocator.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GUARD: AllocGuard = AllocGuard;

/// The signal-handler log path (`Logger::log_from_signal_handler`, as used by
/// every fatal-signal handler in `signal_handler.rs`) must not allocate, so it
/// cannot deadlock on the allocator lock held by the interrupted frame.
#[test]
fn log_from_signal_handler_does_not_allocate() {
    // Aim the static LOGGER at a real file: the signal path writes only when a
    // file target is configured (it stays silent on stdout, which the
    // interrupted frame may be mid-write on). Do all of this before arming.
    let logfile = vmm_sys_util::tempfile::TempFile::new().unwrap();
    LOGGER
        .update(LoggerConfig {
            log_path: Some(logfile.as_path().to_path_buf()),
            level: None,
            show_level: Some(false),
            show_log_origin: Some(false),
            module: None,
        })
        .unwrap();

    // Warm up the exact call once so any one-time lazy initialisation inside
    // the write path (if any) is paid before arming.
    LOGGER.log_from_signal_handler(format_args!("warmup {}, code {}.", 11, 0));

    // Arm, exercise the path with the real handler call sites' shapes, disarm.
    ARMED.store(true, Ordering::SeqCst);
    // generate_handler!: "Shutting down VM after intercepting signal {}, code {}."
    LOGGER.log_from_signal_handler(format_args!(
        "Shutting down VM after intercepting signal {}, code {}.",
        11, 0
    ));
    // log_sigsys_err: "Shutting down VM after intercepting a bad syscall ({})."
    LOGGER.log_from_signal_handler(format_args!(
        "Shutting down VM after intercepting a bad syscall ({}).",
        42
    ));
    // sigpipe_handler invalid-signal branch.
    LOGGER.log_from_signal_handler(format_args!("Received invalid signal {}, code {}.", 13, 0));
    ARMED.store(false, Ordering::SeqCst);

    let allocations = ALLOC_WHILE_ARMED.load(Ordering::SeqCst);
    assert_eq!(
        allocations, 0,
        "the fatal-signal-handler log path allocated {allocations} time(s); it must be \
         allocation-free (see #6419/#6435). A call site likely passes an argument whose \
         Display/Debug impl allocates into log_from_signal_handler."
    );

    // Sanity: the lines were actually written (the path is not a silent no-op).
    let contents = std::fs::read_to_string(logfile.as_path()).unwrap();
    assert!(contents.contains("intercepting signal 11"));
    assert!(contents.contains("bad syscall (42)"));
}
