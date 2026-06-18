// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! CPU-accounting threads for Nitro Enclaves (Parent-PID visibility).
//!
//! Enclave vCPUs are host-scheduled threads inside the Nitro hypervisor; to the
//! parent kernel their CPU usage would otherwise surface as paravirt steal
//! time attributed to nobody. When an enclave is created with
//! `NE_ENCLAVE_CPU_ACCOUNTING_MODE`, the NE driver keeps a per-vCPU cumulative
//! `KVM_RUN`-ns counter and exposes the `NE_ACCOUNT_VCPU` ioctl. This module
//! gives the driver a userspace task to attribute that time to: it spawns one
//! resident thread per enclave vCPU which
//!
//!   1. issues `NE_ACCOUNT_VCPU(vcpu_idx)` to register its own task as the
//!      driver's attribution target for that vCPU,
//!   2. then idles (0% CPU) so its `task_struct` stays a valid attribution
//!      target. The driver reflects the vCPU's guest time into the thread's
//!      `gtime`, so enclave CPU shows up as `fc_vcpu N` threads of the VMM in
//!      `top -H` / `pidstat` and in `/proc/stat`'s guest column.
//!
//! The thread does no work itself — it is purely an accounting anchor. The
//! lifecycle mirrors the KVM vCPU threads (see `vstate::vcpu`): each thread is
//! controlled by an [`AccountingThreadHandle`] over an mpsc channel, idles on a
//! blocking `recv()`, and is stopped + joined on drop by sending
//! [`AccountingEvent::Finish`].

use std::io;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, channel};
use std::thread;
use std::time::Duration;

use crate::logger::error;
use crate::nitro_enclave::ne_ioctl::EnclaveFd;
use crate::seccomp::{BpfProgram, apply_filter};

/// How long to wait for a CPU-accounting thread to bind (handshake) or exit
/// (teardown) before giving up, mirroring `VcpuHandle`'s `VCPU_JOIN_TIMEOUT`.
const ACCOUNTING_JOIN_TIMEOUT: Duration = Duration::from_secs(1);

/// Errors from spawning the CPU-accounting threads.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum AccountingError {
    /// Failed to duplicate the enclave fd for vCPU {idx}: {source}
    DupFd {
        /// Zero-based vCPU index whose fd dup failed.
        idx: u32,
        /// Underlying error.
        source: io::Error,
    },
    /// Failed to spawn CPU-accounting thread for vCPU {idx}: {source}
    Spawn {
        /// Zero-based vCPU index that failed to spawn.
        idx: u32,
        /// Underlying error.
        source: io::Error,
    },
    /// Failed to bind vCPU {idx} for CPU accounting: {source}
    Bind {
        /// Zero-based vCPU index that failed to bind.
        idx: u32,
        /// Underlying error.
        source: io::Error,
    },
    /// CPU-accounting thread for vCPU {idx} exited before reporting readiness
    Died {
        /// Zero-based vCPU index whose thread died early.
        idx: u32,
    },
}

/// Control message sent to a CPU-accounting thread (cf. [`crate::VcpuEvent`]).
#[derive(Debug)]
pub enum AccountingEvent {
    /// The accounting thread will exit when receiving this message.
    Finish,
}

/// Reply sent from a CPU-accounting thread to the spawner
/// (cf. [`crate::VcpuResponse`]).
#[derive(Debug)]
pub enum AccountingResponse {
    /// The thread has bound its vCPU and applied its seccomp filter.
    Ready,
    /// The thread failed to bind or filter; carries the cause.
    Error(io::Error),
}

/// Handle to a single CPU-accounting thread (cf. [`crate::VcpuHandle`]).
#[derive(Debug)]
pub struct AccountingThreadHandle {
    event_sender: Sender<AccountingEvent>,
    response_receiver: Receiver<AccountingResponse>,
    // Wrapped in Option so the thread can be joined in Drop.
    thread: Option<thread::JoinHandle<()>>,
}

impl AccountingThreadHandle {
    /// Sends a control event to the accounting thread. Errors (channel closed
    /// because the thread already exited) are returned, not panicked on.
    pub fn send_event(
        &mut self,
        event: AccountingEvent,
    ) -> Result<(), mpsc::SendError<AccountingEvent>> {
        self.event_sender.send(event)
    }
}

impl Drop for AccountingThreadHandle {
    fn drop(&mut self) {
        // By the time we get here a Finish event has been sent (see
        // AccountingThreads::drop). Wait for the thread to drop its response
        // sender (channel disconnect) with a timeout rather than joining
        // unconditionally, so a thread that never finished panics instead of
        // hanging teardown forever on the join below — mirroring
        // VcpuHandle::drop.
        let thread = self.thread.take().unwrap();
        loop {
            match self.response_receiver.recv_timeout(ACCOUNTING_JOIN_TIMEOUT) {
                // Sender dropped: the thread has exited.
                Err(RecvTimeoutError::Disconnected) => break,
                Err(RecvTimeoutError::Timeout) => {
                    let name = thread.thread().name().unwrap_or("<unnamed>");
                    panic!("Timed out waiting for CPU-accounting thread '{name}' to exit")
                }
                // Unexpected stray response queued at teardown; discard it.
                Ok(response) => {
                    error!("Discarding unexpected accounting response at teardown: {response:?}");
                }
            }
        }
        // Propagate a panic from the accounting thread, same as the KVM vCPU
        // threads do on teardown (`VcpuHandle::drop`).
        thread.join().unwrap();
    }
}

/// Owns the per-vCPU CPU-accounting threads and stops + joins them on drop,
/// mirroring how [`crate::Vmm`] tears down its vCPU threads.
#[derive(Debug)]
pub struct AccountingThreads {
    handles: Vec<AccountingThreadHandle>,
}

impl AccountingThreads {
    /// Spawn one CPU-accounting thread per enclave vCPU and synchronously
    /// verify each one bound its vCPU.
    ///
    /// `enclave_fd` must belong to an enclave created with
    /// `NE_ENCLAVE_CPU_ACCOUNTING_MODE` that has already been started. Each
    /// thread gets its own duplicate of the fd to issue `NE_ACCOUNT_VCPU`, and
    /// applies `vcpu_filter` (the "vcpu" seccomp filter) to itself.
    ///
    /// Fatal on any per-thread failure: already-started threads are stopped and
    /// joined, and an error is returned so the enclave launch fails cleanly.
    pub fn spawn(
        enclave_fd: &EnclaveFd,
        vcpu_count: u32,
        vcpu_filter: Arc<BpfProgram>,
    ) -> Result<Self, AccountingError> {
        // Build the owner up front so that an early return (via `?` or the
        // handshake below) drops it, which sends Finish to every already-spawned
        // thread and joins it — no leaked or deadlocked threads on failure.
        let mut threads = AccountingThreads {
            handles: Vec::with_capacity(vcpu_count as usize),
        };

        for idx in 0..vcpu_count {
            let (event_sender, event_receiver) = channel::<AccountingEvent>();
            let (response_sender, response_receiver) = channel::<AccountingResponse>();
            // Each thread owns its own enclave fd dup.
            let thread_fd = enclave_fd
                .try_clone()
                .map_err(|source| AccountingError::DupFd { idx, source })?;
            let filter = Arc::clone(&vcpu_filter);

            let thread = thread::Builder::new()
                .name(format!("fc_vcpu {idx}"))
                .spawn(move || {
                    // Bind before applying the filter, so NE_ACCOUNT_VCPU needs
                    // no seccomp allowlist entry.
                    let res = thread_fd
                        .account_vcpu(idx)
                        .and_then(|()| apply_filter(&filter).map_err(io::Error::other));
                    match res {
                        Ok(()) => {
                            // If the spawner is gone there is nothing to anchor.
                            if response_sender.send(AccountingResponse::Ready).is_err() {
                                return;
                            }
                        }
                        Err(e) => {
                            error!("CPU-accounting thread for vCPU {idx} failed to bind: {e}");
                            let _ = response_sender.send(AccountingResponse::Error(e));
                            return;
                        }
                    }

                    // Idle as the driver's attribution target until Finish (or
                    // the sender drops). `thread_fd` was moved into the closure,
                    // so it stays open for the thread's whole life.
                    while !matches!(event_receiver.recv(), Ok(AccountingEvent::Finish) | Err(_)) {}
                })
                .map_err(|source| AccountingError::Spawn { idx, source })?;

            threads.handles.push(AccountingThreadHandle {
                event_sender,
                response_receiver,
                thread: Some(thread),
            });
        }

        // Handshake: wait for each thread to report readiness. Bounded by a
        // timeout so a stalled NE_ACCOUNT_VCPU can't hang the launch (this runs
        // synchronously on the API/preboot thread). Any failure, timeout, or a
        // thread that died before responding is fatal; returning here drops
        // `threads` and tears down the ones that did start.
        for (pos, handle) in threads.handles.iter().enumerate() {
            let idx = u32::try_from(pos).unwrap();
            match handle
                .response_receiver
                .recv_timeout(ACCOUNTING_JOIN_TIMEOUT)
            {
                Ok(AccountingResponse::Ready) => {}
                Ok(AccountingResponse::Error(source)) => {
                    return Err(AccountingError::Bind { idx, source });
                }
                Err(RecvTimeoutError::Timeout) => {
                    error!("Timed out waiting for vCPU {idx} accounting thread to bind");
                    return Err(AccountingError::Died { idx });
                }
                Err(RecvTimeoutError::Disconnected) => return Err(AccountingError::Died { idx }),
            }
        }

        Ok(threads)
    }
}

impl Drop for AccountingThreads {
    fn drop(&mut self) {
        // Signal every thread to exit, then drop the handles (each joins in
        // AccountingThreadHandle::drop). Same two-phase shape as Vmm::drop for
        // vCPUs: send Finish to all, then join all.
        for handle in &mut self.handles {
            let _ = handle.send_event(AccountingEvent::Finish);
        }
        self.handles.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Spawning a real accounting thread requires a started enclave VM (NE
    // hardware), so the bind/handshake/teardown path is covered by the
    // integration test (test_enclave.py::test_enclave_cpu_accounting). Here we
    // exercise the handle plumbing in isolation with a stand-in worker thread.

    #[test]
    fn test_empty_threads_drop_is_clean() {
        // No vCPUs => no handles => drop must not block or panic.
        let threads = AccountingThreads {
            handles: Vec::new(),
        };
        drop(threads);
    }

    #[test]
    fn test_handle_finish_stops_and_joins_thread() {
        let (event_sender, event_receiver) = channel::<AccountingEvent>();
        let (response_sender, response_receiver) = channel::<AccountingResponse>();

        let thread = thread::Builder::new()
            .name("fc_vcpu test".to_string())
            .spawn(move || {
                response_sender.send(AccountingResponse::Ready).unwrap();
                // Idle exactly like a real accounting thread until told to stop.
                while !matches!(event_receiver.recv(), Ok(AccountingEvent::Finish) | Err(_)) {}
            })
            .unwrap();

        let mut handle = AccountingThreadHandle {
            event_sender,
            response_receiver,
            thread: Some(thread),
        };

        assert!(matches!(
            handle.response_receiver.recv(),
            Ok(AccountingResponse::Ready)
        ));
        handle.send_event(AccountingEvent::Finish).unwrap();
        // Drop joins the worker; if Finish were not honored this would hang.
        drop(handle);
    }
}
