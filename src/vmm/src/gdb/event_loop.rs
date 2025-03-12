// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::net::UnixStream;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::TryRecvError::Empty;
use std::sync::{Arc, Mutex};

use gdbstub::common::{Signal, Tid};
use gdbstub::conn::{Connection, ConnectionExt};
use gdbstub::stub::run_blocking::{self, WaitForStopReasonError};
use gdbstub::stub::{DisconnectReason, GdbStub, MultiThreadStopReason};
use gdbstub::target::Target;
use kvm_ioctls::VcpuFd;
use vm_memory::GuestAddress;

use super::target::{FirecrackerTarget, GdbTargetError, vcpuid_to_tid};
use crate::Vmm;
use crate::logger::{error, trace};

/// Starts the GDB event loop which acts as a proxy between the Vcpus and GDB
pub fn event_loop(
    connection: UnixStream,
    vmm: Arc<Mutex<Vmm>>,
    vcpu_fds: Vec<VcpuFd>,
    gdb_event_receiver: Receiver<usize>,
    entry_addr: GuestAddress,
) {
    let target = FirecrackerTarget::new(vmm, vcpu_fds, gdb_event_receiver, entry_addr);
    let connection: Box<dyn ConnectionExt<Error = std::io::Error>> = { Box::new(connection) };
    let debugger = GdbStub::new(connection);

    // We wait for the VM to reach the inital breakpoint we inserted before starting the event loop
    target
        .gdb_event
        .recv()
        .expect("Error getting initial gdb event");

    gdb_event_loop_thread(debugger, target);
}

struct GdbBlockingEventLoop {}

impl run_blocking::BlockingEventLoop for GdbBlockingEventLoop {
    type Target = FirecrackerTarget;
    type Connection = Box<dyn ConnectionExt<Error = std::io::Error>>;

    type StopReason = MultiThreadStopReason<u64>;

    /// Poll for events from either Vcpu's or packets from the GDB connection
    fn wait_for_stop_reason(
        target: &mut FirecrackerTarget,
        conn: &mut Self::Connection,
    ) -> Result<
        run_blocking::Event<MultiThreadStopReason<u64>>,
        run_blocking::WaitForStopReasonError<
            <Self::Target as Target>::Error,
            <Self::Connection as Connection>::Error,
        >,
    > {
        loop {
            match target.gdb_event.try_recv() {
                Ok(cpu_id) => {
                    // The Vcpu reports it's id from raw_id so we straight convert here
                    let tid = Tid::new(cpu_id).expect("Error converting cpu id to Tid");
                    // If notify paused returns false this means we were already debugging a single
                    // core, the target will track this for us to pick up later
                    target.set_paused_vcpu(tid);
                    trace!("Vcpu: {tid:?} paused from debug exit");

                    let stop_reason = target
                        .get_stop_reason(tid)
                        .map_err(WaitForStopReasonError::Target)?;

                    let Some(stop_response) = stop_reason else {
                        // If we returned None this is a break which should be handled by
                        // the guest kernel (e.g. kernel int3 self testing) so we won't notify
                        // GDB and instead inject this back into the guest
                        target
                            .inject_bp_to_guest(tid)
                            .map_err(WaitForStopReasonError::Target)?;
                        target
                            .resume_vcpu(tid)
                            .map_err(WaitForStopReasonError::Target)?;

                        trace!("Injected BP into guest early exit");
                        continue;
                    };

                    trace!("Returned stop reason to gdb: {stop_response:?}");
                    return Ok(run_blocking::Event::TargetStopped(stop_response));
                }
                Err(Empty) => (),
                Err(_) => {
                    return Err(WaitForStopReasonError::Target(
                        GdbTargetError::GdbQueueError,
                    ));
                }
            }

            if conn.peek().map(|b| b.is_some()).unwrap_or(false) {
                let byte = conn
                    .read()
                    .map_err(run_blocking::WaitForStopReasonError::Connection)?;
                return Ok(run_blocking::Event::IncomingData(byte));
            }
        }
    }

    /// Invoked when the GDB client sends a Ctrl-C interrupt.
    fn on_interrupt(
        target: &mut FirecrackerTarget,
    ) -> Result<Option<MultiThreadStopReason<u64>>, <FirecrackerTarget as Target>::Error> {
        // notify the target that a ctrl-c interrupt has occurred.
        let main_core = vcpuid_to_tid(0)?;

        target.pause_vcpu(main_core)?;
        target.set_paused_vcpu(main_core);

        let exit_reason = MultiThreadStopReason::SignalWithThread {
            tid: main_core,
            signal: Signal::SIGINT,
        };
        Ok(Some(exit_reason))
    }
}

/// Runs while communication with GDB is in progress, after GDB disconnects we
/// shutdown firecracker
fn gdb_event_loop_thread(
    debugger: GdbStub<FirecrackerTarget, Box<dyn ConnectionExt<Error = std::io::Error>>>,
    mut target: FirecrackerTarget,
) {
    match debugger.run_blocking::<GdbBlockingEventLoop>(&mut target) {
        Ok(disconnect_reason) => match disconnect_reason {
            DisconnectReason::Disconnect => {
                trace!("Client disconnected")
            }
            DisconnectReason::TargetExited(code) => {
                trace!("Target exited with code {}", code)
            }
            DisconnectReason::TargetTerminated(sig) => {
                trace!("Target terminated with signal {}", sig)
            }
            DisconnectReason::Kill => trace!("GDB sent a kill command"),
        },
        Err(e) => {
            if e.is_target_error() {
                error!("target encountered a fatal error: {e:?}")
            } else if e.is_connection_error() {
                error!("connection error: {e:?}")
            } else {
                error!("gdbstub encountered a fatal error {e:?}")
            }
        }
    }

    target.shutdown_vmm();
}
