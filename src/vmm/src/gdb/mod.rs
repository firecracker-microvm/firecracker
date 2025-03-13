// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Arch specific implementations
mod arch;
/// Event loop for connection to GDB server
mod event_loop;
/// Target for gdb
pub mod target;

use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};

use arch::vcpu_set_debug;
use event_loop::event_loop;
use kvm_ioctls::VcpuFd;
use target::GdbTargetError;
use vm_memory::GuestAddress;

use crate::Vmm;
use crate::logger::trace;

/// Kickstarts the GDB debugging process, it takes in the VMM object, a slice of
/// the paused Vcpu's, the GDB event queue which is used as a mechanism for the Vcpu's to notify
/// our GDB thread that they've been paused, then finally the entry address of the kernel.
///
/// Firstly the function will start by configuring the Vcpus with KVM for debugging
///
/// This will then create the GDB socket which will be used for communication to the GDB process.
/// After creating this, the function will block while waiting for GDB to connect.
///
/// After the connection has been established the function will start a new thread for handling
/// communcation to the GDB server
pub fn gdb_thread(
    vmm: Arc<Mutex<Vmm>>,
    vcpu_fds: Vec<VcpuFd>,
    gdb_event_receiver: Receiver<usize>,
    entry_addr: GuestAddress,
    socket_addr: &str,
) -> Result<(), GdbTargetError> {
    // We register a hw breakpoint at the entry point as GDB expects the application
    // to be stopped as it connects. This also allows us to set breakpoints before kernel starts.
    // This entry adddress is automatically used as it is not tracked inside the target state, so
    // when resumed will be removed
    vcpu_set_debug(&vcpu_fds[0], &[entry_addr], false)?;

    for vcpu_fd in &vcpu_fds[1..] {
        vcpu_set_debug(vcpu_fd, &[], false)?;
    }

    let path = Path::new(socket_addr);
    let listener = UnixListener::bind(path).map_err(|_| GdbTargetError::ServerSocketError)?;
    trace!("Waiting for GDB server connection on {}...", path.display());
    let (connection, _addr) = listener
        .accept()
        .map_err(|_| GdbTargetError::ServerSocketError)?;

    std::thread::Builder::new()
        .name("gdb".into())
        .spawn(move || event_loop(connection, vmm, vcpu_fds, gdb_event_receiver, entry_addr))
        .map_err(|_| GdbTargetError::GdbThreadError)?;

    Ok(())
}
