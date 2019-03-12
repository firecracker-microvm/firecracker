// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

extern crate kvm;
extern crate sys_util;

use std::io;

use kvm::{IoeventAddress, VmFd};
use sys_util::EventFd;

/// Indication of success or failure of a `VmRequest`.
///
/// Success is usually indicated `VmResponse::Ok` unless there is data associated with the response.
#[derive(Debug)]
pub enum VmResponse {
    /// Indicates the request was executed successfully.
    Ok,
    /// Indicates the request encountered some error during execution.
    Err(io::Error),
}

/// A request to the main process to perform some operation on the VM.
///
/// Unless otherwise noted, each request should expect a `VmResponse::Ok` to be received on success.
pub enum VmRequest {
    /// Register the given ioevent address along with given datamatch to trigger the `EventFd`.
    RegisterIoevent(EventFd, IoeventAddress, u32),
    /// Register the given IRQ number to be triggered when the `EventFd` is triggered.
    RegisterIrqfd(EventFd, u32),
}

impl VmRequest {
    /// Executes this request on the given Vm.
    ///
    /// # Arguments
    /// * `vm` - The `Vm` to perform the request on.
    ///
    /// This does not return a result, instead encapsulating the success or failure in a
    /// `VmResponse` with the intended purpose of sending the response back over the  socket that
    /// received this `VmRequest`.
    pub fn execute(&self, vm: &VmFd) -> VmResponse {
        match *self {
            VmRequest::RegisterIoevent(ref evt, ref addr, datamatch) => {
                match vm.register_ioevent(evt, addr, datamatch) {
                    Ok(_) => VmResponse::Ok,
                    Err(e) => VmResponse::Err(e),
                }
            }
            VmRequest::RegisterIrqfd(ref evt, irq) => match vm.register_irqfd(evt, irq) {
                Ok(_) => VmResponse::Ok,
                Err(e) => VmResponse::Err(e),
            },
        }
    }
}
