// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements vhost-based virtio devices.

use std;
use sys_util::Error as SysError;
use vhost_backend::Error as VhostBackendError;

pub mod vsock;
pub mod handle;

#[derive(Debug)]
pub enum Error {
    /// Creating kill eventfd failed.
    CreateKillEventFd(SysError),
    /// Cloning kill eventfd failed.
    CloneKillEventFd(SysError),
    /// Error while polling for events.
    PollError(SysError),
    /// Failed to open vhost device.
    VhostOpen(VhostBackendError),
    /// Set owner failed.
    VhostSetOwner(VhostBackendError),
    /// Get features failed.
    VhostGetFeatures(VhostBackendError),
    /// Set features failed.
    VhostSetFeatures(VhostBackendError),
    /// Set mem table failed.
    VhostSetMemTable(VhostBackendError),
    /// Set vring num failed.
    VhostSetVringNum(VhostBackendError),
    /// Set vring addr failed.
    VhostSetVringAddr(VhostBackendError),
    /// Set vring base failed.
    VhostSetVringBase(VhostBackendError),
    /// Set vring call failed.
    VhostSetVringCall(VhostBackendError),
    /// Set vring kick failed.
    VhostSetVringKick(VhostBackendError),
    /// Net set backend failed.
    VhostNetSetBackend(VhostBackendError),
    /// Failed to set CID for guest.
    VhostVsockSetCid(VhostBackendError),
    /// Failed to start vhost-vsock driver.
    VhostVsockStart(VhostBackendError),
    /// Failed to create vhost eventfd.
    VhostIrqCreate(SysError),
    /// Failed to read vhost eventfd.
    VhostIrqRead(SysError),
}
type Result<T> = std::result::Result<T, Error>;
