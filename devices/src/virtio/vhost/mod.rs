// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Implements vhost-based virtio devices.

use std;
use sys_util::Error as SysError;

pub mod handle;
pub mod vsock;

#[derive(Debug)]
pub enum Error {
    /// Creating kill eventfd failed.
    CreateKillEventFd(SysError),
    /// Cloning kill eventfd failed.
    CloneKillEventFd(SysError),
    /// Error while polling for events.
    PollError(SysError),
    /// Failed to open vhost device.
    VhostOpen(vhost_backend::Error),
    /// Set owner failed.
    VhostSetOwner(vhost_backend::Error),
    /// Get features failed.
    VhostGetFeatures(vhost_backend::Error),
    /// Set features failed.
    VhostSetFeatures(vhost_backend::Error),
    /// Set mem table failed.
    VhostSetMemTable(vhost_backend::Error),
    /// Set vring num failed.
    VhostSetVringNum(vhost_backend::Error),
    /// Set vring addr failed.
    VhostSetVringAddr(vhost_backend::Error),
    /// Set vring base failed.
    VhostSetVringBase(vhost_backend::Error),
    /// Set vring call failed.
    VhostSetVringCall(vhost_backend::Error),
    /// Set vring kick failed.
    VhostSetVringKick(vhost_backend::Error),
    /// Net set backend failed.
    VhostNetSetBackend(vhost_backend::Error),
    /// Failed to set CID for guest.
    VhostVsockSetCid(vhost_backend::Error),
    /// Failed to start vhost-vsock driver.
    VhostVsockStart(vhost_backend::Error),
    /// Failed to create vhost eventfd.
    VhostIrqCreate(SysError),
    /// Failed to read vhost eventfd.
    VhostIrqRead(SysError),
}
type Result<T> = std::result::Result<T, Error>;
const INTERRUPT_STATUS_USED_RING: u32 = 0x1;
const TYPE_VSOCK: u32 = 19;
