// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use kvm_bindings::KVM_API_VERSION;
use kvm_ioctls::{Error as KvmIoctlsError, Kvm};

/// Errors associated with the wrappers over KVM ioctls.
#[derive(Debug, derive_more::From, thiserror::Error)]
pub enum SystemError {
    /// The host kernel reports an invalid KVM API version.
    #[error("The host kernel reports an invalid KVM API version: {0}")]
    ApiVersion(i32),
    /// Cannot initialize the KVM context due to missing capabilities.
    #[error("Missing KVM capabilities: {0:?}")]
    Capabilities(kvm_ioctls::Cap),
    /// Cannot initialize the KVM context.
    #[error("{}", ({
        if .0.errno() == libc::EACCES {
            format!(
                "Error creating KVM object. [{}]\nMake sure the user \
                launching the firecracker process is configured on the /dev/kvm file's ACL.",
                .0
            )
        } else {
            format!("Error creating KVM object. [{}]", .0)
        }
    }))]
    Initialization(KvmIoctlsError),
}

/// Describes a KVM context that gets attached to the microVM.
/// It gives access to the functionality of the KVM wrapper as
/// long as every required KVM capability is present on the host.
#[derive(Debug)]
pub struct KvmContext {
    kvm: Kvm,
    max_memslots: usize,
}

impl KvmContext {
    pub fn new() -> Result<Self, SystemError> {
        use kvm_ioctls::Cap::*;
        let kvm = Kvm::new()?;

        // Check that KVM has the correct version.
        #[allow(clippy::cast_possible_wrap)] // This is a constant
        if kvm.get_api_version() != KVM_API_VERSION as i32 {
            return Err(SystemError::ApiVersion(kvm.get_api_version()));
        }

        // A list of KVM capabilities we want to check.
        #[cfg(target_arch = "x86_64")]
        let capabilities = vec![
            Irqchip,
            Ioeventfd,
            Irqfd,
            UserMemory,
            SetTssAddr,
            Pit2,
            PitState2,
            AdjustClock,
            Debugregs,
            MpState,
            VcpuEvents,
            Xcrs,
            Xsave,
            ExtCpuid,
        ];

        #[cfg(target_arch = "aarch64")]
        let capabilities = vec![
            Ioeventfd, Irqfd, UserMemory, ArmPsci02, DeviceCtrl, MpState, OneReg,
        ];

        // Check that all desired capabilities are supported.
        match capabilities
            .iter()
            .find(|&capability| !kvm.check_extension(*capability))
        {
            None => {
                let max_memslots = kvm.get_nr_memslots();
                Ok(KvmContext { kvm, max_memslots })
            }

            Some(c) => Err(SystemError::Capabilities(*c)),
        }
    }

    pub fn fd(&self) -> &Kvm {
        &self.kvm
    }

    /// Get the maximum number of memory slots reported by this KVM context.
    pub fn max_memslots(&self) -> usize {
        self.max_memslots
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
    use std::fs::File;

    use super::*;

    #[test]
    fn test_kvm_context() {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::io::{AsRawFd, FromRawFd};

        let c = KvmContext::new().unwrap();

        assert!(c.max_memslots() >= 32);

        let kvm = Kvm::new().unwrap();
        let f = unsafe { File::from_raw_fd(kvm.as_raw_fd()) };
        let m1 = f.metadata().unwrap();
        let m2 = File::open("/dev/kvm").unwrap().metadata().unwrap();

        assert_eq!(m1.dev(), m2.dev());
        assert_eq!(m1.ino(), m2.ino());
    }
}
