// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// The microvm state. When Firecracker starts, the instance state is Uninitialized.
/// Once start_microvm method is called, the state goes from Uninitialized to Starting.
/// The state is changed to Running before ending the start_microvm method.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum InstanceState {
    /// Microvm is not initialized.
    Uninitialized,
    /// Microvm is starting.
    Starting,
    /// Microvm is running.
    Running,
}

/// The strongly typed that contains general information about the microVM.
#[derive(Debug, Serialize)]
pub struct InstanceInfo {
    /// The ID of the microVM.
    pub id: String,
    /// The state of the microVM.
    pub state: InstanceState,
    /// The version of the VMM that runs the microVM.
    pub vmm_version: String,
}
