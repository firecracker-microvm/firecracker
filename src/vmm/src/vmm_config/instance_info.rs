// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use serde::Serialize;

/// The strongly typed that contains general information about the microVM.
#[derive(Clone, Debug, Default, Serialize)]
pub struct InstanceInfo {
    /// The ID of the microVM.
    pub id: String,
    /// Whether the microVM is not started/running/paused.
    pub state: String,
    /// The version of the VMM that runs the microVM.
    pub vmm_version: String,
    /// The name of the application that runs the microVM.
    pub app_name: String,
}
