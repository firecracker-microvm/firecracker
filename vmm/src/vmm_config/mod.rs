// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Wrapper for configuring the microVM boot source.
pub mod boot_source;
/// Wrapper for configuring the block devices.
pub mod drive;
/// Wrapper over the microVM general information attached to the microVM.
pub mod instance_info;
/// Wrapper for configuring the logger.
pub mod logger;
/// Wrapper for configuring the memory and CPU of the microVM.
pub mod machine_config;
/// Wrapper for configuring the network devices attached to the microVM.
pub mod net;

/// Device State. TODO: This should be removed because we don't plan
/// to support hot plug-unplug in the near future.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub enum DeviceState {
    /// Device is attached.
    Attached,
}
