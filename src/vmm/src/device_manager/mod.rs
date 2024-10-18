// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

/// ACPI device manager.
pub mod acpi;
/// Legacy Device Manager.
pub mod legacy;
/// Memory Mapped I/O Manager.
pub mod mmio;
/// Device managers (de)serialization support.
pub mod persist;
/// Resource manager for devices.
pub mod resources;
