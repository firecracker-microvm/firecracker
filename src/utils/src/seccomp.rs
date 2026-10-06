// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Serialized seccomp filter types shared by the compiler and runtime.

use serde::{Deserialize, Serialize};

/// One part of a thread category's compiled seccomp filter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BpfPart {
    /// Features that enable this part; any one is sufficient. Empty means always included.
    pub features: Vec<String>,
    /// BPF instructions, each encoded as one eight-byte `sock_filter`.
    pub code: Vec<u64>,
}
