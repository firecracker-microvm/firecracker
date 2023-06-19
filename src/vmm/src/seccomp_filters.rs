// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::sync::Arc;

use seccompiler::BpfThreadMap;

/// Retrieve empty seccomp filters.
pub fn get_empty_filters() -> BpfThreadMap {
    let mut map = BpfThreadMap::new();
    map.insert("vmm".to_string(), Arc::new(vec![]));
    map.insert("api".to_string(), Arc::new(vec![]));
    map.insert("vcpu".to_string(), Arc::new(vec![]));
    map
}
