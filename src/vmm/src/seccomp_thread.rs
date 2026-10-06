// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::logger::{info, warn};
use crate::seccomp::{BpfProgram, BpfThreadMap, SeccompFeatures, SeccompFilter};

/// The thread categories Firecracker expects in a seccomp filter file.
#[derive(Debug, Clone, Copy)]
pub enum SeccompThread {
    /// MicroVM monitor thread.
    Vmm,
    /// API server thread.
    Api,
    /// Guest vCPU thread.
    Vcpu,
}

impl SeccompThread {
    /// All required Firecracker filter categories.
    pub const ALL: [Self; 3] = [Self::Vmm, Self::Api, Self::Vcpu];

    /// Category name in the filter file and in the installation logs.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Vmm => "vmm",
            Self::Api => "api",
            Self::Vcpu => "vcpu",
        }
    }

    pub(crate) fn filter(self, filters: &BpfThreadMap) -> Option<&SeccompFilter> {
        filters.get(self.name())
    }

    /// Compose and log this thread's program; a missing category has no program.
    pub fn compose(self, filters: &BpfThreadMap, features: SeccompFeatures) -> Option<BpfProgram> {
        let program = self.filter(filters)?.compose(features);
        let thread = self.name();
        if program.is_empty() {
            warn!("No seccomp filter is installed on the {thread} thread");
        } else {
            info!(
                "Seccomp filter of the {thread} thread: {} instructions, features [{features}]",
                program.len()
            );
        }
        Some(program)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_thread_filter() {
        for (thread, category) in [
            (SeccompThread::Vmm, "vmm"),
            (SeccompThread::Api, "api"),
            (SeccompThread::Vcpu, "vcpu"),
        ] {
            let mut filters = BpfThreadMap::new();
            assert_eq!(thread.compose(&filters, SeccompFeatures::empty()), None);
            filters.insert(category.to_string(), SeccompFilter::default());
            assert_eq!(
                thread.compose(&filters, SeccompFeatures::empty()),
                Some(vec![])
            );
        }
    }
}
