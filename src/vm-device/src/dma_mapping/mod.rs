// Copyright © 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

pub mod vfio;

/// Trait meant for triggering the DMA mapping update related to an external
/// device not managed fully through virtio. It is dedicated to virtio-iommu
/// in order to trigger the map update anytime the mapping is updated from the
/// guest.
pub trait ExternalDmaMapping: Send + Sync {
    /// Map a memory range
    fn map(&self, iova: u64, gpa: u64, size: u64) -> std::result::Result<(), std::io::Error>;

    /// Unmap a memory range
    fn unmap(&self, iova: u64, size: u64) -> std::result::Result<(), std::io::Error>;
}
