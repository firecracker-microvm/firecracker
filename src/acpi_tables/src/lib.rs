// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod aml;
pub mod rsdp;
pub mod sdt;

fn generate_checksum(data: &[u8]) -> u8 {
    (255 - data.iter().fold(0u8, |acc, x| acc.wrapping_add(*x))).wrapping_add(1)
}
