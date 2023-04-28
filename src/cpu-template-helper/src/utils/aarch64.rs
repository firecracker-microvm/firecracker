// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

macro_rules! reg_modifier {
    ($addr:expr, $value:expr) => {
        RegisterModifier {
            addr: $addr,
            bitmap: RegisterValueFilter {
                filter: u128::MAX,
                value: $value,
            },
        }
    };
    ($addr:expr, $value:expr, $filter:expr) => {
        RegisterModifier {
            addr: $addr,
            bitmap: RegisterValueFilter {
                filter: $filter,
                value: $value,
            },
        }
    };
}

pub(crate) use reg_modifier;
