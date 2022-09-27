// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate self as bit_fields;
bit_fields::bitfield!(ExampleBitField,u32,{
    /// RANGE1 bit field
    RANGE1: 0..1,
    /// SSE bit flag
    SSE: 2,
    /// SSE1 bit flag
    SSE1: 3,
    /// RANGE2 bit field
    RANGE2: 4..6,
    /// SSE2 bit flag
    SSE2: 9,
    /// SSE3 bit flag
    SSE3: 10,
    /// RANGE3 bit field
    RANGE3: 12..15,
    /// SSE4 bit flag
    SSE4: 18,
});
