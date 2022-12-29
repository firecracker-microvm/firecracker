// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate self as bit_fields;

bit_fields::bitfield!(ExampleBitFieldU32,u32,{
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

bit_fields::bitfield!(BitFieldIndexedU16, u16, {
    #[skip]
    one: 0..1,
    one0: one[0..1],
    #[skip]
    one00: one0[0],
    #[skip]
    two: 1..3,
    two0: two[0..1],
    #[skip]
    two00: two0[0],
    two1: two[1],
    #[skip]
    three: 3..6,
    #[skip]
    three0: three[0..1],
    three00: three0[0],
    three1: three[1..3],
    #[skip]
    three10: three1[0..1],
    #[skip]
    three11: three1[1],
    four: 6..10,
    five: 10..15,
    six: 15
});
