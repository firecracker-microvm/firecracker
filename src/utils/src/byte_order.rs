// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

macro_rules! generate_read_fn {
    ($fn_name: ident, $data_type: ty, $byte_type: ty, $type_size: expr, $endian_type: ident) => {
        pub fn $fn_name(input: &[$byte_type]) -> $data_type {
            assert!($type_size == std::mem::size_of::<$data_type>());
            let mut array = [0u8; $type_size];
            #[allow(clippy::cast_sign_loss)]
            #[allow(clippy::cast_possible_wrap)]
            for (byte, read) in array.iter_mut().zip(input.iter().cloned()) {
                *byte = read as u8;
            }
            <$data_type>::$endian_type(array)
        }
    };
}

macro_rules! generate_write_fn {
    ($fn_name: ident, $data_type: ty, $byte_type: ty, $endian_type: ident) => {
        pub fn $fn_name(buf: &mut [$byte_type], n: $data_type) {
            #[allow(clippy::cast_sign_loss)]
            #[allow(clippy::cast_possible_wrap)]
            for (byte, read) in buf
                .iter_mut()
                .zip(<$data_type>::$endian_type(n).iter().cloned())
            {
                *byte = read as $byte_type;
            }
        }
    };
}

generate_read_fn!(read_le_u16, u16, u8, 2, from_le_bytes);
generate_read_fn!(read_le_u32, u32, u8, 4, from_le_bytes);
generate_read_fn!(read_le_u32_from_i8, u32, i8, 4, from_le_bytes);
generate_read_fn!(read_le_u64, u64, u8, 8, from_le_bytes);
generate_read_fn!(read_le_i32, i32, i8, 4, from_le_bytes);

generate_read_fn!(read_be_u16, u16, u8, 2, from_be_bytes);
generate_read_fn!(read_be_u32, u32, u8, 4, from_be_bytes);

generate_write_fn!(write_le_u16, u16, u8, to_le_bytes);
generate_write_fn!(write_le_u32, u32, u8, to_le_bytes);
generate_write_fn!(write_le_u32_to_i8, u32, i8, to_le_bytes);
generate_write_fn!(write_le_u64, u64, u8, to_le_bytes);
generate_write_fn!(write_le_i32, i32, i8, to_le_bytes);

generate_write_fn!(write_be_u16, u16, u8, to_be_bytes);
generate_write_fn!(write_be_u32, u32, u8, to_be_bytes);

#[cfg(test)]
mod tests {
    use super::*;
    macro_rules! byte_order_test_read_write {
        ($test_name: ident, $write_fn_name: ident, $read_fn_name: ident, $is_be: expr, $data_type: ty) => {
            #[test]
            fn $test_name() {
                #[allow(overflowing_literals)]
                let test_cases = [
                    (
                        0x0123_4567_89AB_CDEF as u64,
                        [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
                    ),
                    (
                        0x0000_0000_0000_0000 as u64,
                        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                    ),
                    (
                        0x1923_2345_ABF3_CCD4 as u64,
                        [0x19, 0x23, 0x23, 0x45, 0xAB, 0xF3, 0xCC, 0xD4],
                    ),
                    (
                        0x0FF0_0FF0_0FF0_0FF0 as u64,
                        [0x0F, 0xF0, 0x0F, 0xF0, 0x0F, 0xF0, 0x0F, 0xF0],
                    ),
                    (
                        0xFFFF_FFFF_FFFF_FFFF as u64,
                        [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
                    ),
                    (
                        0x89AB_12D4_C2D2_09BB as u64,
                        [0x89, 0xAB, 0x12, 0xD4, 0xC2, 0xD2, 0x09, 0xBB],
                    ),
                ];

                let type_size = std::mem::size_of::<$data_type>();
                #[allow(clippy::cast_possible_truncation)]
                #[allow(clippy::cast_sign_loss)]
                for (test_val, v_arr) in &test_cases {
                    let v = *test_val as $data_type;
                    let cmp_iter: Box<dyn Iterator<Item = _>> = if $is_be {
                        Box::new(v_arr[(8 - type_size)..].iter())
                    } else {
                        Box::new(v_arr.iter().rev())
                    };
                    // test write
                    let mut write_arr = vec![Default::default(); type_size];
                    $write_fn_name(&mut write_arr, v);
                    for (cmp, cur) in cmp_iter.zip(write_arr.iter()) {
                        assert_eq!(*cmp, *cur as u8)
                    }
                    // test read
                    let read_val = $read_fn_name(&write_arr);
                    assert_eq!(v, read_val);
                }
            }
        };
    }

    byte_order_test_read_write!(test_le_u16, write_le_u16, read_le_u16, false, u16);
    byte_order_test_read_write!(test_le_u32, write_le_u32, read_le_u32, false, u32);
    byte_order_test_read_write!(test_le_u64, write_le_u64, read_le_u64, false, u64);
    byte_order_test_read_write!(test_le_i32, write_le_i32, read_le_i32, false, i32);
    byte_order_test_read_write!(test_be_u16, write_be_u16, read_be_u16, true, u16);
    byte_order_test_read_write!(test_be_u32, write_be_u32, read_be_u32, true, u32);
}
