// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// For GDT details see arch/x86/include/asm/segment.h

use kvm_sys::kvm_segment;

/// Constructor for a conventional segment GDT (or LDT) entry. Derived from the kernel's segment.h.
pub fn gdt_entry(flags: u16, base: u32, limit: u32) -> u64 {
    ((((base as u64) & 0xff000000u64) << (56 - 24)) | (((flags as u64) & 0x0000f0ffu64) << 40) |
         (((limit as u64) & 0x000f0000u64) << (48 - 16)) |
         (((base as u64) & 0x00ffffffu64) << 16) | (((limit as u64) & 0x0000ffffu64)))
}

fn get_base(entry: u64) -> u64 {
    ((((entry) & 0xFF00000000000000) >> 32) | (((entry) & 0x000000FF00000000) >> 16) |
         (((entry) & 0x00000000FFFF0000) >> 16))
}

fn get_limit(entry: u64) -> u32 {
    ((((entry) & 0x000F000000000000) >> 32) | (((entry) & 0x000000000000FFFF))) as u32
}

fn get_g(entry: u64) -> u8 {
    ((entry & 0x0080000000000000) >> 55) as u8
}

fn get_db(entry: u64) -> u8 {
    ((entry & 0x0040000000000000) >> 54) as u8
}

fn get_l(entry: u64) -> u8 {
    ((entry & 0x0020000000000000) >> 53) as u8
}

fn get_avl(entry: u64) -> u8 {
    ((entry & 0x0010000000000000) >> 52) as u8
}

fn get_p(entry: u64) -> u8 {
    ((entry & 0x0000800000000000) >> 47) as u8
}

fn get_dpl(entry: u64) -> u8 {
    ((entry & 0x0000600000000000) >> 45) as u8
}

fn get_s(entry: u64) -> u8 {
    ((entry & 0x0000100000000000) >> 44) as u8
}

fn get_type(entry: u64) -> u8 {
    ((entry & 0x00000F0000000000) >> 40) as u8
}

/// Automatically build the kvm struct for SET_SREGS from the kernel bit fields.
///
/// # Arguments
///
/// * `entry` - The gdt entry.
/// * `table_index` - Index of the entry in the gdt table.
pub fn kvm_segment_from_gdt(entry: u64, table_index: u8) -> kvm_segment {
    kvm_segment {
        base: get_base(entry),
        limit: get_limit(entry),
        selector: (table_index * 8) as u16,
        type_: get_type(entry),
        present: get_p(entry),
        dpl: get_dpl(entry),
        db: get_db(entry),
        s: get_s(entry),
        l: get_l(entry),
        g: get_g(entry),
        avl: get_avl(entry),
        padding: 0,
        unusable: match get_p(entry) {
            0 => 1,
            _ => 0,
        },
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn field_parse() {
        let gdt = gdt_entry(0xA09B, 0x100000, 0xfffff);
        let seg = kvm_segment_from_gdt(gdt, 0);
        // 0xA09B
        // 'A'
        assert_eq!(0x1, seg.g);
        assert_eq!(0x0, seg.db);
        assert_eq!(0x1, seg.l);
        assert_eq!(0x0, seg.avl);
        // '9'
        assert_eq!(0x1, seg.present);
        assert_eq!(0x0, seg.dpl);
        assert_eq!(0x1, seg.s);
        // 'B'
        assert_eq!(0xB, seg.type_);
        // base and limit
        assert_eq!(0x100000, seg.base);
        assert_eq!(0xfffff, seg.limit);
        assert_eq!(0x0, seg.unusable);
    }
}
