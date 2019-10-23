// Copyright 2019 UCloud.cn, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::mem;

use sys_util::fs::Entry;

use memory_model::{GuestAddress, GuestMemory};

#[derive(Debug)]
pub struct FuseDirent {
    pub offset: u64,
    pub entry: Entry,
}

impl FuseDirent {
    pub fn aligned_size(&self) -> usize {
        let u64_size = mem::size_of::<u64>();
        // size of fuse_dirent
        let x = 3 * u64_size + self.entry.file_name().to_bytes_with_nul().len();
        // aligned size
        (((x) + u64_size - 1) & !(u64_size - 1))
    }

    pub fn write_to_memory(&self, mem: &GuestMemory, mut pos: GuestAddress) {
        let name_buf = self.entry.file_name().to_bytes_with_nul();

        let ino = self.entry.ino();
        mem.write_obj_at_addr(ino, pos).unwrap();
        pos = pos.unchecked_add(mem::size_of::<u64>());

        mem.write_obj_at_addr(self.offset, pos).unwrap();
        pos = pos.unchecked_add(mem::size_of::<u64>());

        mem.write_obj_at_addr(name_buf.len() as u32, pos).unwrap();
        pos = pos.unchecked_add(mem::size_of::<u32>());

        let file_type = self.entry.file_type() as u32;
        mem.write_obj_at_addr(file_type, pos).unwrap();
        pos = pos.unchecked_add(mem::size_of::<u32>());

        mem.write_slice_at_addr(name_buf, pos).unwrap();
    }
}
