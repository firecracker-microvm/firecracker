// Copyright 2019 UCloud.cn, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::fuse;
use memory_model::DataInit;

// Implement DataInit for fuse structures to read/write in GusetMemory.
unsafe impl DataInit for fuse::fuse_in_header {}
unsafe impl DataInit for fuse::fuse_out_header {}
unsafe impl DataInit for fuse::fuse_init_in {}
unsafe impl DataInit for fuse::fuse_init_out {}
unsafe impl DataInit for fuse::fuse_attr_out {}
unsafe impl DataInit for fuse::fuse_entry_out {}
unsafe impl DataInit for fuse::fuse_forget_in {}
unsafe impl DataInit for fuse::fuse_read_in {}
unsafe impl DataInit for fuse::fuse_open_in {}
unsafe impl DataInit for fuse::fuse_open_out {}
unsafe impl DataInit for fuse::fuse_release_in {}
unsafe impl DataInit for fuse::fuse_statfs_out {}
unsafe impl DataInit for fuse::fuse_mknod_in {}
unsafe impl DataInit for fuse::fuse_mkdir_in {}
unsafe impl DataInit for fuse::fuse_setattr_in {}
