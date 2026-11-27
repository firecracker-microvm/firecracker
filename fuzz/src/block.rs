// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Block device setup and seed builders for the block fuzz targets. Every target that takes its
//! device options and builds its drive with them fuzzes the same drive options, decoded the same
//! way. The rest of the drive configuration, such as the partuuid, image format, block size and
//! topology, is fixed.

use std::fs::File;
use std::num::NonZeroU16;

use vmm::devices::virtio::block::CacheType;
use vmm::devices::virtio::block::virtio::VirtioBlock;
use vmm::devices::virtio::block::virtio::device::{
    DiskImageFormat, FileEngineType, VirtioBlockConfig,
};
use vmm::rate_limiter::RateLimiter;
use vmm::vmm_config::machine_config::HugePageConfig;
use vmm::vstate::memory::test_utils::into_region_ext;
use vmm::vstate::memory::{GuestAddress, GuestMemoryMmap, MemoryError, anonymous};

use crate::check_hugepages_available;
use crate::virtio::{FuzzData, InsufficientData};

/// The size of the backing file: 8 sectors of 512 bytes.
pub const BACKING_FILE_SIZE: u64 = 0x1000;

/// The device options both block targets take from the input, in this order: the features the
/// driver acks, the queue size, and one byte of flags.
#[derive(Debug)]
pub struct DeviceOptions {
    pub features: u64,
    /// Block queues hold at most 256 entries, and the fuzzer indexes descriptors with a u8. A
    /// queue size has to be a power of two (VirtQueue::new asserts it).
    pub queue_size: u16,
    pub use_unsafe_cache: bool,
    pub is_disk_read_only: bool,
    pub is_disk_root: bool,
    pub huge_pages: bool,
    /// Already false for a read-only drive, which does not support discard.
    pub discard: bool,
}

impl DeviceOptions {
    pub fn take<'a>(input: &mut impl FuzzData<'a>) -> Result<Self, InsufficientData> {
        let features = input.take_u64()?;
        let queue_size = u16::from(input.take_u8()?).next_power_of_two();
        let [
            use_unsafe_cache,
            is_disk_read_only,
            is_disk_root,
            huge_pages,
            discard,
            ..,
        ] = input.take_bools()?;
        Ok(Self {
            features,
            queue_size,
            use_unsafe_cache,
            is_disk_read_only,
            is_disk_root,
            huge_pages,
            discard: discard && !is_disk_read_only,
        })
    }
}

/// Builds the device on a fresh memfd of [`BACKING_FILE_SIZE`] bytes, from the shared `options`
/// and the drive config fields each target sets itself: `num_queues`, the rate limiter and the file
/// engine. Returns the backing file too, which must stay open for as long as the device may open
/// its path again (on restore).
pub fn new_device(
    options: &DeviceOptions,
    num_queues: Option<NonZeroU16>,
    rate_limiter: Option<&RateLimiter>,
    file_engine_type: FileEngineType,
) -> (VirtioBlock, File) {
    let cache_type = match options.use_unsafe_cache {
        true => CacheType::Unsafe,
        false => CacheType::Writeback,
    };
    let (backing, path) = crate::make_memfd("block_backing");
    backing.set_len(BACKING_FILE_SIZE).unwrap();

    let config = VirtioBlockConfig {
        drive_id: "fuzzing".to_string(),
        partuuid: None,
        is_root_device: options.is_disk_root,
        cache_type,

        is_read_only: options.is_disk_read_only,
        discard: options.discard,
        num_queues,
        path_on_host: path,
        rate_limiter: rate_limiter.map(Into::into),
        file_engine_type,
        image_format: DiskImageFormat::Raw,
        blk_size: None,
        topology: None,
        dmb_size_mib: None,
    };

    (VirtioBlock::new(config).unwrap(), backing)
}

/// The rate limiter the targets use when they limit loosely: 10 million ops/s, so every request is
/// charged against it but none waits.
pub fn loose_rate_limiter() -> RateLimiter {
    RateLimiter::new(0, 0, 0, 100_000, 0, 10)
}

/// Why [`guest_memory`] could not set up guest memory.
#[derive(Debug)]
pub enum GuestMemoryError {
    /// The host has too few free hugepages: mapping them would fail with SIGBUS on first touch,
    /// so the target should return without fuzzing.
    NotEnoughHugepages,
    /// The mapping itself failed: the target can't run.
    Mmap(MemoryError),
}

/// Guest memory at address 0: `size` bytes of anonymous memory, or `hugetlbfs_size` bytes in 2 MiB
/// hugetlbfs pages if `huge_pages` is set, with dirty page tracking if `track_dirty_pages` is set.
pub fn guest_memory(
    huge_pages: bool,
    size: usize,
    hugetlbfs_size: usize,
    track_dirty_pages: bool,
) -> Result<GuestMemoryMmap, GuestMemoryError> {
    let (huge_page_config, size) = match huge_pages {
        true if !check_hugepages_available(hugetlbfs_size) => {
            return Err(GuestMemoryError::NotEnoughHugepages);
        }
        true => (HugePageConfig::Hugetlbfs2M, hugetlbfs_size),
        false => (HugePageConfig::None, size),
    };
    let regions = anonymous(
        &[(GuestAddress(0), size)],
        track_dirty_pages,
        huge_page_config,
    )
    .map_err(GuestMemoryError::Mmap)?;
    Ok(into_region_ext(regions))
}

/// Builders for the block targets' input seeds.
pub mod seed {
    use std::fs::OpenOptions;
    use std::io::Write;

    /// Appends the options [`super::DeviceOptions::take`] reads: `features`, a queue size of 256
    /// and the `flags` byte (bits: 0 unsafe cache, 1 read-only, 2 root, 3 hugetlbfs, 4 discard).
    pub fn push_device_options(seed: &mut Vec<u8>, features: u64, flags: u8) {
        seed.extend_from_slice(&features.to_le_bytes());
        seed.push(0xff); // queue size: rounded up to 256
        seed.push(flags);
    }

    /// A request on sector 0.
    #[derive(Clone, Copy)]
    pub enum Request {
        Write,
        Read,
        GetId,
        /// A discard of sector 0.
        Discard,
    }

    /// Appends the three descriptors of `request` (header, data, status), at descriptor table
    /// indices `first..first + 3` and guest addresses `base`, `base + 0x100` and `base + 0x400`.
    fn push_request_chain(seed: &mut Vec<u8>, base: u16, first: u8, request: Request) {
        let (request_type, device_writes, data): (u32, bool, Vec<u8>) = match request {
            Request::Write => {
                let mut data = vec![0u8; 512];
                data[..11].copy_from_slice(b"Hello World");
                (1, false, data) // VIRTIO_BLK_T_OUT
            }
            Request::Read => (0, true, vec![0u8; 512]), // VIRTIO_BLK_T_IN
            Request::GetId => (8, true, vec![0u8; 20]), // VIRTIO_BLK_T_GET_ID, 20 ID bytes
            Request::Discard => {
                // VIRTIO_BLK_T_DISCARD: sector 0, one sector, no flags
                let mut range = 0u64.to_le_bytes().to_vec();
                range.extend_from_slice(&1u32.to_le_bytes());
                range.extend_from_slice(&0u32.to_le_bytes());
                (11, false, range)
            }
        };

        // header descriptor, chained to the data descriptor
        let [lo, hi] = base.to_le_bytes();
        seed.extend_from_slice(&[first, lo, hi, 0x1, first + 1]);
        seed.extend_from_slice(&[0x10, 0x0]); // buffer length: the 16-byte request header
        seed.extend_from_slice(&request_type.to_le_bytes());
        seed.extend_from_slice(&[0x0; 4]); // reserved
        seed.extend_from_slice(&[0x0; 8]); // sector 0

        // data descriptor, chained to the status descriptor
        let [lo, hi] = (base + 0x100).to_le_bytes();
        let flags = if device_writes { 0x3 } else { 0x1 }; // NEXT, plus WRITE if device-writable
        seed.extend_from_slice(&[first + 1, lo, hi, flags, first + 2]);
        seed.extend_from_slice(&u16::try_from(data.len()).unwrap().to_le_bytes());
        seed.extend_from_slice(&data);

        // status descriptor: device-writable, end of chain
        let [lo, hi] = (base + 0x400).to_le_bytes();
        seed.extend_from_slice(&[first + 2, lo, hi, 0x2, 0x0]);
        seed.extend_from_slice(&[0x2, 0x0, 0x0, 0x0]); // buffer length 2, and its bytes
    }

    /// Appends one fill of a queue (what `FuzzData::fill_virt_queue` reads) with a request at each
    /// guest address in `requests`.
    pub fn push_fill(seed: &mut Vec<u8>, requests: &[(u16, Request)]) {
        // fill_virt_queue() writes `n % queue_size + 1` descriptors
        seed.push(u8::try_from(requests.len() * 3 - 1).unwrap());
        for (i, (base, request)) in requests.iter().enumerate() {
            push_request_chain(seed, *base, 4 + 3 * u8::try_from(i).unwrap(), *request);
        }
        seed.extend_from_slice(&[0x0, 0x0]); // used_event, unused without EVENT_IDX
    }

    /// Appends one fill of a queue with a write request at each guest address in `bases`.
    pub fn push_write_fill(seed: &mut Vec<u8>, bases: &[u16]) {
        let writes: Vec<_> = bases.iter().map(|base| (*base, Request::Write)).collect();
        push_fill(seed, &writes);
    }

    /// Saves `seed` to `in/<target>/<name>.in`.
    pub fn save_seed(target: &str, name: &str, seed: &[u8]) {
        let _ = std::fs::create_dir_all(format!("in/{target}"));
        let mut seed_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(format!("in/{target}/{name}.in"))
            .unwrap();

        seed_file.write_all(seed).unwrap();
    }
}
