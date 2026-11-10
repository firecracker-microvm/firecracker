// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! KVM's binary statistics (`KVM_GET_STATS_FD`, Linux 5.14+) for the VM and each vCPU, served by
//! `GET /vm/kvm-stats`.
//!
//! debugfs only has per-VM sums, and reads histograms as their first bucket; the stats descriptors
//! have every counter per vCPU, and the histograms in full (e.g. `halt_wait_hist`: how long each
//! halt waited). Firecracker owns the VM and vCPU descriptors, so it can read them without any
//! privilege.
//!
//! The stats descriptors are opened when the vCPUs are created, before the VMM thread's seccomp
//! filter is installed, and read with `pread64` on each request. Nothing is read otherwise.

use std::collections::BTreeMap;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::FileExt;

use kvm_bindings::{
    KVM_STATS_BASE_MASK, KVM_STATS_BASE_POW2, KVM_STATS_BASE_POW10, KVM_STATS_TYPE_CUMULATIVE,
    KVM_STATS_TYPE_INSTANT, KVM_STATS_TYPE_LINEAR_HIST, KVM_STATS_TYPE_LOG_HIST,
    KVM_STATS_TYPE_MASK, KVM_STATS_TYPE_PEAK, KVM_STATS_UNIT_BOOLEAN, KVM_STATS_UNIT_BYTES,
    KVM_STATS_UNIT_CYCLES, KVM_STATS_UNIT_MASK, KVM_STATS_UNIT_NONE, KVM_STATS_UNIT_SECONDS,
};
use serde::Serialize;
use vmm_sys_util::ioctl::ioctl;

use self::ioctls::KVM_GET_STATS_FD;

mod ioctls {
    use kvm_bindings::KVMIO;
    use vmm_sys_util::ioctl_io_nr;

    ioctl_io_nr!(KVM_GET_STATS_FD, KVMIO, 0xce);
}

// Sizes of struct kvm_stats_header and struct kvm_stats_desc (without its name).
const HEADER_SIZE: usize = 24;
const DESC_SIZE: usize = 16;
// Bounds on what the kernel reports, so a bad header can't make us allocate without limit.
const MAX_DESCRIPTORS: u32 = 1024;
const MAX_NAME_SIZE: u32 = 256;
const MAX_DATA_SIZE: usize = 1 << 20;

/// Errors reading KVM's binary statistics.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum KvmStatsError {
    /// KVM binary statistics are not available on this host (they need Linux 5.14 or later)
    Unsupported,
    /// KVM_GET_STATS_FD failed: {0}
    Open(std::io::Error),
    /// Failed to read KVM statistics: {0}
    Read(std::io::Error),
    /// Unexpected KVM statistics header: {0} descriptors, names of {1} bytes
    Header(u32, u32),
    /// Unexpected KVM statistics descriptor `{0}`: data at offset {1}, {2} values
    Descriptor(String, u32, u16),
}

/// The stats descriptors of a VM and of each of its vCPUs.
#[derive(Debug)]
pub struct KvmStatsFds {
    vm: StatsFd,
    vcpus: Vec<(u8, StatsFd)>,
}

impl KvmStatsFds {
    /// Opens the stats descriptors of the VM and of each of its vCPUs (by index).
    pub fn open<V: AsRawFd>(vm: &impl AsRawFd, vcpus: &[(u8, &V)]) -> Result<Self, KvmStatsError> {
        Ok(Self {
            vm: StatsFd::open(vm)?,
            vcpus: vcpus
                .iter()
                .map(|(index, fd)| Ok((*index, StatsFd::open(*fd)?)))
                .collect::<Result<_, KvmStatsError>>()?,
        })
    }

    /// Reads the current stats of the VM and each vCPU.
    pub fn read(&self) -> Result<KvmStats, KvmStatsError> {
        Ok(KvmStats {
            vm: self.vm.read()?,
            vcpus: self
                .vcpus
                .iter()
                .map(|(index, fd)| {
                    Ok(VcpuKvmStats {
                        index: *index,
                        stats: fd.read()?,
                    })
                })
                .collect::<Result<_, KvmStatsError>>()?,
        })
    }
}

/// The stats of the VM and each vCPU.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KvmStats {
    /// The VM's stats, by name.
    pub vm: BTreeMap<String, KvmStat>,
    /// Each vCPU's stats.
    pub vcpus: Vec<VcpuKvmStats>,
}

/// One vCPU's stats, by its index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VcpuKvmStats {
    /// The vCPU index.
    pub index: u8,
    /// The vCPU's stats, by name.
    pub stats: BTreeMap<String, KvmStat>,
}

/// One statistic, with the kind and unit KVM declares for it (named as QEMU's `query-stats`
/// names them). The value is in `unit` scaled by `base^exponent`, e.g. nanoseconds for
/// `unit: seconds, base: 10, exponent: -9`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KvmStat {
    /// The kind of statistic.
    #[serde(rename = "type")]
    pub kind: KvmStatType,
    /// The unit, if any; without one, the value is a plain count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<KvmStatUnit>,
    /// The base of the unit's multiple (10 or 2), present when `exponent` isn't 0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<u8>,
    /// The exponent of the unit's multiple, left out when 0.
    #[serde(skip_serializing_if = "is_zero")]
    pub exponent: i16,
    /// The width of each bucket, for linear histograms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket_size: Option<u32>,
    /// The value: a number, or a histogram's bucket counts.
    pub value: KvmStatValue,
}

fn is_zero(exponent: &i16) -> bool {
    *exponent == 0
}

/// The kind of a statistic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum KvmStatType {
    /// A counter that only increases.
    Cumulative,
    /// An instantaneous value.
    Instant,
    /// A peak value, which only increases.
    Peak,
    /// A histogram whose bucket `i` counts values in `[i * bucket_size, (i + 1) * bucket_size)`.
    LinearHistogram,
    /// A histogram whose bucket 0 counts zeros and bucket `i` counts values in `[2^(i-1), 2^i)`.
    Log2Histogram,
}

/// The unit of a statistic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum KvmStatUnit {
    /// Bytes.
    Bytes,
    /// Seconds.
    Seconds,
    /// Clock cycles.
    Cycles,
    /// A boolean, 0 or 1.
    Boolean,
}

/// A statistic's value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum KvmStatValue {
    /// A number.
    Scalar(u64),
    /// A histogram's bucket counts.
    Histogram(Vec<u64>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Desc {
    flags: u32,
    exponent: i16,
    size: u16,
    offset: u32,
    bucket_size: u32,
    name: String,
}

#[derive(Debug)]
struct StatsFd(File);

impl StatsFd {
    fn open(fd: &impl AsRawFd) -> Result<Self, KvmStatsError> {
        // SAFETY: KVM_GET_STATS_FD takes no argument and returns a new descriptor, which we own.
        let stats_fd = unsafe { ioctl(fd, KVM_GET_STATS_FD()) };
        if stats_fd < 0 {
            return Err(KvmStatsError::Open(std::io::Error::last_os_error()));
        }
        // SAFETY: stats_fd is a valid descriptor that nothing else owns.
        Ok(Self(unsafe { File::from_raw_fd(stats_fd) }))
    }

    /// Reads the header, the descriptors, then the data they describe.
    fn read(&self) -> Result<BTreeMap<String, KvmStat>, KvmStatsError> {
        let mut header = [0u8; HEADER_SIZE];
        self.0
            .read_exact_at(&mut header, 0)
            .map_err(KvmStatsError::Read)?;
        let name_size = u32_at(&header, 4);
        let num_desc = u32_at(&header, 8);
        let desc_offset = u32_at(&header, 16);
        let data_offset = u32_at(&header, 20);
        if num_desc > MAX_DESCRIPTORS || name_size == 0 || name_size > MAX_NAME_SIZE {
            return Err(KvmStatsError::Header(num_desc, name_size));
        }

        let mut raw = vec![0u8; (DESC_SIZE + name_size as usize) * num_desc as usize];
        self.0
            .read_exact_at(&mut raw, u64::from(desc_offset))
            .map_err(KvmStatsError::Read)?;
        let descs = parse_descs(&raw, name_size as usize);

        let mut data_size = 0;
        for d in &descs {
            let end = d.offset as usize + 8 * d.size as usize;
            if end > MAX_DATA_SIZE {
                return Err(KvmStatsError::Descriptor(d.name.clone(), d.offset, d.size));
            }
            data_size = data_size.max(end);
        }
        let mut data = vec![0u8; data_size];
        self.0
            .read_exact_at(&mut data, u64::from(data_offset))
            .map_err(KvmStatsError::Read)?;
        Ok(decode(&descs, &data))
    }
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

/// Parses the descriptors: each is flags, exponent, size (in u64s), offset in the data, bucket
/// size, then a NUL-padded name of `name_size` bytes.
fn parse_descs(raw: &[u8], name_size: usize) -> Vec<Desc> {
    raw.chunks_exact(DESC_SIZE + name_size)
        .map(|d| Desc {
            flags: u32_at(d, 0),
            exponent: i16::from_le_bytes([d[4], d[5]]),
            size: u16::from_le_bytes([d[6], d[7]]),
            offset: u32_at(d, 8),
            bucket_size: u32_at(d, 12),
            name: String::from_utf8_lossy(&d[DESC_SIZE..])
                .trim_end_matches('\0')
                .to_string(),
        })
        .collect()
}

/// Decodes the data by its descriptors. The caller sizes `data` to cover every descriptor. A
/// statistic whose kind, unit or base is newer than this code is left out rather than misreported.
fn decode(descs: &[Desc], data: &[u8]) -> BTreeMap<String, KvmStat> {
    let mut out = BTreeMap::new();
    for d in descs {
        let values: Vec<u64> = data[d.offset as usize..][..8 * d.size as usize]
            .as_chunks::<8>()
            .0
            .iter()
            .map(|v| u64::from_le_bytes(*v))
            .collect();
        let kind = match d.flags & KVM_STATS_TYPE_MASK {
            KVM_STATS_TYPE_CUMULATIVE => KvmStatType::Cumulative,
            KVM_STATS_TYPE_INSTANT => KvmStatType::Instant,
            KVM_STATS_TYPE_PEAK => KvmStatType::Peak,
            KVM_STATS_TYPE_LINEAR_HIST => KvmStatType::LinearHistogram,
            KVM_STATS_TYPE_LOG_HIST => KvmStatType::Log2Histogram,
            _ => continue,
        };
        let unit = match d.flags & KVM_STATS_UNIT_MASK {
            KVM_STATS_UNIT_NONE => None,
            KVM_STATS_UNIT_BYTES => Some(KvmStatUnit::Bytes),
            KVM_STATS_UNIT_SECONDS => Some(KvmStatUnit::Seconds),
            KVM_STATS_UNIT_CYCLES => Some(KvmStatUnit::Cycles),
            KVM_STATS_UNIT_BOOLEAN => Some(KvmStatUnit::Boolean),
            _ => continue,
        };
        let base = match d.flags & KVM_STATS_BASE_MASK {
            _ if d.exponent == 0 => None,
            KVM_STATS_BASE_POW10 => Some(10),
            KVM_STATS_BASE_POW2 => Some(2),
            _ => continue,
        };
        let value = match kind {
            KvmStatType::LinearHistogram | KvmStatType::Log2Histogram => {
                KvmStatValue::Histogram(values)
            }
            _ => match values.first() {
                Some(&value) => KvmStatValue::Scalar(value),
                None => continue,
            },
        };
        out.insert(
            d.name.clone(),
            KvmStat {
                kind,
                unit,
                base,
                exponent: d.exponent,
                bucket_size: (kind == KvmStatType::LinearHistogram).then_some(d.bucket_size),
                value,
            },
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lays down a descriptor as the kernel does: flags, exponent, size, offset, bucket size, name.
    fn desc_bytes(
        flags: u32,
        exponent: i16,
        size: u16,
        offset: u32,
        bucket_size: u32,
        name: &str,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&exponent.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&bucket_size.to_le_bytes());
        let mut padded = name.as_bytes().to_vec();
        padded.resize(48, 0);
        out.extend_from_slice(&padded);
        out
    }

    fn data(values: &[u64]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    fn stat(kind: KvmStatType, value: KvmStatValue) -> KvmStat {
        KvmStat {
            kind,
            unit: None,
            base: None,
            exponent: 0,
            bucket_size: None,
            value,
        }
    }

    #[test]
    fn test_decodes_each_kind_and_unit() {
        let ns = KVM_STATS_UNIT_SECONDS | KVM_STATS_BASE_POW10;
        let raw = [
            desc_bytes(KVM_STATS_TYPE_CUMULATIVE, 0, 1, 0, 0, "exits"),
            desc_bytes(
                KVM_STATS_TYPE_CUMULATIVE | ns,
                -9,
                1,
                8,
                0,
                "halt_poll_success_ns",
            ),
            desc_bytes(
                KVM_STATS_TYPE_INSTANT | KVM_STATS_UNIT_BOOLEAN,
                0,
                1,
                16,
                0,
                "guest_mode",
            ),
            desc_bytes(KVM_STATS_TYPE_PEAK, 0, 1, 24, 0, "max_mmu_rmap_size"),
            desc_bytes(KVM_STATS_TYPE_LOG_HIST | ns, -9, 4, 32, 0, "halt_wait_hist"),
            desc_bytes(KVM_STATS_TYPE_LINEAR_HIST, 0, 2, 64, 5, "lin"),
            desc_bytes(
                KVM_STATS_TYPE_INSTANT | KVM_STATS_UNIT_BYTES | KVM_STATS_BASE_POW2,
                10,
                1,
                80,
                0,
                "kib",
            ),
            // Kinds, units and bases newer than this code are left out.
            desc_bytes(0xf, 0, 1, 0, 0, "unknown_kind"),
            desc_bytes(KVM_STATS_TYPE_CUMULATIVE | 0xf0, 0, 1, 0, 0, "unknown_unit"),
            desc_bytes(
                KVM_STATS_TYPE_CUMULATIVE | 0xf00,
                3,
                1,
                0,
                0,
                "unknown_base",
            ),
        ]
        .concat();
        let descs = parse_descs(&raw, 48);
        assert_eq!(descs.len(), 10);
        assert_eq!(descs[1].exponent, -9);

        let stats = decode(&descs, &data(&[42, 7, 1, 9, 1, 3, 0, 0, 2, 4, 64]));
        let ns_stat = |kind, value| KvmStat {
            unit: Some(KvmStatUnit::Seconds),
            base: Some(10),
            exponent: -9,
            ..stat(kind, value)
        };
        assert_eq!(
            stats,
            BTreeMap::from([
                (
                    "exits".to_string(),
                    stat(KvmStatType::Cumulative, KvmStatValue::Scalar(42))
                ),
                (
                    "halt_poll_success_ns".to_string(),
                    ns_stat(KvmStatType::Cumulative, KvmStatValue::Scalar(7))
                ),
                (
                    "guest_mode".to_string(),
                    KvmStat {
                        unit: Some(KvmStatUnit::Boolean),
                        ..stat(KvmStatType::Instant, KvmStatValue::Scalar(1))
                    }
                ),
                (
                    "max_mmu_rmap_size".to_string(),
                    stat(KvmStatType::Peak, KvmStatValue::Scalar(9))
                ),
                (
                    "halt_wait_hist".to_string(),
                    ns_stat(
                        KvmStatType::Log2Histogram,
                        KvmStatValue::Histogram(vec![1, 3, 0, 0])
                    )
                ),
                (
                    "lin".to_string(),
                    KvmStat {
                        bucket_size: Some(5),
                        ..stat(
                            KvmStatType::LinearHistogram,
                            KvmStatValue::Histogram(vec![2, 4])
                        )
                    }
                ),
                (
                    "kib".to_string(),
                    KvmStat {
                        unit: Some(KvmStatUnit::Bytes),
                        base: Some(2),
                        exponent: 10,
                        ..stat(KvmStatType::Instant, KvmStatValue::Scalar(64))
                    }
                ),
            ])
        );
    }

    #[test]
    fn test_serialization() {
        let stats = KvmStats {
            vm: BTreeMap::from([(
                "pages_2m".to_string(),
                stat(KvmStatType::Instant, KvmStatValue::Scalar(3)),
            )]),
            vcpus: vec![VcpuKvmStats {
                index: 1,
                stats: BTreeMap::from([
                    (
                        "halt_wait_hist".to_string(),
                        KvmStat {
                            unit: Some(KvmStatUnit::Seconds),
                            base: Some(10),
                            exponent: -9,
                            ..stat(
                                KvmStatType::Log2Histogram,
                                KvmStatValue::Histogram(vec![0, 2]),
                            )
                        },
                    ),
                    (
                        "lin".to_string(),
                        KvmStat {
                            bucket_size: Some(5),
                            ..stat(
                                KvmStatType::LinearHistogram,
                                KvmStatValue::Histogram(vec![1]),
                            )
                        },
                    ),
                ]),
            }],
        };
        assert_eq!(
            serde_json::to_string(&stats).unwrap(),
            concat!(
                r#"{"vm":{"pages_2m":{"type":"instant","value":3}},"vcpus":[{"index":1,"#,
                r#""stats":{"halt_wait_hist":{"type":"log2-histogram","unit":"seconds","#,
                r#""base":10,"exponent":-9,"value":[0,2]},"#,
                r#""lin":{"type":"linear-histogram","bucket_size":5,"value":[1]}}}]}"#
            )
        );
    }

    #[test]
    fn test_reads_a_real_vm() {
        use crate::vstate::vm::tests::setup_vm_with_memory;

        let mut vm = setup_vm_with_memory(0x1000);
        let _vcpus = vm.create_vcpus(2).unwrap();
        let stats = match vm.kvm_stats() {
            Err(KvmStatsError::Unsupported) => return,
            res => res.unwrap(),
        };
        assert_eq!(
            stats.vcpus.iter().map(|v| v.index).collect::<Vec<_>>(),
            vec![0, 1]
        );
        let vcpu = &stats.vcpus[0].stats;
        assert_eq!(vcpu["exits"].kind, KvmStatType::Cumulative);
        let halt_wait = &vcpu["halt_wait_hist"];
        assert_eq!(halt_wait.kind, KvmStatType::Log2Histogram);
        assert_eq!(
            (halt_wait.unit, halt_wait.base, halt_wait.exponent),
            (Some(KvmStatUnit::Seconds), Some(10), -9)
        );
    }
}
