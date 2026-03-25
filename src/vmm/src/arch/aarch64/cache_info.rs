// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};
use std::{fs, io};

use crate::logger::warn;

// Based on https://elixir.free-electrons.com/linux/v4.9.62/source/arch/arm64/kernel/cacheinfo.c#L29.
const MAX_CACHE_LEVEL: u8 = 7;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum CacheInfoError {
    /// Failed to read cache information: {0}
    FailedToReadCacheInfo(#[from] io::Error),
    /// Invalid cache configuration found for {0}: {1}
    InvalidCacheAttr(String, String),
    /// Cannot read cache level.
    MissingCacheLevel,
    /// Cannot read cache type.
    MissingCacheType,
    /// {0}
    MissingOptionalAttr(String, CacheEntry),
}

struct CacheEngine {
    store: Box<dyn CacheStore>,
}

trait CacheStore: std::fmt::Debug {
    fn get_by_key(&self, index: u8, file_name: &str) -> Result<String, CacheInfoError>;
}

#[derive(Debug)]
pub struct CacheEntry {
    // Cache Level: 1, 2, 3..
    pub level: u8,
    // Type of cache: Unified, Data, Instruction.
    pub type_: CacheType,
    pub size_: Option<u32>,
    pub number_of_sets: Option<u32>,
    pub line_size: Option<u16>,
    // How many CPUS share this cache.
    pub cpus_per_unit: u16,
}

#[derive(Debug)]
#[cfg_attr(test, allow(dead_code))]
struct HostCacheStore {
    cache_dir: PathBuf,
}

#[cfg(not(test))]
impl Default for CacheEngine {
    fn default() -> Self {
        CacheEngine {
            store: Box::new(HostCacheStore {
                cache_dir: PathBuf::from("/sys/devices/system/cpu/cpu0/cache"),
            }),
        }
    }
}

impl CacheStore for HostCacheStore {
    fn get_by_key(&self, index: u8, file_name: &str) -> Result<String, CacheInfoError> {
        readln_special(&PathBuf::from(format!(
            "{}/index{}/{}",
            self.cache_dir.as_path().display(),
            index,
            file_name
        )))
    }
}

impl CacheEntry {
    fn from_index(index: u8, store: &dyn CacheStore) -> Result<CacheEntry, CacheInfoError> {
        let mut err_str = String::new();
        let mut cache: CacheEntry = CacheEntry::default();

        // If the cache level or the type cannot be retrieved we stop the process
        // of populating the cache levels.
        let level_str = store
            .get_by_key(index, "level")
            .map_err(|_| CacheInfoError::MissingCacheLevel)?;
        cache.level = level_str.parse::<u8>().map_err(|err| {
            CacheInfoError::InvalidCacheAttr("level".to_string(), err.to_string())
        })?;

        let cache_type_str = store
            .get_by_key(index, "type")
            .map_err(|_| CacheInfoError::MissingCacheType)?;
        cache.type_ = CacheType::try_from(&cache_type_str)?;

        if let Ok(shared_cpu_map) = store.get_by_key(index, "shared_cpu_map") {
            cache.cpus_per_unit = mask_str2bit_count(shared_cpu_map.trim_end())?;
        } else {
            err_str += "shared cpu map";
            err_str += ", ";
        }

        if let Ok(coherency_line_size) = store.get_by_key(index, "coherency_line_size") {
            cache.line_size = Some(coherency_line_size.parse::<u16>().map_err(|err| {
                CacheInfoError::InvalidCacheAttr("coherency_line_size".to_string(), err.to_string())
            })?);
        } else {
            err_str += "coherency line size";
            err_str += ", ";
        }

        if let Ok(mut size) = store.get_by_key(index, "size") {
            cache.size_ = Some(to_bytes(&mut size)?);
        } else {
            err_str += "size";
            err_str += ", ";
        }

        if let Ok(number_of_sets) = store.get_by_key(index, "number_of_sets") {
            cache.number_of_sets = Some(number_of_sets.parse::<u32>().map_err(|err| {
                CacheInfoError::InvalidCacheAttr("number_of_sets".to_string(), err.to_string())
            })?);
        } else {
            err_str += "number of sets";
            err_str += ", ";
        }

        // Pop the last 2 chars if a comma and space are present.
        // The unwrap is safe since we check that the string actually
        // ends with those 2 chars.
        if err_str.ends_with(", ") {
            err_str.pop().unwrap();
            err_str.pop().unwrap();
        }

        if !err_str.is_empty() {
            return Err(CacheInfoError::MissingOptionalAttr(err_str, cache));
        }

        Ok(cache)
    }
}

impl Default for CacheEntry {
    fn default() -> Self {
        CacheEntry {
            level: 0,
            type_: CacheType::Unified,
            size_: None,
            number_of_sets: None,
            line_size: None,
            cpus_per_unit: 1,
        }
    }
}

#[derive(Debug)]
// Based on https://elixir.free-electrons.com/linux/v4.9.62/source/include/linux/cacheinfo.h#L11.
pub enum CacheType {
    Instruction,
    Data,
    Unified,
}

impl CacheType {
    fn try_from(string: &str) -> Result<Self, CacheInfoError> {
        match string.trim() {
            "Instruction" => Ok(Self::Instruction),
            "Data" => Ok(Self::Data),
            "Unified" => Ok(Self::Unified),
            cache_type => Err(CacheInfoError::InvalidCacheAttr(
                "type".to_string(),
                cache_type.to_string(),
            )),
        }
    }

    // The below are auxiliary functions used for constructing the FDT.
    pub fn of_cache_size(&self) -> &str {
        match self {
            Self::Instruction => "i-cache-size",
            Self::Data => "d-cache-size",
            Self::Unified => "cache-size",
        }
    }

    pub fn of_cache_line_size(&self) -> &str {
        match self {
            Self::Instruction => "i-cache-line-size",
            Self::Data => "d-cache-line-size",
            Self::Unified => "cache-line-size",
        }
    }

    pub fn of_cache_type(&self) -> Option<&'static str> {
        match self {
            Self::Instruction => None,
            Self::Data => None,
            Self::Unified => Some("cache-unified"),
        }
    }

    pub fn of_cache_sets(&self) -> &str {
        match self {
            Self::Instruction => "i-cache-sets",
            Self::Data => "d-cache-sets",
            Self::Unified => "cache-sets",
        }
    }
}

#[cfg_attr(test, allow(unused))]
fn readln_special<T: AsRef<Path>>(file_path: &T) -> Result<String, CacheInfoError> {
    let line = fs::read_to_string(file_path)?;
    Ok(line.trim_end().to_string())
}

fn to_bytes(cache_size_pretty: &mut String) -> Result<u32, CacheInfoError> {
    match cache_size_pretty.pop() {
        Some('K') => Ok(cache_size_pretty.parse::<u32>().map_err(|err| {
            CacheInfoError::InvalidCacheAttr("size".to_string(), err.to_string())
        })? * 1024),
        Some('M') => Ok(cache_size_pretty.parse::<u32>().map_err(|err| {
            CacheInfoError::InvalidCacheAttr("size".to_string(), err.to_string())
        })? * 1024
            * 1024),
        Some(letter) => {
            cache_size_pretty.push(letter);
            Err(CacheInfoError::InvalidCacheAttr(
                "size".to_string(),
                (*cache_size_pretty).to_string(),
            ))
        }
        _ => Err(CacheInfoError::InvalidCacheAttr(
            "size".to_string(),
            "Empty string was provided".to_string(),
        )),
    }
}

// Helper function to count the number of set bits from a bitmap
// formatted string (see %*pb in the printk formats).
// Expected input is a list of 32-bit comma separated hex values,
// without the 0x prefix.
//
fn mask_str2bit_count(mask_str: &str) -> Result<u16, CacheInfoError> {
    let split_mask_iter = mask_str.split(',');
    let mut bit_count: u16 = 0;

    for s in split_mask_iter {
        let mut s_zero_free = s.trim_start_matches('0');
        if s_zero_free.is_empty() {
            s_zero_free = "0";
        }
        bit_count += u16::try_from(
            u32::from_str_radix(s_zero_free, 16)
                .map_err(|err| {
                    CacheInfoError::InvalidCacheAttr("shared_cpu_map".to_string(), err.to_string())
                })?
                .count_ones(),
        )
        .unwrap(); // Safe because this is at most 32
    }
    if bit_count == 0 {
        return Err(CacheInfoError::InvalidCacheAttr(
            "shared_cpu_map".to_string(),
            mask_str.to_string(),
        ));
    }
    Ok(bit_count)
}

fn append_cache_level(
    cache_l1: &mut Vec<CacheEntry>,
    cache_non_l1: &mut Vec<CacheEntry>,
    cache: CacheEntry,
) {
    if cache.level == 1 {
        cache_l1.push(cache);
    } else {
        cache_non_l1.push(cache);
    }
}

pub(crate) fn read_cache_config(
    cache_l1: &mut Vec<CacheEntry>,
    cache_non_l1: &mut Vec<CacheEntry>,
) -> Result<(), CacheInfoError> {
    // It is used to make sure we log warnings for missing files only for one level because
    // if an attribute is missing for a level for sure it will be missing for other levels too.
    // Also without this mechanism we would be logging the warnings for each level which pollutes
    // a lot the logs.
    let mut logged_missing_attr = false;
    let engine = CacheEngine::default();

    for index in 0..=MAX_CACHE_LEVEL {
        match CacheEntry::from_index(index, engine.store.as_ref()) {
            Ok(cache) => {
                append_cache_level(cache_l1, cache_non_l1, cache);
            }
            // Missing cache level or type means not further search is necessary.
            Err(CacheInfoError::MissingCacheLevel) | Err(CacheInfoError::MissingCacheType) => break,
            // Missing cache files is not necessary an error so we
            // do not propagate it upwards. We were prudent enough to log it.
            Err(CacheInfoError::MissingOptionalAttr(msg, cache)) => {
                let level = cache.level;
                append_cache_level(cache_l1, cache_non_l1, cache);
                if !msg.is_empty() && !logged_missing_attr {
                    warn!("Could not read the {msg} for cache level {level}.");
                    logged_missing_attr = true;
                }
            }
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

// CLIDR_EL1 field positions
// https://developer.arm.com/documentation/ddi0595/2021-12/AArch64-Registers/CLIDR-EL1--Cache-Level-ID-Register
const CLIDR_CTYPE_SHIFT: u8 = 3; // Each Ctype field is 3 bits
const CLIDR_LOC_SHIFT: u8 = 24;

// CLIDR_EL1 Ctype field values
const CLIDR_CTYPE_NO_CACHE: u64 = 0;
const CLIDR_CTYPE_INSTRUCTION: u64 = 1;
const CLIDR_CTYPE_DATA: u64 = 2;
const CLIDR_CTYPE_SEPARATE: u64 = 3;
const CLIDR_CTYPE_UNIFIED: u64 = 4;

/// Classify a set of cache entries at the same level into a CLIDR Ctype value.
fn ctype_for_entries<'a>(entries: impl Iterator<Item = &'a CacheEntry>) -> u64 {
    let (mut has_data, mut has_inst, mut has_unified) = (false, false, false);
    let mut any = false;
    for c in entries {
        any = true;
        match c.type_ {
            CacheType::Data => has_data = true,
            CacheType::Instruction => has_inst = true,
            CacheType::Unified => has_unified = true,
        }
    }
    if !any {
        return CLIDR_CTYPE_NO_CACHE;
    }
    if has_unified {
        CLIDR_CTYPE_UNIFIED
    } else if has_data && has_inst {
        CLIDR_CTYPE_SEPARATE
    } else if has_data {
        CLIDR_CTYPE_DATA
    } else if has_inst {
        CLIDR_CTYPE_INSTRUCTION
    } else {
        CLIDR_CTYPE_NO_CACHE
    }
}

/// Build a CLIDR_EL1 value from the host's cache topology read from sysfs.
///
/// Since host kernel 6.3 (commit 7af0c2534f4c), KVM fabricates CLIDR_EL1 to
/// expose a different cache topology than the host. Guest kernels >= 6.1.156
/// backported `init_of_cache_level()` which counts cache leaves from the DT,
/// while `populate_cache_leaves()` uses CLIDR_EL1. If the DT (built from
/// sysfs) describes different cache entries than CLIDR_EL1, the mismatch
/// causes cache sysfs entries to not be created in the guest.
///
/// This function builds a CLIDR_EL1 value that matches the host's real cache
/// topology so it can be written to each vCPU, making CLIDR_EL1 consistent
/// with the FDT.
pub(crate) fn build_clidr_from_caches(
    l1_caches: &[CacheEntry],
    non_l1_caches: &[CacheEntry],
) -> u64 {
    let mut clidr: u64 = 0;
    let mut max_level: u8 = 0;

    let l1_ctype = ctype_for_entries(l1_caches.iter());
    if l1_ctype != CLIDR_CTYPE_NO_CACHE {
        clidr |= l1_ctype;
        max_level = 1;
    }

    for level in 2..=MAX_CACHE_LEVEL {
        let ctype = ctype_for_entries(non_l1_caches.iter().filter(|c| c.level == level));
        if ctype == CLIDR_CTYPE_NO_CACHE {
            break;
        }

        let shift = CLIDR_CTYPE_SHIFT * (level - 1);
        clidr |= ctype << shift;
        max_level = level;
    }

    // Set LoC (Level of Coherence) to the highest cache level
    clidr |= u64::from(max_level) << CLIDR_LOC_SHIFT;

    clidr
}

/// Merge sysfs-derived ctype/LoC fields into an existing CLIDR_EL1 value,
/// preserving LoUU, LoUIS, ICB, and Ttype fields from the original.
///
/// This ensures that on pre-6.3 kernels (where CLIDR already matches sysfs),
/// the write is effectively a no-op, and fields we can't derive from sysfs
/// (like LoUU, LoUIS, ICB) are never clobbered.
pub(crate) fn merge_clidr(current: u64, sysfs: u64) -> u64 {
    // Ctype fields: bits [20:0] (7 levels × 3 bits each = 21 bits)
    // LoC field: bits [26:24]
    // We replace only these fields from sysfs, preserving LoUIS [23:21],
    // LoUU [29:27], ICB [32:30], and Ttype [46:33] from the original.
    const CTYPE_MASK: u64 = 0x001F_FFFF; // bits [20:0]
    const LOC_MASK: u64 = 0x0700_0000; // bits [26:24]
    const REPLACE_MASK: u64 = CTYPE_MASK | LOC_MASK;
    (current & !REPLACE_MASK) | (sysfs & REPLACE_MASK)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::arch::aarch64::cache_info::{
        CacheEngine, CacheEntry, CacheStore, read_cache_config,
    };

    #[derive(Debug)]
    struct MockCacheStore {
        dummy_fs: HashMap<String, String>,
    }

    impl Default for CacheEngine {
        fn default() -> Self {
            CacheEngine {
                store: Box::new(MockCacheStore {
                    dummy_fs: create_default_store(),
                }),
            }
        }
    }

    impl CacheEngine {
        fn new(map: &HashMap<String, String>) -> Self {
            CacheEngine {
                store: Box::new(MockCacheStore {
                    dummy_fs: map.clone(),
                }),
            }
        }
    }

    impl CacheStore for MockCacheStore {
        fn get_by_key(&self, index: u8, file_name: &str) -> Result<String, CacheInfoError> {
            let key = format!("index{}/{}", index, file_name);
            if let Some(val) = self.dummy_fs.get(&key) {
                Ok(val.to_string())
            } else {
                Err(CacheInfoError::FailedToReadCacheInfo(
                    io::Error::from_raw_os_error(0),
                ))
            }
        }
    }

    fn create_default_store() -> HashMap<String, String> {
        let mut cache_struct = HashMap::new();
        cache_struct.insert("index0/level".to_string(), "1".to_string());
        cache_struct.insert("index0/type".to_string(), "Data".to_string());
        cache_struct.insert("index1/level".to_string(), "1".to_string());
        cache_struct.insert("index1/type".to_string(), "Instruction".to_string());
        cache_struct.insert("index2/level".to_string(), "2".to_string());
        cache_struct.insert("index2/type".to_string(), "Unified".to_string());
        cache_struct
    }

    #[test]
    fn test_mask_str2bit_count() {
        mask_str2bit_count("00000000,00000001").unwrap();
        let res = mask_str2bit_count("00000000,00000000");

        assert!(
            res.is_err()
                && format!("{}", res.unwrap_err())
                    == "Invalid cache configuration found for shared_cpu_map: 00000000,00000000"
        );

        let res = mask_str2bit_count("00000000;00000001");
        assert!(
            res.is_err()
                && format!("{}", res.unwrap_err())
                    == "Invalid cache configuration found for shared_cpu_map: invalid digit found \
                        in string"
        );
    }

    #[test]
    fn test_to_bytes() {
        to_bytes(&mut "64K".to_string()).unwrap();
        to_bytes(&mut "64M".to_string()).unwrap();

        match to_bytes(&mut "64KK".to_string()) {
            Err(err) => assert_eq!(
                format!("{}", err),
                "Invalid cache configuration found for size: invalid digit found in string"
            ),
            _ => panic!("This should be an error!"),
        }

        let res = to_bytes(&mut "64G".to_string());
        assert!(
            res.is_err()
                && format!("{}", res.unwrap_err())
                    == "Invalid cache configuration found for size: 64G"
        );

        let res = to_bytes(&mut "".to_string());
        assert!(
            res.is_err()
                && format!("{}", res.unwrap_err())
                    == "Invalid cache configuration found for size: Empty string was provided"
        );
    }

    #[test]
    fn test_cache_level() {
        let mut default_map = create_default_store();

        let mut map1 = default_map.clone();
        map1.remove("index0/type");
        let engine = CacheEngine::new(&map1);
        let res = CacheEntry::from_index(0, engine.store.as_ref());
        // We did create the level file but we still do not have the type file.
        assert!(matches!(res.unwrap_err(), CacheInfoError::MissingCacheType));

        let engine = CacheEngine::new(&default_map);
        let res = CacheEntry::from_index(0, engine.store.as_ref());
        assert_eq!(
            format!("{}", res.unwrap_err()),
            "shared cpu map, coherency line size, size, number of sets",
        );

        // Now putting some invalid values in the type and level files.
        let mut map2 = default_map.clone();
        map2.insert("index0/level".to_string(), "d".to_string());
        let engine = CacheEngine::new(&map2);
        let res = CacheEntry::from_index(0, engine.store.as_ref());
        assert_eq!(
            format!("{}", res.unwrap_err()),
            "Invalid cache configuration found for level: invalid digit found in string"
        );

        default_map.insert("index0/type".to_string(), "Instructionn".to_string());
        let engine = CacheEngine::new(&default_map);
        let res = CacheEntry::from_index(0, engine.store.as_ref());
        assert_eq!(
            format!("{}", res.unwrap_err()),
            "Invalid cache configuration found for type: Instructionn"
        );
    }

    #[test]
    fn test_cache_shared_cpu_map() {
        let mut default_map = create_default_store();

        default_map.insert(
            "index0/shared_cpu_map".to_string(),
            "00000000,00000001".to_string(),
        );
        let engine = CacheEngine::new(&default_map);
        let res = CacheEntry::from_index(0, engine.store.as_ref());
        assert_eq!(
            format!("{}", res.unwrap_err()),
            "coherency line size, size, number of sets"
        );

        default_map.insert(
            "index0/shared_cpu_map".to_string(),
            "00000000,0000000G".to_string(),
        );
        let engine = CacheEngine::new(&default_map);
        let res = CacheEntry::from_index(0, engine.store.as_ref());
        assert_eq!(
            format!("{}", res.unwrap_err()),
            "Invalid cache configuration found for shared_cpu_map: invalid digit found in string"
        );

        default_map.insert("index0/shared_cpu_map".to_string(), "00000000".to_string());
        let engine = CacheEngine::new(&default_map);
        let res = CacheEntry::from_index(0, engine.store.as_ref());
        assert_eq!(
            format!("{}", res.unwrap_err()),
            "Invalid cache configuration found for shared_cpu_map: 00000000"
        );
    }

    #[test]
    fn test_cache_coherency() {
        let mut default_map = create_default_store();

        default_map.insert("index0/coherency_line_size".to_string(), "64".to_string());
        let engine = CacheEngine::new(&default_map);
        let res = CacheEntry::from_index(0, engine.store.as_ref());
        assert_eq!(
            "shared cpu map, size, number of sets",
            format!("{}", res.unwrap_err())
        );

        default_map.insert(
            "index0/coherency_line_size".to_string(),
            "Instruction".to_string(),
        );
        let engine = CacheEngine::new(&default_map);
        let res = CacheEntry::from_index(0, engine.store.as_ref());
        assert_eq!(
            format!("{}", res.unwrap_err()),
            "Invalid cache configuration found for coherency_line_size: invalid digit found in \
             string"
        );
    }

    #[test]
    fn test_cache_size() {
        let mut default_map = create_default_store();

        default_map.insert("index0/size".to_string(), "64K".to_string());
        let engine = CacheEngine::new(&default_map);
        let res = CacheEntry::from_index(0, engine.store.as_ref());
        assert_eq!(
            format!("{}", res.unwrap_err()),
            "shared cpu map, coherency line size, number of sets",
        );

        default_map.insert("index0/size".to_string(), "64".to_string());
        let engine = CacheEngine::new(&default_map);
        let res = CacheEntry::from_index(0, engine.store.as_ref());
        assert_eq!(
            format!("{}", res.unwrap_err()),
            "Invalid cache configuration found for size: 64"
        );

        default_map.insert("index0/size".to_string(), "64Z".to_string());
        let engine = CacheEngine::new(&default_map);
        let res = CacheEntry::from_index(0, engine.store.as_ref());
        assert_eq!(
            format!("{}", res.unwrap_err()),
            "Invalid cache configuration found for size: 64Z"
        );
    }

    #[test]
    fn test_cache_no_sets() {
        let mut default_map = create_default_store();

        default_map.insert("index0/number_of_sets".to_string(), "64".to_string());
        let engine = CacheEngine::new(&default_map);
        let res = CacheEntry::from_index(0, engine.store.as_ref());
        assert_eq!(
            "shared cpu map, coherency line size, size",
            format!("{}", res.unwrap_err())
        );

        default_map.insert("index0/number_of_sets".to_string(), "64K".to_string());
        let engine = CacheEngine::new(&default_map);
        let res = CacheEntry::from_index(0, engine.store.as_ref());
        assert_eq!(
            format!("{}", res.unwrap_err()),
            "Invalid cache configuration found for number_of_sets: invalid digit found in string"
        );
    }

    #[test]
    fn test_sysfs_read_caches() {
        let mut l1_caches: Vec<CacheEntry> = Vec::new();
        let mut non_l1_caches: Vec<CacheEntry> = Vec::new();
        // We use sysfs for extracting the cache information.
        read_cache_config(&mut l1_caches, &mut non_l1_caches).unwrap();
        assert_eq!(l1_caches.len(), 2);
        assert_eq!(l1_caches.len(), 2);
    }

    #[test]
    fn test_build_clidr_from_caches() {
        // L1 Separate (Data + Instruction) + L2 Unified + L3 Unified
        let l1 = vec![
            CacheEntry {
                level: 1,
                type_: CacheType::Data,
                ..CacheEntry::default()
            },
            CacheEntry {
                level: 1,
                type_: CacheType::Instruction,
                ..CacheEntry::default()
            },
        ];
        let non_l1 = vec![
            CacheEntry {
                level: 2,
                type_: CacheType::Unified,
                ..CacheEntry::default()
            },
            CacheEntry {
                level: 3,
                type_: CacheType::Unified,
                ..CacheEntry::default()
            },
        ];
        let clidr = build_clidr_from_caches(&l1, &non_l1);
        // ctype1=3 (Separate), ctype2=4 (Unified), ctype3=4 (Unified), LoC=3
        assert_eq!(clidr & 0x7, 3, "L1 should be Separate");
        assert_eq!((clidr >> 3) & 0x7, 4, "L2 should be Unified");
        assert_eq!((clidr >> 6) & 0x7, 4, "L3 should be Unified");
        assert_eq!((clidr >> 24) & 0x7, 3, "LoC should be 3");

        // L1 Unified only (no higher levels)
        let l1_unified = vec![CacheEntry {
            level: 1,
            type_: CacheType::Unified,
            ..CacheEntry::default()
        }];
        let clidr = build_clidr_from_caches(&l1_unified, &[]);
        assert_eq!(clidr & 0x7, 4, "L1 should be Unified");
        assert_eq!((clidr >> 3) & 0x7, 0, "L2 should be NoCache");
        assert_eq!((clidr >> 24) & 0x7, 1, "LoC should be 1");

        // No caches at all
        let clidr = build_clidr_from_caches(&[], &[]);
        assert_eq!(clidr, 0, "Empty caches should produce CLIDR=0");

        // Mock store default: L1 Data + L1 Instruction + L2 Unified
        let mut l1_mock: Vec<CacheEntry> = Vec::new();
        let mut non_l1_mock: Vec<CacheEntry> = Vec::new();
        read_cache_config(&mut l1_mock, &mut non_l1_mock).unwrap();
        let clidr = build_clidr_from_caches(&l1_mock, &non_l1_mock);
        assert_eq!(clidr & 0x7, 3, "Mock L1 should be Separate");
        assert_eq!((clidr >> 3) & 0x7, 4, "Mock L2 should be Unified");
        assert_eq!((clidr >> 24) & 0x7, 2, "Mock LoC should be 2");
    }

    #[test]
    fn test_merge_clidr() {
        // CLIDR_EL1 layout:
        //   [20:0]  Ctype1..Ctype7 (7 × 3 bits)
        //   [23:21] LoUIS
        //   [26:24] LoC
        //   [29:27] LoUU
        //   [32:30] ICB
        //   [46:33] Ttype1..Ttype7
        //
        // merge_clidr replaces only Ctype [20:0] and LoC [26:24] from sysfs,
        // preserving LoUIS, LoUU, ICB, and Ttype from current.

        // current: LoUU=2 [29:27], LoUIS=1 [23:21], ICB=1 [32:30]
        //          Ctype1=Unified(4) [2:0], LoC=1 [26:24]
        let current: u64 = (1 << 30) // ICB=1
            | (2 << 27)              // LoUU=2
            | (1 << 24)              // LoC=1
            | (1 << 21)              // LoUIS=1
            | 4; // Ctype1=Unified
        // sysfs: Ctype1=Separate(3), Ctype2=Unified(4), Ctype3=Unified(4), LoC=3
        let sysfs: u64 = (3 << 24) | (4 << 6) | (4 << 3) | 3;
        let merged = merge_clidr(current, sysfs);

        // Ctype and LoC should come from sysfs
        assert_eq!(merged & 0x001F_FFFF, sysfs & 0x001F_FFFF, "Ctype mismatch");
        assert_eq!((merged >> 24) & 0x7, 3, "LoC should be 3 from sysfs");
        // LoUIS, LoUU, ICB should be preserved from current
        assert_eq!((merged >> 21) & 0x7, 1, "LoUIS should be preserved");
        assert_eq!((merged >> 27) & 0x7, 2, "LoUU should be preserved");
        assert_eq!((merged >> 30) & 0x7, 1, "ICB should be preserved");

        // When current == sysfs in the replaced region, merge is identity
        let current = 0x0000_0000_0300_0123_u64;
        let sysfs = 0x0000_0000_0300_0123_u64;
        assert_eq!(merge_clidr(current, sysfs), current);
    }
}
