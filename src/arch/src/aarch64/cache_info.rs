// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{Display, Formatter};
use std::path::{Path, PathBuf};
use std::{fs, io, result};

// Based on https://elixir.free-electrons.com/linux/v4.9.62/source/arch/arm64/kernel/cacheinfo.c#L29.
const MAX_CACHE_LEVEL: u8 = 7;

#[derive(Debug)]
pub enum Error {
    FailedToReadCacheInfo(io::Error),
    InvalidCacheAttr(String, String),
    NoMoreCacheLevels(u8),
}

type Result<T> = result::Result<T, Error>;

#[derive(Default)]
pub struct CacheInfo {
    // Cache Level: 1, 2, 3..
    pub level: u8,
    pub size_: usize,
    // Type of cache: Unified, Data, Instruction.
    pub type_: CacheType,
    pub number_of_sets: u16,
    pub line_size: u16,
    // How many CPUS share this cache.
    pub cpus_per_unit: u16,
}

// Based on https://elixir.free-electrons.com/linux/v4.9.62/source/include/linux/cacheinfo.h#L11.
#[derive(Debug)]
pub enum CacheType {
    Instruction,
    Data,
    Unified,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match *self {
            Error::FailedToReadCacheInfo(ref err) => {
                write!(f, "Failed to read cache information: {}", err)
            }
            Error::InvalidCacheAttr(ref attr, ref err) => {
                write!(f, "Invalid \"{}\" cache attribute: {}", attr, err)
            }
            Error::NoMoreCacheLevels(ref index) => {
                write!(f, "Reached maximum cache index: {}", index)
            }
        }
    }
}

impl CacheType {
    fn try_from(string: &str) -> Result<Self> {
        match string.trim() {
            "Instruction" => Ok(Self::Instruction),
            "Data" => Ok(Self::Data),
            "Unified" => Ok(Self::Unified),
            cache_type => Err(Error::InvalidCacheAttr(
                "Type".to_string(),
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

impl Default for CacheType {
    fn default() -> CacheType {
        CacheType::Unified
    }
}

fn readln_special<T: AsRef<Path>>(file_path: &T) -> Result<String> {
    let line = fs::read_to_string(file_path).map_err(Error::FailedToReadCacheInfo)?;
    Ok(line.trim_end().to_string())
}

fn sysfs_cache(index: u8, file_name: &str) -> Result<String> {
    readln_special(&PathBuf::from(format!(
        "/sys/devices/system/cpu/cpu0/cache/index{}/{}",
        index, file_name
    )))
}

fn to_bytes(cache_size_pretty: &mut String) -> Result<usize> {
    match cache_size_pretty.pop() {
        Some('K') => Ok(cache_size_pretty
            .parse::<usize>()
            .map_err(|e| Error::InvalidCacheAttr("Size".to_string(), e.to_string()))?
            * 1024),
        Some('M') => Ok(cache_size_pretty
            .parse::<usize>()
            .map_err(|e| Error::InvalidCacheAttr("Size".to_string(), e.to_string()))?
            * 1024
            * 1024),
        Some(letter) => {
            cache_size_pretty.push(letter);
            Err(Error::InvalidCacheAttr(
                "Size".to_string(),
                (*cache_size_pretty).to_string(),
            ))
        }
        _ => Err(Error::InvalidCacheAttr(
            "Size".to_string(),
            "Empty string was provided".to_string(),
        )),
    }
}

// Helper function to count the number of set bits from a bitmap
// formatted string (see %*pb in the printk formats).
// Expected input is a list of 32-bit comma separated hex values,
// without the 0x prefix.
//
fn mask_str2bit_count(mask_str: &str) -> Result<u16> {
    let split_mask_iter = mask_str.split(',');
    let mut bit_count: u16 = 0;

    for s in split_mask_iter {
        let mut s_zero_free = s.trim_start_matches('0');
        if s_zero_free.is_empty() {
            s_zero_free = "0";
        }
        bit_count += u32::from_str_radix(s_zero_free, 16)
            .map_err(|e| Error::InvalidCacheAttr("Shared Cpu Map".to_string(), e.to_string()))?
            .count_ones() as u16;
    }
    if bit_count == 0 {
        return Err(Error::InvalidCacheAttr(
            "Shared Cpu Map".to_string(),
            mask_str.to_string(),
        ));
    }
    Ok(bit_count)
}

fn populate_cache_info(index: u8) -> Result<CacheInfo> {
    let mut cache: CacheInfo = CacheInfo::default();

    // If the cache type cannot be retrieved it means that we exhausted all cache levels
    // and so we return the result.
    let cache_type;
    match sysfs_cache(index, "type") {
        Ok(t) => cache_type = t,
        Err(e) => {
            if index == 0 {
                return Err(e);
            } else {
                return Err(Error::NoMoreCacheLevels(index));
            }
        }
    }

    let level = sysfs_cache(index, "level").unwrap_or_else(|_| "".to_string());
    let shared_cpu_map = sysfs_cache(index, "shared_cpu_map").unwrap_or_else(|_| "".to_string());
    let coherency_line_size =
        sysfs_cache(index, "coherency_line_size").unwrap_or_else(|_| "".to_string());
    let number_of_sets = sysfs_cache(index, "number_of_sets").unwrap_or_else(|_| "".to_string());
    let mut size = sysfs_cache(index, "size").unwrap_or_else(|_| "".to_string());

    cache.type_ = CacheType::try_from(&cache_type)?;
    cache.level = level
        .parse::<u8>()
        .map_err(|e| Error::InvalidCacheAttr("Level".to_string(), e.to_string()))?;
    cache.line_size = coherency_line_size
        .parse::<u16>()
        .map_err(|e| Error::InvalidCacheAttr("Line Size".to_string(), e.to_string()))?;
    cache.size_ = to_bytes(&mut size)
        .map_err(|e| Error::InvalidCacheAttr("Size".to_string(), e.to_string()))?;
    cache.number_of_sets = number_of_sets
        .parse::<u16>()
        .map_err(|e| Error::InvalidCacheAttr("Number of Sets".to_string(), e.to_string()))?;
    // calculating the number of cpus that share the same cache unit.
    cache.cpus_per_unit = mask_str2bit_count(shared_cpu_map.trim_end())?;
    Ok(cache)
}

pub fn sysfs_read_caches(
    cache_l1: &mut Vec<CacheInfo>,
    cache_non_l1: &mut Vec<CacheInfo>,
) -> Result<()> {
    for index in 0..(MAX_CACHE_LEVEL + 1) {
        match populate_cache_info(index) {
            Ok(cache_info) => {
                if cache_info.level == 1 {
                    cache_l1.push(cache_info);
                } else {
                    cache_non_l1.push(cache_info);
                }
            }
            Err(Error::NoMoreCacheLevels(_)) => return Ok(()),
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_str2bit_count() {
        assert!(mask_str2bit_count("00000000,00000001").is_ok());
        let res = mask_str2bit_count("00000000,00000000");

        assert!(
            res.is_err()
                && format!("{}", res.unwrap_err())
                    == "Invalid \"Shared Cpu Map\" cache attribute: 00000000,00000000"
        );

        let res = mask_str2bit_count("00000000;00000001");
        assert!(
            res.is_err()
                && format!("{}", res.unwrap_err())
                    == "Invalid \"Shared Cpu Map\" cache attribute: invalid digit found in string"
        );
    }

    #[test]
    fn test_to_bytes() {
        assert!(to_bytes(&mut "64K".to_string()).is_ok());
        assert!(to_bytes(&mut "64M".to_string()).is_ok());

        let res = to_bytes(&mut "64KK".to_string());
        assert!(
            res.is_err()
                && format!("{}", res.unwrap_err())
                    == "Invalid \"Size\" cache attribute: invalid digit found in string"
        );

        let res = to_bytes(&mut "64G".to_string());
        assert!(
            res.is_err()
                && format!("{}", res.unwrap_err()) == "Invalid \"Size\" cache attribute: 64G"
        );

        let res = to_bytes(&mut "".to_string());
        assert!(
            res.is_err()
                && format!("{}", res.unwrap_err())
                    == "Invalid \"Size\" cache attribute: Empty string was provided"
        );
    }
}
