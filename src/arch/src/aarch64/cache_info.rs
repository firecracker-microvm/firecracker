// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{Display, Formatter};
use std::path::{Path, PathBuf};
use std::{fs, io, result};

use logger::warn;

// Based on https://elixir.free-electrons.com/linux/v4.9.62/source/arch/arm64/kernel/cacheinfo.c#L29.
const MAX_CACHE_LEVEL: u8 = 7;

#[derive(Debug)]
pub enum Error {
    FailedToReadCacheInfo(io::Error),
    InvalidCacheAttr(String, String),
    MissingCacheConfig,
    MissingOptionalAttr(String),
}

type Result<T> = result::Result<T, Error>;

#[derive(Clone)]
pub(crate) struct CacheInfo {
    // Cache Level: 1, 2, 3..
    pub level: u8,
    // Type of cache: Unified, Data, Instruction.
    pub type_: CacheType,
    pub size_: Option<usize>,
    pub number_of_sets: Option<u16>,
    pub line_size: Option<u16>,
    // How many CPUS share this cache.
    pub cpus_per_unit: u16,
    // The directory from which to read cache info.
    // In tests this gets modified.
    pub cache_dir: PathBuf,
}

impl Default for CacheInfo {
    fn default() -> Self {
        CacheInfo {
            level: 0,
            type_: CacheType::Unified,
            size_: None,
            number_of_sets: None,
            line_size: None,
            cpus_per_unit: 1,
            cache_dir: PathBuf::from("/sys/devices/system/cpu/cpu0/cache"),
        }
    }
}

#[derive(Clone)]
// Based on https://elixir.free-electrons.com/linux/v4.9.62/source/include/linux/cacheinfo.h#L11.
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
                write!(f, "Invalid cache configuration found for {}: {}", attr, err)
            }
            Error::MissingCacheConfig => write!(f, "Cannot proceed with reading cache info"),
            Error::MissingOptionalAttr(ref msg) => write!(f, "{}", msg),
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

impl CacheInfo {
    fn sysfs_cache(&self, index: u8, file_name: &str) -> Result<String> {
        readln_special(&PathBuf::from(format!(
            "{}/index{}/{}",
            self.cache_dir.as_path().display(),
            index,
            file_name
        )))
    }

    pub fn populate(&mut self, index: u8) -> Result<()> {
        let mut err_str = String::new();

        // If the cache level or the type cannot be retrieved we stop the process
        // of populating the cache levels.
        match self.sysfs_cache(index, "level") {
            Ok(level) => {
                self.level = level
                    .parse::<u8>()
                    .map_err(|e| Error::InvalidCacheAttr("level".to_string(), e.to_string()))?;
            }
            Err(e) => {
                // If we cannot read the cache level even for the first level of cache, we will
                // stop processing anymore cache info and log an error.
                warn!("Could not read cache level for index {}: {}", index, e);
                return Err(Error::MissingCacheConfig);
            }
        }
        match self.sysfs_cache(index, "type") {
            Ok(cache_type) => self.type_ = CacheType::try_from(&cache_type)?,
            Err(e) => {
                warn!("Could not read type for cache level {}: {}", self.level, e);
                return Err(Error::MissingCacheConfig);
            }
        }

        if let Ok(shared_cpu_map) = self.sysfs_cache(index, "shared_cpu_map") {
            self.cpus_per_unit = mask_str2bit_count(shared_cpu_map.trim_end())?;
        } else {
            err_str += "shared cpu map";
            err_str += ", ";
        }

        if let Ok(coherency_line_size) = self.sysfs_cache(index, "coherency_line_size") {
            self.line_size = Some(coherency_line_size.parse::<u16>().map_err(|e| {
                Error::InvalidCacheAttr("coherency_line_size".to_string(), e.to_string())
            })?);
        } else {
            err_str += "coherency line size";
            err_str += ", ";
        }

        if let Ok(mut size) = self.sysfs_cache(index, "size") {
            self.size_ = Some(to_bytes(&mut size)?);
        } else {
            err_str += "size";
            err_str += ", ";
        }

        if let Ok(number_of_sets) = self.sysfs_cache(index, "number_of_sets") {
            self.number_of_sets = Some(number_of_sets.parse::<u16>().map_err(|e| {
                Error::InvalidCacheAttr("number_of_sets".to_string(), e.to_string())
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

        if err_str != "" {
            return Err(Error::MissingOptionalAttr(err_str));
        }

        Ok(())
    }

    pub fn level(&self) -> u8 {
        self.level
    }
}

fn readln_special<T: AsRef<Path>>(file_path: &T) -> Result<String> {
    let line = fs::read_to_string(file_path).map_err(Error::FailedToReadCacheInfo)?;
    Ok(line.trim_end().to_string())
}

fn to_bytes(cache_size_pretty: &mut String) -> Result<usize> {
    match cache_size_pretty.pop() {
        Some('K') => Ok(cache_size_pretty
            .parse::<usize>()
            .map_err(|e| Error::InvalidCacheAttr("size".to_string(), e.to_string()))?
            * 1024),
        Some('M') => Ok(cache_size_pretty
            .parse::<usize>()
            .map_err(|e| Error::InvalidCacheAttr("size".to_string(), e.to_string()))?
            * 1024
            * 1024),
        Some(letter) => {
            cache_size_pretty.push(letter);
            Err(Error::InvalidCacheAttr(
                "size".to_string(),
                (*cache_size_pretty).to_string(),
            ))
        }
        _ => Err(Error::InvalidCacheAttr(
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
fn mask_str2bit_count(mask_str: &str) -> Result<u16> {
    let split_mask_iter = mask_str.split(',');
    let mut bit_count: u16 = 0;

    for s in split_mask_iter {
        let mut s_zero_free = s.trim_start_matches('0');
        if s_zero_free.is_empty() {
            s_zero_free = "0";
        }
        bit_count += u32::from_str_radix(s_zero_free, 16)
            .map_err(|e| Error::InvalidCacheAttr("shared_cpu_map".to_string(), e.to_string()))?
            .count_ones() as u16;
    }
    if bit_count == 0 {
        return Err(Error::InvalidCacheAttr(
            "shared_cpu_map".to_string(),
            mask_str.to_string(),
        ));
    }
    Ok(bit_count)
}

pub(crate) fn sysfs_read_caches(
    cache_l1: &mut Vec<CacheInfo>,
    cache_non_l1: &mut Vec<CacheInfo>,
) -> Result<()> {
    let mut cache: CacheInfo = CacheInfo::default();
    // These variables are used to make sure we log warnings for missing files only for one level because
    // if an attribute is missing for a level for sure it will be missing for other levels too.
    // Also without this mechanism we would be logging the warnings for each level which pollutes
    // a lot the logs.
    let mut logged_missing_attr = false;

    for index in 0..(MAX_CACHE_LEVEL + 1) {
        match cache.populate(index) {
            Ok(()) => {
                let cache_info = cache.clone();
                if cache.level() == 1 {
                    cache_l1.push(cache_info);
                } else {
                    cache_non_l1.push(cache_info);
                }
            }
            // Missing cache files is not necessary an error so we
            // do not propagate it upwards. We were prudent enough to log a warning.
            Err(Error::MissingCacheConfig) => return Ok(()),
            Err(Error::MissingOptionalAttr(ref msg)) => {
                if msg != "" && !logged_missing_attr {
                    warn!(
                        "{}",
                        format!(
                            "Could not read the {} for cache level {}.",
                            msg, cache.level
                        )
                    );
                    logged_missing_attr = true;
                }
            }
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
