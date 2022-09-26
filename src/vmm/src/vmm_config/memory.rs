// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::sync::{Arc, Mutex};

use devices::virtio::Memory;
use serde::{Deserialize, Serialize};

const KIB: u64 = 1024;

type MutexMemory = Arc<Mutex<Memory>>;

/// Errors associated with the operations allowed on the memory.
#[derive(Debug, derive_more::From)]
pub enum MemoryConfigError {
    /// The user made a request on an inexistent memory device.
    DeviceNotFound,
    /// Device not activated yet.
    DeviceNotActive,
    /// There already exists a device with this id.
    DeviceWithThisIdExists,
    /// Failed to create a memory device.
    CreateFailure(devices::virtio::memory::Error),
}

impl fmt::Display for MemoryConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> std::fmt::Result {
        use self::MemoryConfigError::*;
        match self {
            DeviceNotFound => write!(f, "No memory device found."),
            DeviceNotActive => write!(
                f,
                "Device is inactive, check if memory driver is enabled in guest kernel."
            ),
            DeviceWithThisIdExists => write!(f, "A memory device with this id already exists"),
            CreateFailure(err) => write!(f, "Error creating the memory device: {:?}", err),
        }
    }
}

type Result<T> = std::result::Result<T, MemoryConfigError>;

/// This struct represents the strongly typed equivalent of the json body
/// from memory related requests.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryDeviceConfig {
    /// ID of the device.
    pub id: String,
    /// Block size in KiB.
    #[serde(default)]
    pub block_size_kib: u64,
    /// Node id if any.
    pub node_id: Option<u16>,
    /// Region size in KiB.
    pub region_size_kib: u64,
    /// Requested size in KiB.
    #[serde(default)]
    pub requested_size_kib: u64,
}

/// The data fed into a memory update request. The only thing that can be modified
/// is the requested size of the memory region.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryUpdateConfig {
    /// Requested size in KiB.
    pub requested_size_kib: u64,
}

/// A builder for `Memory` devices from 'MemoryDeviceConfig'.
pub struct MemoryBuilder {
    memory_devices: Vec<MutexMemory>,
}

// #[cfg(not(test))]
impl Default for MemoryBuilder {
    fn default() -> MemoryBuilder {
        MemoryBuilder {
            memory_devices: Vec::new(),
        }
    }
}

impl MemoryBuilder {
    /// Creates an empty Memory Store.
    pub fn new() -> Self {
        Default::default()
    }

    /// Creates a Memory device from the MemoryDeviceConfig provided
    fn build(cfg: MemoryDeviceConfig) -> Result<MutexMemory> {
        let memory = Memory::new(
            cfg.block_size_kib * KIB,
            cfg.node_id,
            cfg.region_size_kib * KIB,
            cfg.id,
        )
        .map_err(MemoryConfigError::CreateFailure)?;

        Ok(Arc::new(Mutex::new(memory)))
    }

    /// Inserts into the builder the memory device created from the config.
    pub fn insert(&mut self, cfg: MemoryDeviceConfig) -> Result<()> {
        let memory = Self::build(cfg)?;
        self.add_device(memory)?;

        Ok(())
    }

    /// Inserts an existing memory device.
    pub fn add_device(&mut self, memory: MutexMemory) -> Result<()> {
        for device in &self.memory_devices {
            if device.lock().expect("Poisoned lock").id()
                == memory.lock().expect("Poisoned lock").id()
            {
                return Err(MemoryConfigError::DeviceWithThisIdExists);
            }
        }

        self.memory_devices.push(memory);

        Ok(())
    }

    /// Gets an iterator over mutable references
    pub fn iter_mut(&mut self) -> std::slice::IterMut<MutexMemory> {
        self.memory_devices.iter_mut()
    }

    /// Gets an iterator over references
    pub fn iter(&self) -> std::slice::Iter<MutexMemory> {
        self.memory_devices.iter()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use utils::get_page_size;

    use super::*;

    fn page_size_kib() -> u64 {
        get_page_size().unwrap() as u64 / KIB
    }

    fn default_config() -> MemoryDeviceConfig {
        MemoryDeviceConfig {
            id: String::from("memory-dev"),
            block_size_kib: 4 * page_size_kib(),
            node_id: None,
            region_size_kib: 8 * 4 * page_size_kib(),
            requested_size_kib: 0,
        }
    }

    fn broken_config() -> MemoryDeviceConfig {
        MemoryDeviceConfig {
            id: String::from("broken-config"),
            block_size_kib: 0,
            node_id: None,
            region_size_kib: 8 * 4 * page_size_kib(),
            requested_size_kib: 0,
        }
    }

    #[test]
    fn test_insert_duplicate() {
        let mut memory_builder = MemoryBuilder::new();

        // adding one memory device should work
        assert!(memory_builder.insert(default_config()).is_ok());

        // adding the second memory device with the same Id should fail
        match memory_builder.insert(default_config()) {
            Err(MemoryConfigError::DeviceWithThisIdExists) => {}
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_insert_broken_config() {
        let mut memory_builder = MemoryBuilder::new();

        // trying to build a memory device from an ill-formed config
        match memory_builder.insert(broken_config()) {
            Err(MemoryConfigError::CreateFailure(_)) => {}
            _ => unreachable!(),
        }

        // adding a valid one should work
        assert!(memory_builder.insert(default_config()).is_ok());
    }
}
