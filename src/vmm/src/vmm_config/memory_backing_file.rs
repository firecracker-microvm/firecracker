use std::{
    fmt::{Display, Formatter},
    io,
    path::PathBuf,
};

use serde::{Deserialize, Serialize};

/// Keeps the Memory Backing file configuration.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryBackingFileConfig {
    /// Location of the memory backing file.
    pub path: PathBuf,
}

/// Errors associated with the operations allowed on a memory backing file.
#[derive(Debug)]
pub enum MemoryBackingFileError {
    /// Failed to create the block device
    CreateFile(io::Error),
}

impl Display for MemoryBackingFileError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::MemoryBackingFileError::*;
        match self {
            CreateFile(e) => write!(f, "Unable to create the memory backing file: {}", e),
        }
    }
}
