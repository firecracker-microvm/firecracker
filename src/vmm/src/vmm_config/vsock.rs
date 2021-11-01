// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use std::fmt;
use std::sync::{Arc, Mutex};

use devices::virtio::{Vsock, VsockError, VsockUnixBackend, VsockUnixBackendError};

use serde::{Deserialize, Serialize};

type MutexVsockUnix = Arc<Mutex<Vsock<VsockUnixBackend>>>;

/// Errors associated with `NetworkInterfaceConfig`.
#[derive(Debug)]
pub enum VsockConfigError {
    /// Failed to create the backend for the vsock device.
    CreateVsockBackend(VsockUnixBackendError),
    /// Failed to create the vsock device.
    CreateVsockDevice(VsockError),
}

impl fmt::Display for VsockConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::VsockConfigError::*;
        match *self {
            CreateVsockBackend(ref e) => {
                write!(f, "Cannot create backend for vsock device: {:?}", e)
            }
            CreateVsockDevice(ref e) => write!(f, "Cannot create vsock device: {:?}", e),
        }
    }
}

type Result<T> = std::result::Result<T, VsockConfigError>;

/// This struct represents the strongly typed equivalent of the json body
/// from vsock related requests.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VsockDeviceConfig {
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    /// ID of the vsock device.
    pub vsock_id: Option<String>,
    /// A 32-bit Context Identifier (CID) used to identify the guest.
    pub guest_cid: u32,
    /// Path to local unix socket.
    pub uds_path: String,
}

struct VsockAndUnixPath {
    vsock: MutexVsockUnix,
    uds_path: String,
}

impl From<&VsockAndUnixPath> for VsockDeviceConfig {
    fn from(vsock: &VsockAndUnixPath) -> Self {
        let vsock_lock = vsock.vsock.lock().unwrap();
        VsockDeviceConfig {
            vsock_id: None,
            guest_cid: u32::try_from(vsock_lock.cid()).unwrap(),
            uds_path: vsock.uds_path.clone(),
        }
    }
}

/// A builder of Vsock with Unix backend from 'VsockDeviceConfig'.
#[derive(Default)]
pub struct VsockBuilder {
    inner: Option<VsockAndUnixPath>,
}

impl VsockBuilder {
    /// Creates an empty Vsock with Unix backend Store.
    pub fn new() -> Self {
        Self { inner: None }
    }

    /// Inserts a Unix backend Vsock in the store.
    /// If an entry already exists, it will overwrite it.
    pub fn insert(&mut self, cfg: VsockDeviceConfig) -> Result<()> {
        // Make sure to drop the old one and remove the socket before creating a new one.
        if let Some(existing) = self.inner.take() {
            std::fs::remove_file(existing.uds_path)
                .map_err(VsockUnixBackendError::UnixBind)
                .map_err(VsockConfigError::CreateVsockBackend)?;
        }
        self.inner = Some(VsockAndUnixPath {
            uds_path: cfg.uds_path.clone(),
            vsock: Arc::new(Mutex::new(Self::create_unixsock_vsock(cfg)?)),
        });
        Ok(())
    }

    /// Provides a reference to the Vsock if present.
    pub fn get(&self) -> Option<&MutexVsockUnix> {
        self.inner.as_ref().map(|pair| &pair.vsock)
    }

    /// Creates a Vsock device from a VsockDeviceConfig.
    pub fn create_unixsock_vsock(cfg: VsockDeviceConfig) -> Result<Vsock<VsockUnixBackend>> {
        let backend = VsockUnixBackend::new(u64::from(cfg.guest_cid), cfg.uds_path)
            .map_err(VsockConfigError::CreateVsockBackend)?;

        Vsock::new(u64::from(cfg.guest_cid), backend).map_err(VsockConfigError::CreateVsockDevice)
    }

    /// Returns the structure used to configure the vsock device.
    pub fn config(&self) -> Option<VsockDeviceConfig> {
        self.inner.as_ref().map(VsockDeviceConfig::from)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use devices::virtio::vsock::VSOCK_DEV_ID;
    use utils::tempfile::TempFile;

    pub(crate) fn default_config(tmp_sock_file: &TempFile) -> VsockDeviceConfig {
        VsockDeviceConfig {
            vsock_id: None,
            guest_cid: 3,
            uds_path: tmp_sock_file.as_path().to_str().unwrap().to_string(),
        }
    }

    #[test]
    fn test_vsock_create() {
        let mut tmp_sock_file = TempFile::new().unwrap();
        tmp_sock_file.remove().unwrap();
        let vsock_config = default_config(&tmp_sock_file);
        VsockBuilder::create_unixsock_vsock(vsock_config).unwrap();
    }

    #[test]
    fn test_vsock_insert() {
        let mut store = VsockBuilder::new();
        let mut tmp_sock_file = TempFile::new().unwrap();
        tmp_sock_file.remove().unwrap();
        let mut vsock_config = default_config(&tmp_sock_file);

        store.insert(vsock_config.clone()).unwrap();
        let vsock = store.get().unwrap();
        assert_eq!(vsock.lock().unwrap().id(), VSOCK_DEV_ID);

        let new_cid = vsock_config.guest_cid + 1;
        vsock_config.guest_cid = new_cid;
        store.insert(vsock_config).unwrap();
        let vsock = store.get().unwrap();
        assert_eq!(vsock.lock().unwrap().cid(), new_cid as u64);
    }

    #[test]
    fn test_vsock_config() {
        let mut vsock_builder = VsockBuilder::new();
        let mut tmp_sock_file = TempFile::new().unwrap();
        tmp_sock_file.remove().unwrap();
        let vsock_config = default_config(&tmp_sock_file);
        vsock_builder.insert(vsock_config.clone()).unwrap();

        let config = vsock_builder.config();
        assert!(config.is_some());
        assert_eq!(config.unwrap(), vsock_config);
    }

    #[test]
    fn test_error_messages() {
        use super::VsockConfigError::*;
        use std::io;
        let err = CreateVsockBackend(devices::virtio::VsockUnixBackendError::EpollAdd(
            io::Error::from_raw_os_error(0),
        ));
        let _ = format!("{}{:?}", err, err);

        let err = CreateVsockDevice(devices::virtio::VsockError::EventFd(
            io::Error::from_raw_os_error(0),
        ));
        let _ = format!("{}{:?}", err, err);
    }
}
