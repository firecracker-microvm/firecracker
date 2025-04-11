// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::devices::virtio::vsock::{Vsock, VsockError, VsockUnixBackend, VsockUnixBackendError};

type MutexVsockUnix = Arc<Mutex<Vsock<VsockUnixBackend>>>;

/// Errors associated with `NetworkInterfaceConfig`.
#[derive(Debug, derive_more::From, thiserror::Error, displaydoc::Display)]
pub enum VsockConfigError {
    /// Cannot create backend for vsock device: {0}
    CreateVsockBackend(VsockUnixBackendError),
    /// Cannot create vsock device: {0}
    CreateVsockDevice(VsockError),
}

/// This struct represents the strongly typed equivalent of the json body
/// from vsock related requests.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
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

#[derive(Debug)]
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
#[derive(Debug, Default)]
pub struct VsockBuilder {
    inner: Option<VsockAndUnixPath>,
}

impl VsockBuilder {
    /// Creates an empty Vsock with Unix backend Store.
    pub fn new() -> Self {
        Self { inner: None }
    }

    /// Inserts an existing vsock device.
    pub fn set_device(&mut self, device: Arc<Mutex<Vsock<VsockUnixBackend>>>) {
        self.inner = Some(VsockAndUnixPath {
            uds_path: device
                .lock()
                .expect("Poisoned lock")
                .backend()
                .host_sock_path()
                .to_owned(),
            vsock: device.clone(),
        });
    }

    /// Inserts a Unix backend Vsock in the store.
    /// If an entry already exists, it will overwrite it.
    pub fn insert(&mut self, cfg: VsockDeviceConfig) -> Result<(), VsockConfigError> {
        // Make sure to drop the old one and remove the socket before creating a new one.
        if let Some(existing) = self.inner.take() {
            std::fs::remove_file(existing.uds_path).map_err(VsockUnixBackendError::UnixBind)?;
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
    pub fn create_unixsock_vsock(
        cfg: VsockDeviceConfig,
    ) -> Result<Vsock<VsockUnixBackend>, VsockConfigError> {
        let backend = VsockUnixBackend::new(u64::from(cfg.guest_cid), cfg.uds_path)?;

        Vsock::new(u64::from(cfg.guest_cid), backend).map_err(VsockConfigError::CreateVsockDevice)
    }

    /// Returns the structure used to configure the vsock device.
    pub fn config(&self) -> Option<VsockDeviceConfig> {
        self.inner.as_ref().map(VsockDeviceConfig::from)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::devices::virtio::vsock::VSOCK_DEV_ID;

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
        assert_eq!(vsock.lock().unwrap().cid(), u64::from(new_cid));
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
    fn test_set_device() {
        let mut vsock_builder = VsockBuilder::new();
        let mut tmp_sock_file = TempFile::new().unwrap();
        tmp_sock_file.remove().unwrap();
        let vsock = Vsock::new(
            0,
            VsockUnixBackend::new(1, tmp_sock_file.as_path().to_str().unwrap().to_string())
                .unwrap(),
        )
        .unwrap();

        vsock_builder.set_device(Arc::new(Mutex::new(vsock)));
        assert!(vsock_builder.inner.is_some());
        assert_eq!(
            vsock_builder.inner.unwrap().uds_path,
            tmp_sock_file.as_path().to_str().unwrap().to_string()
        )
    }
}
