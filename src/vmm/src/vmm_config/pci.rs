use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PciConfig {
    pub enabled: bool,
    pub vfio_devices: Option<Vec<VfioDeviceConfig>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct VfioDeviceConfig {
    // sysfs path of the device
    pub path: String,
}