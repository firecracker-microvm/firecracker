pub mod boot_source;
pub mod instance_info;
pub mod logger;
pub mod net;

pub use self::net::{NetworkInterfaceConfig, NetworkInterfaceConfigs};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum DeviceState {
    Attached,
}
