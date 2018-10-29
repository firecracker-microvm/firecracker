pub mod boot_source;
pub mod drive;
pub mod instance_info;
pub mod logger;
pub mod net;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum DeviceState {
    Attached,
}
