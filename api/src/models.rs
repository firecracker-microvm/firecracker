#![allow(unused_qualifications)]

use models;

/// Boot source descriptor. 'source_type' will specify the boot source type and depending on its value: one and only one of 'local_image', 'drive_boot' or 'network_boot' should describe the boot resource in detail. 
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BootSource {
    /// unique identifier for this boot source
    #[serde(rename = "boot_source_id")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub boot_source_id: Option<String>,

    /// type of boot source
    // Note: inline enums are not fully supported by swagger-codegen
    #[serde(rename = "source_type")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub source_type: Option<String>,

    #[serde(rename = "local_image")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub local_image: Option<models::LocalImage>,

    #[serde(rename = "drive_boot")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub drive_boot: Option<models::DriveBoot>,

    #[serde(rename = "network_boot")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub network_boot: Option<models::NetworkBoot>,

    /// kernel boot arguments
    #[serde(rename = "boot_args")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub boot_args: Option<String>,

}

impl BootSource {
    pub fn new() -> BootSource {
        BootSource {
            boot_source_id: None,
            source_type: None,
            local_image: None,
            drive_boot: None,
            network_boot: None,
            boot_args: None,
        }
    }
}

/// Enumeration of values.
/// Since this enum's variants do not hold data, we can easily define them them as `#[repr(C)]`
/// which helps with FFI.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum DeviceState { 
    #[serde(rename = "attached")]
    ATTACHED,
    #[serde(rename = "detaching")]
    DETACHING,
    #[serde(rename = "detached")]
    DETACHED,
}

impl ::std::fmt::Display for DeviceState {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            DeviceState::ATTACHED => write!(f, "{}", "attached"),
            DeviceState::DETACHING => write!(f, "{}", "detaching"),
            DeviceState::DETACHED => write!(f, "{}", "detached"),
        }
    }
}

impl ::std::str::FromStr for DeviceState {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "attached" => Ok(DeviceState::ATTACHED),
            "detaching" => Ok(DeviceState::DETACHING),
            "detached" => Ok(DeviceState::DETACHED),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Drive {
    #[serde(rename = "drive_id")]
    pub drive_id: String,

    /// host level path for the guest drive
    #[serde(rename = "path_on_host")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub path_on_host: Option<String>,

    #[serde(rename = "state")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub state: Option<models::DeviceState>,

}

impl Drive {
    pub fn new(drive_id: String, ) -> Drive {
        Drive {
            drive_id: drive_id,
            path_on_host: None,
            state: None,
        }
    }
}

/// Drive to use as boot source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DriveBoot {
    /// unique identifier specifying which drive to boot from
    #[serde(rename = "drive_id")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub drive_id: Option<String>,

}

impl DriveBoot {
    pub fn new() -> DriveBoot {
        DriveBoot {
            drive_id: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Error {
    /// A description of the error condition.
    #[serde(rename = "faultMessage")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub fault_message: Option<String>,

}

impl Error {
    pub fn new() -> Error {
        Error {
            fault_message: None,
        }
    }
}

/// Variant wrapper containing the real action. For listInstanceActions, only action_id will be populated. instance_device_detach_action will only be present if action_type is InstanceDeviceDetach. 
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InstanceActionInfo {
    #[serde(rename = "action_id")]
    pub action_id: String,

    /// Enumeration indicating what type of action is contained in the payload.
    // Note: inline enums are not fully supported by swagger-codegen
    #[serde(rename = "action_type")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub action_type: Option<String>,

    #[serde(rename = "instance_device_detach_action")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub instance_device_detach_action: Option<models::InstanceDeviceDetachAction>,

    #[serde(rename = "timestamp")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub timestamp: Option<String>,

}

impl InstanceActionInfo {
    pub fn new(action_id: String, ) -> InstanceActionInfo {
        InstanceActionInfo {
            action_id: action_id,
            action_type: None,
            instance_device_detach_action: None,
            timestamp: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InstanceDeviceDetachAction {
    // Note: inline enums are not fully supported by swagger-codegen
    #[serde(rename = "device_type")]
    pub device_type: String,

    #[serde(rename = "device_resource_id")]
    pub device_resource_id: String,

    #[serde(rename = "force")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub force: Option<bool>,

}

impl InstanceDeviceDetachAction {
    pub fn new(device_type: String, device_resource_id: String, ) -> InstanceDeviceDetachAction {
        InstanceDeviceDetachAction {
            device_type: device_type,
            device_resource_id: device_resource_id,
            force: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InstanceInfo {
    #[serde(rename = "instance_id")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub instance_id: Option<String>,

    /// The current detailed state of the Firecracker instance. This value is read-only by the control-plane. 
    // Note: inline enums are not fully supported by swagger-codegen
    #[serde(rename = "state")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub state: Option<String>,

    #[serde(rename = "node_info")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub node_info: Option<models::NodeInfo>,

}

impl InstanceInfo {
    pub fn new() -> InstanceInfo {
        InstanceInfo {
            instance_id: None,
            state: None,
            node_info: None,
        }
    }
}

/// Instance metadata or metainformation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InstanceMetadata {
    /// The numeric instance-id.
    #[serde(rename = "virt_id")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub virt_id: Option<i64>,

    /// The AWS account ID of the instance's owner
    #[serde(rename = "account_id")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub account_id: Option<String>,

    /// The instance type - e.g. 'm3.xlarge', etc.
    #[serde(rename = "instance_type")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub instance_type: Option<String>,

    /// The numeric image id (ami) of the instance.
    #[serde(rename = "image_id")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub image_id: Option<i64>,

    /// True for enabling detailed monitoring
    #[serde(rename = "detailed_monitoring")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub detailed_monitoring: Option<bool>,

}

impl InstanceMetadata {
    pub fn new() -> InstanceMetadata {
        InstanceMetadata {
            virt_id: None,
            account_id: None,
            instance_type: None,
            image_id: None,
            detailed_monitoring: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InstanceStartAction {
    #[serde(rename = "timestamp")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub timestamp: Option<String>,

}

impl InstanceStartAction {
    pub fn new() -> InstanceStartAction {
        InstanceStartAction {
            timestamp: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Limiter {
    /// Id of this limiter.
    #[serde(rename = "limiter_id")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub limiter_id: Option<String>,

    #[serde(rename = "egress")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub egress: Option<models::LimiterConfig>,

    #[serde(rename = "ingress")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub ingress: Option<models::LimiterConfig>,

    #[serde(rename = "egress_counters")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub egress_counters: Option<models::LimiterCounters>,

    #[serde(rename = "ingress_counters")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub ingress_counters: Option<models::LimiterCounters>,

}

impl Limiter {
    pub fn new() -> Limiter {
        Limiter {
            limiter_id: None,
            egress: None,
            ingress: None,
            egress_counters: None,
            ingress_counters: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LimiterConfig {
    /// In bits.
    #[serde(rename = "bandwidth")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub bandwidth: Option<models::TokenBucket>,

    /// In packets or ops.
    #[serde(rename = "pps")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub pps: Option<models::TokenBucket>,

    #[serde(rename = "max_queue_len")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub max_queue_len: Option<i64>,

}

impl LimiterConfig {
    pub fn new() -> LimiterConfig {
        LimiterConfig {
            bandwidth: None,
            pps: None,
            max_queue_len: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LimiterCounters {
    #[serde(rename = "packets")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub packets: Option<i64>,

    #[serde(rename = "bytes")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub bytes: Option<i64>,

    #[serde(rename = "dropped_packets")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub dropped_packets: Option<i64>,

    #[serde(rename = "dropped_bytes")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub dropped_bytes: Option<i64>,

}

impl LimiterCounters {
    pub fn new() -> LimiterCounters {
        LimiterCounters {
            packets: None,
            bytes: None,
            dropped_packets: None,
            dropped_bytes: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LimiterList {
    /// Opaque token that specifies where to start the next list of limiters. If not present or NULL, there are no more limiters to list. 
    #[serde(rename = "next_token")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub next_token: Option<String>,

    #[serde(rename = "limiters")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub limiters: Option<Vec<models::Limiter>>,

}

impl LimiterList {
    pub fn new() -> LimiterList {
        LimiterList {
            next_token: None,
            limiters: None,
        }
    }
}

/// Locations for local kernel image and initrd files. Empty path(s) means not used. 
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocalImage {
    /// host level path to the kernel image used to boot the guest
    #[serde(rename = "kernel_image_path")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub kernel_image_path: Option<String>,

    /// host level path to initrd used to boot the guest
    #[serde(rename = "initrd_path")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub initrd_path: Option<String>,

}

impl LocalImage {
    pub fn new() -> LocalImage {
        LocalImage {
            kernel_image_path: None,
            initrd_path: None,
        }
    }
}

/// Network to use as boot source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkBoot {
    /// unique identifier specifying which network interface to boot from
    #[serde(rename = "iface_id")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub iface_id: Option<String>,

}

impl NetworkBoot {
    pub fn new() -> NetworkBoot {
        NetworkBoot {
            iface_id: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkInterface {
    #[serde(rename = "iface_id")]
    pub iface_id: String,

    #[serde(rename = "mac")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub mac: Option<String>,

    /// host level path for the guest network interface
    #[serde(rename = "path_on_host")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub path_on_host: Option<String>,

    #[serde(rename = "state")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub state: Option<models::DeviceState>,

}

impl NetworkInterface {
    pub fn new(iface_id: String, ) -> NetworkInterface {
        NetworkInterface {
            iface_id: iface_id,
            mac: None,
            path_on_host: None,
            state: None,
        }
    }
}

/// Node information for this instance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeInfo {
    /// The number of 2MiB pages of memory in this instance.
    #[serde(rename = "nr_huge_pages")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub nr_huge_pages: Option<i32>,

    /// The number of CPU cores in this instance.
    #[serde(rename = "cores")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub cores: Option<i32>,

    /// Bitmask for the active CPU features in this instance.
    #[serde(rename = "cpu_features")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub cpu_features: Option<i64>,

}

impl NodeInfo {
    pub fn new() -> NodeInfo {
        NodeInfo {
            nr_huge_pages: None,
            cores: None,
            cpu_features: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TokenBucket {
    #[serde(rename = "size")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub size: Option<i64>,

    #[serde(rename = "cost")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub cost: Option<i64>,

    #[serde(rename = "initial_value")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub initial_value: Option<i64>,

    #[serde(rename = "refill_rate")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub refill_rate: Option<i64>,

}

impl TokenBucket {
    pub fn new() -> TokenBucket {
        TokenBucket {
            size: None,
            cost: None,
            initial_value: None,
            refill_rate: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Vsock {
    #[serde(rename = "vsock_id")]
    pub vsock_id: String,

    /// host level path for the guest vsock
    #[serde(rename = "path_on_host")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub path_on_host: Option<String>,

    #[serde(rename = "state")]
    #[serde(skip_serializing_if="Option::is_none")]
    pub state: Option<models::DeviceState>,

}

impl Vsock {
    pub fn new(vsock_id: String, ) -> Vsock {
        Vsock {
            vsock_id: vsock_id,
            path_on_host: None,
            state: None,
        }
    }
}
