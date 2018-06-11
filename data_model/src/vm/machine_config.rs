use std::fmt;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MachineConfiguration {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vcpu_count: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_size_mib: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ht_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_template: Option<CPUFeaturesTemplate>,
}

impl Default for MachineConfiguration {
    fn default() -> Self {
        MachineConfiguration {
            vcpu_count: Some(1),
            mem_size_mib: Some(128),
            ht_enabled: Some(false),
            cpu_template: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub enum CPUFeaturesTemplate {
    C3,
    T2,
}

impl fmt::Display for CPUFeaturesTemplate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CPUFeaturesTemplate::C3 => write!(f, "C3"),
            CPUFeaturesTemplate::T2 => write!(f, "T2"),
        }
    }
}
