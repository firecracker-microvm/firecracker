#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MachineConfiguration {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vcpu_count: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_size_mib: Option<usize>,
}

impl Default for MachineConfiguration {
    fn default() -> Self {
        MachineConfiguration {
            vcpu_count: Some(1),
            mem_size_mib: Some(128),
        }
    }
}
