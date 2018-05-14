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
    pub cpu_template: Option<CpuFeaturesTemplate>,
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
pub enum CpuFeaturesTemplate {
    C3,
    T2,
}

impl fmt::Display for CpuFeaturesTemplate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CpuFeaturesTemplate::C3 => write!(f, "C3"),
            CpuFeaturesTemplate::T2 => write!(f, "T2"),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum MachineConfigurationError {
    InvalidVcpuCount,
    InvalidMemorySize,
}

pub enum PutMachineConfigurationOutcome {
    Created,
    Updated,
    Error(MachineConfigurationError),
}

#[cfg(test)]
mod tests {
    extern crate serde_json;

    use super::*;

    #[test]
    fn test_machine_config_default() {
        let mcfg = MachineConfiguration::default();
        assert_eq!(mcfg.vcpu_count.unwrap(), 1);
        assert_eq!(mcfg.mem_size_mib.unwrap(), 128);
        assert_eq!(mcfg.ht_enabled.unwrap(), false);

        let j = r#"{
                "vcpu_count": 1,
                "mem_size_mib": 128,
                "ht_enabled": false
        }"#;
        let result: MachineConfiguration = serde_json::from_str(j).unwrap();

        assert_eq!(
            format!("{:?}", result.clone()),
            "MachineConfiguration { vcpu_count: Some(1), mem_size_mib: Some(128), ht_enabled: Some(false), cpu_template: None }",
        );

        assert_eq!(result, mcfg);

        let result = serde_json::to_string(&result);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            String::from(j).replace("\n", "").replace(" ", "")
        );
    }

    #[test]
    fn test_machine_config_error() {
        assert_eq!(
            format!("{:?}", MachineConfigurationError::InvalidVcpuCount),
            "InvalidVcpuCount"
        );
        assert_eq!(
            format!("{:?}", MachineConfigurationError::InvalidMemorySize),
            "InvalidMemorySize"
        );
    }

}
