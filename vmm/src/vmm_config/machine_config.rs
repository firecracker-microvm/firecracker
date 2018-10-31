use std::fmt::{Display, Formatter, Result};

#[derive(Debug, PartialEq)]
pub enum VmConfigError {
    InvalidVcpuCount,
    InvalidMemorySize,
    UpdateNotAllowedPostBoot,
}

impl Display for VmConfigError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        use self::VmConfigError::*;
        match *self {
            InvalidVcpuCount => write!(
                f,
                "The vCPU number is invalid! The vCPU number can only \
                 be 1 or an even number when hyperthreading is enabled.",
            ),
            InvalidMemorySize => write!(f, "The memory size (MiB) is invalid.",),
            UpdateNotAllowedPostBoot => {
                write!(f, "The update operation is not allowed after boot.")
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VmConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vcpu_count: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_size_mib: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ht_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_template: Option<CpuFeaturesTemplate>,
}

impl Default for VmConfig {
    fn default() -> Self {
        VmConfig {
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

impl Display for CpuFeaturesTemplate {
    fn fmt(&self, f: &mut Formatter) -> Result {
        match self {
            CpuFeaturesTemplate::C3 => write!(f, "C3"),
            CpuFeaturesTemplate::T2 => write!(f, "T2"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_cpu_features_template() {
        assert_eq!(CpuFeaturesTemplate::C3.to_string(), "C3".to_string());
        assert_eq!(CpuFeaturesTemplate::T2.to_string(), "T2".to_string());
    }

    #[test]
    fn test_display_vm_config_error() {
        let expected_str = "The vCPU number is invalid! The vCPU number can only \
                            be 1 or an even number when hyperthreading is enabled.";
        assert_eq!(VmConfigError::InvalidVcpuCount.to_string(), expected_str);

        let expected_str = "The memory size (MiB) is invalid.";
        assert_eq!(VmConfigError::InvalidMemorySize.to_string(), expected_str);

        let expected_str = "The update operation is not allowed after boot.";
        assert_eq!(
            VmConfigError::UpdateNotAllowedPostBoot.to_string(),
            expected_str
        );
    }
}
