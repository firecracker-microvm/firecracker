use std::fmt::{Display, Formatter, Result};

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootSourceConfig {
    pub kernel_image_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_args: Option<String>,
}

#[derive(Debug)]
pub enum BootSourceConfigError {
    InvalidKernelPath,
    InvalidKernelCommandLine,
    UpdateNotAllowedPostBoot,
}

impl Display for BootSourceConfigError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        use self::BootSourceConfigError::*;
        match *self {
            InvalidKernelPath => write!(
                f,
                "The kernel file cannot be opened due to invalid kernel path or \
                 invalid permissions.",
            ),
            InvalidKernelCommandLine => write!(f, "The kernel command line is invalid!"),
            UpdateNotAllowedPostBoot => {
                write!(f, "The update operation is not allowed after boot.")
            }
        }
    }
}
