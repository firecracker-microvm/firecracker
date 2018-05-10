#[derive(Debug, Deserialize, PartialEq, Serialize)]
enum BootSourceType {
    LocalImage,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct LocalImage {
    pub kernel_image_path: String,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct BootSource {
    boot_source_id: String,
    source_type: BootSourceType,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_image: Option<LocalImage>,
    // drive_boot to be added later
    // network_boot to be added later
    #[serde(skip_serializing_if = "Option::is_none")]
    boot_args: Option<String>,
}

impl BootSource {
    pub fn get_kernel_image(&self) -> Option<&String> {
        if let Some(ref image) = self.local_image {
            Some(&image.kernel_image_path)
        } else {
            None
        }
    }

    pub fn get_boot_args(&self) -> Option<&String> {
        if let Some(ref args) = self.boot_args {
            Some(&args)
        } else {
            None
        }
    }
}

pub enum BootSourceError {
    InvalidKernelPath,
    InvalidKernelCommandLine,
}

pub enum PutBootSourceOutcome {
    Created,
    Updated,
    Error(BootSourceError),
}

#[cfg(test)]
mod tests {
    extern crate serde_json;

    use super::*;

    #[test]
    fn test_boot_source_getters() {
        let body = r#"{
            "boot_source_id": "/foo/bar",
            "source_type": "LocalImage",
            "local_image": { "kernel_image_path": "/foo/bar"}
        }"#;
        let result: Result<BootSource, serde_json::Error> = serde_json::from_str(body);
        assert!(result.is_ok());
        let boot_source = result.unwrap();
        assert!(boot_source.get_boot_args().is_none());
        assert_eq!(
            boot_source.get_kernel_image(),
            Some(&String::from("/foo/bar"))
        );

        let body = r#"{
            "boot_source_id": "/foo/bar",
            "source_type": "LocalImage"
                   }"#;
        let result: Result<BootSource, serde_json::Error> = serde_json::from_str(body);
        assert!(result.is_ok());
        let boot_source = result.unwrap();
        assert!(boot_source.get_kernel_image().is_none());
    }
}
