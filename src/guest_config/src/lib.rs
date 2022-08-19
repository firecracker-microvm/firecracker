// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Borrow;
use std::convert::TryFrom;
use std::ffi::OsStr;
use std::fs;
use std::fs::File;
use std::io::{BufWriter, Read};
use std::path::Path;

use cpuid::{Cpuid, CpuidNewError};
use logger::{debug, error, info, warn};

use crate::cpu::cpu_config::{
    CpuConfigurationAttribute, CustomCpuConfiguration, CustomCpuConfigurationApiRequest,
};
use crate::cpu::cpu_symbolic_engine::CPU_FEATURE_INDEX_MAP;

/// Contains types used to configure guest vCPUs.
pub mod cpu;

const JSON_FILE_FORMAT_EXTENSION: &str = "json";
const BINARY_FILE_FORMAT_EXTENSION: &str = "bin";

/// Errors associated with processing CPU configuration
#[derive(Debug, thiserror::Error)]
pub enum GuestConfigurationError {
    /// Error while configuring CPU features via CPUID
    #[error("Failed to configure CPU features via CPUID")]
    CpuId(CpuidNewError),
    /// Error while configuration model-specific registers
    #[error("Error while configuring CPU features via model-specific registers")]
    MSR,
    /// Invalid file path specified
    #[error("Invalid file path specified - {0}")]
    InvalidFilePath(String),
    /// Invalid file type provided
    #[error(
        "Invalid file type specified. Only JSON or extensionless (binary) is accepted - [{0}]"
    )]
    InvalidFileType(String),
    #[error("Invalid file format provided. Not able to deserialize guest configuration - [{0}]")]
    JsonError(serde_json::Error),
    /// Unknown/Undefined CPU feature name
    #[error("Unknown or undefined CPU feature name")]
    UndefinedCpuFeatureName,
    #[error("CPU feature override for [{0}] is not supported")]
    UnsupportedCpuFeatureOverride(String),
    /// Opening or reading the file was unsuccessful
    #[error("Unable to use file specified [{0}]. See error [{1}]")]
    IOError(String, std::io::Error),
    /// Binary file operation was unsuccessful
    #[error("Error handling binary file [{0}]. See error [{1}]")]
    BinaryFileOperationError(String, bincode::Error),
}

/// Takes a file referred to by a template path string and
/// compiles the json types referred to in the template
/// into binary objects, converting from a
/// CustomCpuConfigurationApiRequest to CustomCpuConfiguration
pub fn deserialize_configuration_file(
    template_file_path_string: &str,
) -> Result<CustomCpuConfiguration, GuestConfigurationError> {
    deserialize_configuration_str(
        fs::read_to_string(template_file_path_string)
            .expect(&format!(
                "Unable to read template file [{}]",
                template_file_path_string
            ))
            .as_str(),
    )
}

/// Take a JSON string of CustomCpuConfigurationApiRequest and
/// converts to the JSON-deserialized type, CustomCpuConfiguration
pub fn deserialize_configuration_str(
    custom_cpu_config_request_str: &str,
) -> Result<CustomCpuConfiguration, GuestConfigurationError> {
    deserialize_configuration_request(&CustomCpuConfigurationApiRequest::try_from(
        custom_cpu_config_request_str,
    )?)
}

/// Take a JSON string of CustomCpuConfigurationApiRequest and
/// converts to the JSON-deserialized type, CustomCpuConfiguration
pub fn deserialize_configuration_request(
    cpu_config_request: &CustomCpuConfigurationApiRequest,
) -> Result<CustomCpuConfiguration, GuestConfigurationError> {
    // Validate feature overrides
    let _ = validate_cpu_feature_overrides(Vec::from(
        cpu_config_request.cpu_feature_overrides.borrow(),
    ));

    // "Compile" general features template
    let compiled_gen_arch_template =
        deserialize_cpu_features_from_file(&cpu_config_request.base_arch_features_template_path)?;
    Ok(CustomCpuConfiguration {
        base_arch_features_configuration: compiled_gen_arch_template,
        cpu_feature_overrides: Vec::from(cpu_config_request.cpu_feature_overrides.borrow()),
    })

    // TODO - Validate+Compile special features template
}

pub fn write_cpu_features_binary_file(
    path: &str,
    cpuid: &Cpuid,
) -> Result<(), GuestConfigurationError> {
    let output_file = File::create(path)
        .map_err(|err| GuestConfigurationError::IOError(String::from(path), err))?;

    Ok(bincode::serialize_into(BufWriter::new(output_file), &cpuid)
        .map_err(|err| GuestConfigurationError::BinaryFileOperationError(String::from(path), err)))?
}

pub fn snapshot_local_cpu_features(target_str: &str) -> Result<Cpuid, GuestConfigurationError> {
    info!("Building CPUID configuration from local context");
    let cpuid = unsafe { Cpuid::new() }.map_err(|err| GuestConfigurationError::CpuId(err))?;

    write_cpu_features_binary_file(target_str, &cpuid)?;
    info!(
        "CPUID configuration from local context written to [{}]",
        target_str
    );
    Ok(cpuid)
}

pub fn read_cpu_features_binary_file(
    file_path_str: &str,
) -> Result<Cpuid, GuestConfigurationError> {
    let file_path = Path::new(&file_path_str);
    warn!(
        "Loading binary file for CPU configuration - [{}]",
        file_path.to_str().unwrap()
    );
    let mut cpuid_config_file = File::open(file_path)
        .map_err(|err| GuestConfigurationError::IOError(file_path_str.to_string(), err))?;

    let metadata = fs::metadata(&file_path)
        .map_err(|err| GuestConfigurationError::IOError(file_path_str.to_string(), err))?;
    let mut cpu_config_buffer = vec![0; metadata.len() as usize];
    cpuid_config_file
        .read(&mut cpu_config_buffer)
        .expect(&format!("Failed to read binary file [{}]", file_path_str));
    let cpuid_result: Result<Cpuid, bincode::Error> = bincode::deserialize(&cpu_config_buffer);

    match cpuid_result {
        Ok(cpuid) => Ok(cpuid),
        Err(err) => {
            error!("Error handling binary file: {:?}", err);
            Err(GuestConfigurationError::BinaryFileOperationError(
                String::from(file_path_str),
                err,
            ))
        }
    }
}

/// Compile the JSON string contained in the referenced file into a generic features type
pub fn deserialize_cpu_features_from_file(
    general_features_file_path_str: &str,
) -> Result<Cpuid, GuestConfigurationError> {
    let template_file_path: &Path = Path::new(general_features_file_path_str);

    if template_file_path.is_file() {
        let extension_option: Option<&str> = template_file_path.extension().and_then(OsStr::to_str);

        match extension_option {
            // Without a file extension, assume the file is a binary formatted template file,
            // and attempt to serialize the binary data into a Cpuid instance
            None => {
                warn!(
                    "No file extension found on CPUID configuration file [{}], assuming bin file",
                    general_features_file_path_str,
                );

                read_cpu_features_binary_file(general_features_file_path_str)
            }
            // A file extension exists on the file, if the file is JSON, it will need to be
            // deserialized into
            Some(file_ext) => {
                if file_ext.eq_ignore_ascii_case(JSON_FILE_FORMAT_EXTENSION) {
                    read_cpu_features_json_file(general_features_file_path_str)
                } else if file_ext.eq_ignore_ascii_case(BINARY_FILE_FORMAT_EXTENSION) {
                    read_cpu_features_binary_file(general_features_file_path_str)
                } else {
                    Err(GuestConfigurationError::InvalidFileType(
                        general_features_file_path_str.to_string(),
                    ))
                }
            }
        }
    } else {
        error!(
            "Template path [{}] is not a file",
            general_features_file_path_str
        );
        Err(GuestConfigurationError::InvalidFilePath(String::from(
            general_features_file_path_str,
        )))
    }
}

fn validate_cpu_feature_overrides(
    feature_overrides: Vec<CpuConfigurationAttribute>,
) -> Result<(), GuestConfigurationError> {
    // Validate CPU feature overrides
    for cpu_config_entry in &feature_overrides {
        if !CPU_FEATURE_INDEX_MAP.contains_key(cpu_config_entry.name.as_str()) {
            return Err(GuestConfigurationError::UndefinedCpuFeatureName);
        }
    }

    Ok(())
}

fn read_cpu_features_json_file(
    json_template_file_path: &str,
) -> Result<Cpuid, GuestConfigurationError> {
    let cpuid_json_string = fs::read_to_string(&json_template_file_path).map_err(|err| {
        GuestConfigurationError::IOError(json_template_file_path.to_string(), err)
    })?;

    debug!(
        "Deserializing JSON CPUID structure \n{}",
        &cpuid_json_string
    );
    match serde_json::from_str(&cpuid_json_string.as_str()) {
        Ok(cpuid) => {
            info!(
                "Parsed JSON file [{}] successfully",
                json_template_file_path
            );
            Ok(cpuid)
        }
        Err(err) => {
            error!("Failed to load JSON file [{}]", json_template_file_path);
            Err(GuestConfigurationError::JsonError(err))
        }
    }
}
