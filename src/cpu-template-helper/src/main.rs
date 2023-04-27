// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::{read_to_string, write};
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use vmm::guest_config::templates::{CustomCpuTemplate, GetCpuTemplate, GetCpuTemplateError};

mod dump;
mod strip;
mod utils;
mod verify;

const EXIT_CODE_ERROR: i32 = 1;

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("Failed to operate file: {0}")]
    FileIo(#[from] std::io::Error),
    #[error("{0}")]
    DumpCpuConfig(#[from] dump::Error),
    #[error("CPU template is not specified: {0}")]
    NoCpuTemplate(#[from] GetCpuTemplateError),
    #[error("Failed to serialize/deserialize JSON file: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("{0}")]
    Utils(#[from] utils::Error),
    #[error("A modifier has not been applied as intended: {0}")]
    VerifyCpuTemplate(String),
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Dump CPU configuration in custom CPU template format.
    Dump {
        /// Path of firecracker config file.
        #[arg(short, long, value_name = "PATH")]
        config: PathBuf,
        /// Path of output file.
        #[arg(short, long, value_name = "PATH", default_value = "cpu_config.json")]
        output: PathBuf,
    },
    /// Strip items shared between multiple CPU configurations.
    Strip {
        /// List of paths of input CPU configuration files.
        #[arg(short, long, num_args = 2..)]
        paths: Vec<PathBuf>,
        /// Suffix of output files. To overwrite input files, specify an empty string ''.
        #[arg(short, long, default_value = "_stripped")]
        suffix: String,
    },
    /// Verify that the given CPU template is applied as intended.
    Verify {
        /// Path of firecracker config file specifying CPU template.
        #[arg(short, long, value_name = "PATH")]
        config: PathBuf,
    },
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Dump { config, output } => {
            let config = read_to_string(config)?;
            let (vmm, _) = utils::build_microvm_from_config(&config)?;

            let cpu_config = dump::dump(vmm)?;

            let cpu_config_json = serde_json::to_string_pretty(&cpu_config)?;
            write(output, cpu_config_json)?;
        }
        Command::Strip { paths, suffix } => {
            let mut templates = Vec::with_capacity(paths.len());
            for path in &paths {
                let template_json = read_to_string(path)?;
                let template: CustomCpuTemplate = serde_json::from_str(&template_json)?;
                templates.push(template);
            }

            let stripped_templates = strip::strip(templates);

            for (path, template) in paths.into_iter().zip(stripped_templates.into_iter()) {
                let path = utils::add_suffix(&path, &suffix);
                let template_json = serde_json::to_string_pretty(&template)?;
                write(path, template_json)?;
            }
        }
        Command::Verify { config } => {
            let config = read_to_string(config)?;
            let (vmm, vm_resources) = utils::build_microvm_from_config(&config)?;

            let cpu_template = vm_resources
                .vm_config
                .cpu_template
                .get_cpu_template()?
                .into_owned();
            let cpu_config = dump::dump(vmm)?;

            verify::verify(cpu_template, cpu_config).map_err(Error::VerifyCpuTemplate)?;
        }
    };

    Ok(())
}

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        eprintln!("Error: {}", e);
        std::process::exit(EXIT_CODE_ERROR);
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use ::utils::tempfile::TempFile;
    use vmm::utilities::mock_resources::kernel_image_path;

    use super::*;

    pub fn generate_config(kernel_image_path: &str, rootfs_path: &str) -> String {
        format!(
            r#"{{
                "boot-source": {{
                    "kernel_image_path": "{}"
                }},
                "drives": [
                    {{
                        "drive_id": "rootfs",
                        "path_on_host": "{}",
                        "is_root_device": true,
                        "is_read_only": false
                    }}
                ]
            }}"#,
            kernel_image_path, rootfs_path,
        )
    }

    fn generate_config_file(kernel_image_path: &str, rootfs_path: &str) -> TempFile {
        let config = generate_config(kernel_image_path, rootfs_path);
        let config_file = TempFile::new().unwrap();
        config_file.as_file().write_all(config.as_bytes()).unwrap();
        config_file
    }

    #[test]
    fn test_dump_command() {
        let kernel_image_path = kernel_image_path(None);
        let rootfs_file = TempFile::new().unwrap();
        let config_file =
            generate_config_file(&kernel_image_path, rootfs_file.as_path().to_str().unwrap());
        let output_file = TempFile::new().unwrap();

        let args = vec![
            "cpu-template-helper",
            "dump",
            "--config",
            config_file.as_path().to_str().unwrap(),
            "--output",
            output_file.as_path().to_str().unwrap(),
        ];
        let cli = Cli::parse_from(args);

        run(cli).unwrap();
    }

    #[cfg(target_arch = "x86_64")]
    fn build_sample_cpu_config_files() -> Vec<TempFile> {
        let files = vec![TempFile::new().unwrap(), TempFile::new().unwrap()];
        files[0]
            .as_file()
            .write_all(
                r#"{
                    "cpuid_modifiers": [
                        {
                            "leaf": "0x0",
                            "subleaf": "0x0",
                            "flags": 0,
                            "modifiers": [
                                {
                                    "register": "eax",
                                    "bitmap": "0b00000000000000000000000000000000"
                                }
                            ]
                        }
                    ],
                    "msr_modifiers": [
                        {
                            "addr": "0x0",
                            "bitmap": "0b0000000000000000000000000000000000000000000000000000000000000000"
                        }
                    ]
                }"#
                .as_bytes(),
            )
            .unwrap();
        files[1]
            .as_file()
            .write_all(
                r#"{
                    "cpuid_modifiers": [
                        {
                            "leaf": "0x0",
                            "subleaf": "0x0",
                            "flags": 0,
                            "modifiers": [
                                {
                                    "register": "eax",
                                    "bitmap": "0b00000000000000000000000000000000"
                                }
                            ]
                        }
                    ],
                    "msr_modifiers": [
                        {
                            "addr": "0x0",
                            "bitmap": "0b0000000000000000000000000000000000000000000000000000000000000000"
                        }
                    ]
                }"#
                .as_bytes(),
            )
            .unwrap();
        files
    }

    #[cfg(target_arch = "aarch64")]
    fn build_sample_cpu_config_files() -> Vec<TempFile> {
        let files = vec![TempFile::new().unwrap(), TempFile::new().unwrap()];
        files[0]
            .as_file()
            .write_all(
                r#"{
                    "reg_modifiers": [
                        {
                            "addr": "0x0",
                            "bitmap": "0b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                        }
                    ]
                }"#
                .as_bytes(),
            )
            .unwrap();
        files[1]
            .as_file()
            .write_all(
                r#"{
                    "reg_modifiers": [
                        {
                            "addr": "0x0",
                            "bitmap": "0b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                        }
                    ]
                }"#
                .as_bytes(),
            )
            .unwrap();
        files
    }

    #[test]
    fn test_strip_command() {
        let files = build_sample_cpu_config_files();

        let mut args = vec!["cpu-template-helper", "strip", "-p"];
        let paths = files
            .iter()
            .map(|file| file.as_path().to_str().unwrap())
            .collect::<Vec<_>>();
        args.extend(paths);
        let cli = Cli::parse_from(args);

        run(cli).unwrap();
    }
}
