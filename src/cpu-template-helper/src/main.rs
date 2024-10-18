// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::{read_to_string, write};
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use vmm::cpu_config::templates::{GetCpuTemplate, GetCpuTemplateError};

mod fingerprint;
mod template;
mod utils;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
enum HelperError {
    /// Failed to operate file: {0}
    FileIo(#[from] std::io::Error),
    /// {0}
    FingerprintCompare(#[from] fingerprint::compare::FingerprintCompareError),
    /// {0}
    FingerprintDump(#[from] fingerprint::dump::FingerprintDumpError),
    /// CPU template is not specified: {0}
    NoCpuTemplate(#[from] GetCpuTemplateError),
    /// Failed to serialize/deserialize JSON file: {0}
    Serde(#[from] serde_json::Error),
    /// {0}
    Utils(#[from] utils::UtilsError),
    /// {0}
    TemplateDump(#[from] template::dump::DumpError),
    /// {0}
    TemplateStrip(#[from] template::strip::StripError),
    /// {0}
    TemplateVerify(#[from] template::verify::VerifyError),
}

#[derive(Debug, Parser)]
#[command(version = format!("v{}", crate::utils::CPU_TEMPLATE_HELPER_VERSION))]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Template-related operations
    #[command(subcommand)]
    Template(TemplateOperation),
    /// Fingerprint-related operations
    #[command(subcommand)]
    Fingerprint(FingerprintOperation),
}

#[derive(Debug, Subcommand)]
enum TemplateOperation {
    /// Dump guest CPU configuration in the custom CPU template format.
    Dump {
        /// Path of firecracker config file.
        #[arg(short, long, value_name = "PATH")]
        config: Option<PathBuf>,
        /// Path of CPU template to apply.
        #[arg(short, long, value_name = "PATH")]
        template: Option<PathBuf>,
        /// Path of output file.
        #[arg(short, long, value_name = "PATH", default_value = "cpu_config.json")]
        output: PathBuf,
    },
    /// Strip entries shared between multiple CPU template files.
    Strip {
        /// List of paths of input CPU configuration files.
        #[arg(short, long, value_name = "PATH", num_args = 2..)]
        paths: Vec<PathBuf>,
        /// Suffix of output files. To overwrite input files, specify an empty string ''.
        #[arg(short, long, default_value = "_stripped")]
        suffix: String,
    },
    /// Verify that the given CPU template file is applied as intended.
    Verify {
        /// Path of firecracker config file.
        #[arg(short, long, value_name = "PATH")]
        config: Option<PathBuf>,
        /// Path of the target CPU template.
        #[arg(short, long, value_name = "PATH")]
        template: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum FingerprintOperation {
    /// Dump fingerprint consisting of host-related information and guest CPU config.
    Dump {
        /// Path of firecracker config file.
        #[arg(short, long, value_name = "PATH")]
        config: Option<PathBuf>,
        /// Path of CPU template to apply.
        #[arg(short, long, value_name = "PATH")]
        template: Option<PathBuf>,
        /// Path of output file.
        #[arg(short, long, value_name = "PATH", default_value = "fingerprint.json")]
        output: PathBuf,
    },
    /// Compare two fingerprint files with queries.
    Compare {
        /// Path of fingerprint file that stores the previous state at CPU template creation.
        #[arg(short, long, value_name = "PATH")]
        prev: PathBuf,
        /// Path of fingerprint file that stores the current state.
        #[arg(short, long, value_name = "PATH")]
        curr: PathBuf,
        /// List of fields to be compared.
        #[arg(
            short,
            long,
            value_enum,
            num_args = 1..,
            default_values_t = fingerprint::FingerprintField::value_variants()
        )]
        filters: Vec<fingerprint::FingerprintField>,
    },
}

fn run(cli: Cli) -> Result<(), HelperError> {
    match cli.command {
        Command::Template(op) => match op {
            TemplateOperation::Dump {
                config,
                template,
                output,
            } => {
                let config = config.map(read_to_string).transpose()?;
                let template = template
                    .as_ref()
                    .map(utils::load_cpu_template)
                    .transpose()?;
                let (vmm, _) = utils::build_microvm_from_config(config, template)?;

                let cpu_config = template::dump::dump(vmm)?;

                let cpu_config_json = serde_json::to_string_pretty(&cpu_config)?;
                write(output, cpu_config_json)?;
            }
            TemplateOperation::Strip { paths, suffix } => {
                let templates = paths
                    .iter()
                    .map(utils::load_cpu_template)
                    .collect::<Result<Vec<_>, utils::UtilsError>>()?;

                let stripped_templates = template::strip::strip(templates)?;

                for (path, template) in paths.into_iter().zip(stripped_templates.into_iter()) {
                    let path = utils::add_suffix(&path, &suffix);
                    let template_json = serde_json::to_string_pretty(&template)?;
                    write(path, template_json)?;
                }
            }
            TemplateOperation::Verify { config, template } => {
                let config = config.map(read_to_string).transpose()?;
                let template = template
                    .as_ref()
                    .map(utils::load_cpu_template)
                    .transpose()?;
                let (vmm, vm_resources) = utils::build_microvm_from_config(config, template)?;

                let cpu_template = vm_resources
                    .vm_config
                    .cpu_template
                    .get_cpu_template()?
                    .into_owned();
                let cpu_config = template::dump::dump(vmm)?;

                template::verify::verify(cpu_template, cpu_config)?;
            }
        },
        Command::Fingerprint(op) => match op {
            FingerprintOperation::Dump {
                config,
                template,
                output,
            } => {
                let config = config.map(read_to_string).transpose()?;
                let template = template
                    .as_ref()
                    .map(utils::load_cpu_template)
                    .transpose()?;
                let (vmm, _) = utils::build_microvm_from_config(config, template)?;

                let fingerprint = fingerprint::dump::dump(vmm)?;

                let fingerprint_json = serde_json::to_string_pretty(&fingerprint)?;
                write(output, fingerprint_json)?;
            }
            FingerprintOperation::Compare {
                prev,
                curr,
                filters,
            } => {
                let prev_json = read_to_string(prev)?;
                let prev = serde_json::from_str(&prev_json)?;
                let curr_json = read_to_string(curr)?;
                let curr = serde_json::from_str(&curr_json)?;
                fingerprint::compare::compare(prev, curr, filters)?;
            }
        },
    }

    Ok(())
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let result = run(cli);
    if let Err(e) = result {
        eprintln!("{}", e);
        std::process::ExitCode::FAILURE
    } else {
        std::process::ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    // Sample modifiers for x86_64 that should work correctly as a CPU template and a guest CPU
    // config.
    // * CPUID leaf 0x0 / subleaf 0x0 / register eax indicates the maximum input EAX value for basic
    //   CPUID information.
    // * MSR index 0x4b564d00 indicates MSR_KVM_WALL_CLOCK_NEW.
    #[cfg(target_arch = "x86_64")]
    const SAMPLE_MODIFIERS: &str = r#"
    {
        "cpuid_modifiers": [
            {
                "leaf": "0x0",
                "subleaf": "0x0",
                "flags": 0,
                "modifiers": [
                    {
                        "register": "eax",
                        "bitmap": "0b00000000000000000000000000000001"
                    }
                ]
            }
        ],
        "msr_modifiers": [
            {
                "addr": "0x4b564d00",
                "bitmap": "0b0000000000000000000000000000000000000000000000000000000000000001"
            }
        ]
    }"#;

    // Sample modifiers for aarch64 that should work correctly as a CPU template and a guest CPU
    // config.
    // * Register ID 0x6030000000100002 indicates X1 register.
    #[cfg(target_arch = "aarch64")]
    const SAMPLE_MODIFIERS: &str = r#"
    {
        "reg_modifiers": [
            {
                "addr": "0x6030000000100002",
                "bitmap": "0b00000001"
            }
        ]
    }"#;

    // Build a sample custom CPU template.
    fn generate_sample_template() -> TempFile {
        let file = TempFile::new().unwrap();
        file.as_file()
            .write_all(SAMPLE_MODIFIERS.as_bytes())
            .unwrap();
        file
    }

    // Build a sample fingerprint file.
    fn generate_sample_fingerprint() -> TempFile {
        let fingerprint = fingerprint::Fingerprint {
            firecracker_version: crate::utils::CPU_TEMPLATE_HELPER_VERSION.to_string(),
            kernel_version: "sample_kernel_version".to_string(),
            microcode_version: "sample_microcode_version".to_string(),
            bios_version: "sample_bios_version".to_string(),
            bios_revision: "sample_bios_revision".to_string(),
            guest_cpu_config: serde_json::from_str(SAMPLE_MODIFIERS).unwrap(),
        };
        let file = TempFile::new().unwrap();
        file.as_file()
            .write_all(
                serde_json::to_string_pretty(&fingerprint)
                    .unwrap()
                    .as_bytes(),
            )
            .unwrap();
        file
    }

    #[test]
    fn test_template_dump_command() {
        let output_file = TempFile::new().unwrap();
        let args = vec![
            "cpu-template-helper",
            "template",
            "dump",
            "--output",
            output_file.as_path().to_str().unwrap(),
        ];
        let cli = Cli::parse_from(args);

        run(cli).unwrap();
    }

    #[test]
    fn test_template_strip_command() {
        let files = [generate_sample_template(), generate_sample_template()];

        let mut args = vec!["cpu-template-helper", "template", "strip", "-p"];
        let paths = files
            .iter()
            .map(|file| file.as_path().to_str().unwrap())
            .collect::<Vec<_>>();
        args.extend(paths);
        let cli = Cli::parse_from(args);

        run(cli).unwrap();
    }

    #[test]
    fn test_template_verify_command() {
        let template_file = generate_sample_template();
        let args = vec![
            "cpu-template-helper",
            "template",
            "verify",
            "--template",
            template_file.as_path().to_str().unwrap(),
        ];
        let cli = Cli::parse_from(args);

        run(cli).unwrap();
    }

    #[test]
    fn test_fingerprint_dump_command() {
        let output_file = TempFile::new().unwrap();
        let args = vec![
            "cpu-template-helper",
            "fingerprint",
            "dump",
            "--output",
            output_file.as_path().to_str().unwrap(),
        ];
        let cli = Cli::parse_from(args);

        run(cli).unwrap();
    }

    #[test]
    fn test_fingerprint_compare_command() {
        let fingerprint_file1 = generate_sample_fingerprint();
        let fingerprint_file2 = generate_sample_fingerprint();
        let filters = fingerprint::FingerprintField::value_variants()
            .iter()
            .map(|variant| variant.to_possible_value().unwrap().get_name().to_string())
            .collect::<Vec<_>>();

        let mut args = vec![
            "cpu-template-helper",
            "fingerprint",
            "compare",
            "--prev",
            fingerprint_file1.as_path().to_str().unwrap(),
            "--curr",
            fingerprint_file2.as_path().to_str().unwrap(),
            "--filters",
        ];
        for filter in &filters {
            args.push(filter);
        }
        let cli = Cli::parse_from(args);

        run(cli).unwrap();
    }
}
