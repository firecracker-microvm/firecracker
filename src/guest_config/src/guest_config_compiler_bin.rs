// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate core;

use std::convert::TryFrom;
use std::time::SystemTime;
use std::{fs, process};

use guest_config::cpu::cpu_config::CustomCpuConfigurationApiRequest;
use guest_config::GuestConfigurationError::JsonError;
use guest_config::{
    deserialize_configuration_request, write_cpu_features_binary_file, GuestConfigurationError,
};
use logger::{debug, info};
use utils::arg_parser::{ArgParser, Argument, Arguments as ArgumentsBag};

const GUESTCONFIG_COMPILER_FILE_NAME: &str = "guestconfig-compiler-bin";
const GUESTCONFIG_DEFAULT_OUTPUT_FILENAME: &str = "guestconfig.bin";
const GUESTCONFIG_COMPILER_VERSION: &str = env!("FIRECRACKER_VERSION");
const EXIT_CODE_ERROR: i32 = 1;

#[derive(Debug, thiserror::Error)]
enum GuestConfigCompilerError {
    /// Opening or reading the file was unsuccessful
    #[error("IO error for path specified [{0}]. See error [{1}]")]
    IOError(String, std::io::Error),
    /// Error parsing JSON
    #[error("Error processing virtualized guest's configuration. See error [{0}]")]
    TemplateConfiguration(GuestConfigurationError),
}

#[derive(Debug, PartialEq)]
struct Arguments {
    input_file: String,
    output_file: String,
}

fn build_arg_parser() -> ArgParser<'static> {
    ArgParser::new()
        .arg(
            Argument::new("input-file")
                .required(true)
                .takes_value(true)
                .help("File path of the JSON input."),
        )
        .arg(
            Argument::new("output-file")
                .required(false)
                .takes_value(true)
                .default_value(GUESTCONFIG_DEFAULT_OUTPUT_FILENAME)
                .help("Optional path of the output file."),
        )
}

fn get_argument_values(arguments: &ArgumentsBag) -> Result<Arguments, GuestConfigCompilerError> {
    Ok(Arguments {
        // Safe to unwrap - presence validated by Arguments lib
        input_file: arguments.single_value("input-file").unwrap().to_string(),
        // Safe to unwrap because it has a default value
        output_file: arguments.single_value("output-file").unwrap().to_owned(),
    })
}

fn compile(args: &Arguments) -> Result<(), GuestConfigCompilerError> {
    // Parse CustomCpuConfigurationApiRequest
    info!("Reading configuration input file [{}]", &args.input_file);
    let api_request_json = fs::read_to_string(&args.input_file)
        .map_err(|err| GuestConfigCompilerError::IOError(String::from(&args.input_file), err))?;
    debug!("Json request: \n{}", api_request_json);
    let api_request = CustomCpuConfigurationApiRequest::try_from(api_request_json.as_str())
        .map_err(|err| GuestConfigCompilerError::TemplateConfiguration(err))?;

    // Compile the binary formats of the template's configuration
    match deserialize_configuration_request(&api_request) {
        Ok(cpu_config) => {
            // Architecture general configuration
            let cpuid_config_binary_file_path = api_request
                .base_arch_features_template_path
                .replace("json", "bin");
            info!(
                "Writing CPUID configuration in binary format to [{}]",
                cpuid_config_binary_file_path
            );
            write_cpu_features_binary_file(
                cpuid_config_binary_file_path.as_str(),
                &cpu_config.base_arch_features_configuration,
            )
            .map_err(|err| GuestConfigCompilerError::TemplateConfiguration(err))?;
            // TODO Special-register configuration
            // write_binary_file(cpu_config., );

            let template_json_string =
                serde_json::to_string_pretty(&CustomCpuConfigurationApiRequest {
                    base_arch_features_template_path: cpuid_config_binary_file_path,
                    cpu_feature_overrides: api_request.cpu_feature_overrides,
                })
                .map_err(|err| GuestConfigCompilerError::TemplateConfiguration(JsonError(err)))?;

            // JSON template using binary configuration files
            let template_output_file_path: String;
            if args.output_file.is_empty() {
                // Without a specified output file path,
                // use the input file and suffix a datetime stamp to the end.

                match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                    Ok(elapsed) => {
                        template_output_file_path =
                            format!("{}-{}", args.input_file, elapsed.as_secs(),)
                    }
                    Err(err) => panic!("Critical system error retrieving clock time - [{:?}]", err),
                }
            } else {
                template_output_file_path = args.output_file.to_string();
            }

            match std::fs::write(&template_output_file_path, template_json_string) {
                Ok(_) => Ok(()),
                Err(err) => Err(GuestConfigCompilerError::IOError(
                    template_output_file_path,
                    err,
                )),
            }
        }
        Err(err) => Err(GuestConfigCompilerError::TemplateConfiguration(err)),
    }
}

fn main() {
    let mut arg_parser = build_arg_parser();

    if let Err(err) = arg_parser.parse_from_cmdline() {
        eprintln!(
            "Arguments parsing error: {} \n\nFor more information try --help.",
            err
        );
        process::exit(EXIT_CODE_ERROR);
    }

    if arg_parser.arguments().flag_present("help") {
        println!(
            "{} v{}\n",
            GUESTCONFIG_COMPILER_FILE_NAME, GUESTCONFIG_COMPILER_VERSION
        );
        println!("{}", arg_parser.formatted_help());
        return;
    }

    let args = get_argument_values(arg_parser.arguments()).unwrap_or_else(|err| {
        eprintln!("{:?} \n\nFor more information try --help.", err);
        process::exit(EXIT_CODE_ERROR);
    });

    if let Err(err) = compile(&args) {
        eprintln!("guestconfig compilation error: {:?}", err);
        process::exit(EXIT_CODE_ERROR);
    }

    println!("Template successfully compiled into: {}", args.output_file);
}

#[cfg(test)]
mod tests {
    use std::{fs, io};

    use cpuid::Cpuid;
    use guest_config::GuestConfigurationError;
    use logger::error;
    use tempfile::Builder;

    use super::{
        build_arg_parser, compile, get_argument_values, Arguments, GuestConfigCompilerError,
        GUESTCONFIG_DEFAULT_OUTPUT_FILENAME,
    };
    use crate::GUESTCONFIG_COMPILER_FILE_NAME;

    #[test]
    fn test_errors() {
        let path = "nonexistent";
        assert_eq!(
            format!(
                "{:?}",
                GuestConfigCompilerError::IOError(
                    String::from(path),
                    io::Error::from_raw_os_error(2)
                )
            ),
            r#"IOError("nonexistent", Os { code: 2, kind: NotFound, message: "No such file or directory" })"#
        );
        assert_eq!(
            format!(
                "{}",
                GuestConfigCompilerError::TemplateConfiguration(GuestConfigurationError::MSR)
            ),
            format!(
                "{}",
                "Error processing virtualized guest's configuration. See error [Error while \
                 configuring CPU features via model-specific registers]"
            )
        );
    }

    #[test]
    fn test_get_arguments() {
        let arg_parser = build_arg_parser();
        // correct arguments
        let arguments = &mut arg_parser.arguments().clone();
        arguments
            .parse(
                vec![GUESTCONFIG_COMPILER_FILE_NAME, "--input-file", "foo.txt"]
                    .into_iter()
                    .map(String::from)
                    .collect::<Vec<String>>()
                    .as_ref(),
            )
            .unwrap();
        assert_eq!(
            get_argument_values(arguments).unwrap(),
            Arguments {
                input_file: "foo.txt".to_string(),
                output_file: GUESTCONFIG_DEFAULT_OUTPUT_FILENAME.to_string(),
            }
        );

        let arguments = &mut arg_parser.arguments().clone();
        arguments
            .parse(
                vec![
                    GUESTCONFIG_COMPILER_FILE_NAME,
                    "--input-file",
                    "foo.txt",
                    "--output-file",
                    "/path.to/file.txt",
                ]
                .into_iter()
                .map(String::from)
                .collect::<Vec<String>>()
                .as_ref(),
            )
            .unwrap();
        assert_eq!(
            get_argument_values(arguments).unwrap(),
            Arguments {
                input_file: "foo.txt".to_string(),
                output_file: "/path.to/file.txt".to_string(),
            }
        );

        // missing --input-file
        let arguments = &mut arg_parser.arguments().clone();
        assert!(arguments
            .parse(
                vec![GUESTCONFIG_COMPILER_FILE_NAME]
                    .into_iter()
                    .map(String::from)
                    .collect::<Vec<String>>()
                    .as_ref(),
            )
            .is_err());
    }

    #[test]
    fn test_compilation() {
        // --input-file json malformed/empty
        {
            let in_file = Builder::new()
                .prefix("cpu-json-template-config")
                .suffix(".json")
                .tempfile()
                .unwrap();
            let args = Arguments {
                input_file: String::from(in_file.path().to_str().unwrap()),
                output_file: String::from(GUESTCONFIG_DEFAULT_OUTPUT_FILENAME),
            };

            match compile(&args).unwrap_err() {
                GuestConfigCompilerError::TemplateConfiguration(
                    GuestConfigurationError::JsonError(_),
                ) => {} // success
                err => {
                    panic!(
                        "Expected GuestConfigCompilerError::GuestConfigurationError::JsonError \
                         error. Receieved [{:?}]",
                        err
                    )
                }
            }
        }

        // test a successful compilation
        {
            // create usable cpuid object
            let cpuid_config = Cpuid::kvm_get_supported_cpuid().expect("Failed to get CPUID");
            let cpuid_file = Builder::new()
                .prefix("cpuid-config")
                .suffix(".json")
                .tempfile()
                .unwrap();
            let in_file = Builder::new()
                .prefix("cpu-json-template-config")
                .suffix(".json")
                .tempfile()
                .unwrap();
            let out_file = Builder::new()
                .prefix("cpu-bin-template-config")
                .suffix(".json")
                .tempfile()
                .unwrap();

            // Write CPUID json file
            let cpuid_path = cpuid_file.path().to_str().unwrap();
            let cpuid_json = serde_json::to_string_pretty(&cpuid_config).unwrap();
            fs::write(cpuid_path, cpuid_json).expect("Unable to write JSON test file");

            let configuration_json = get_correct_json_input(Some(cpuid_path.to_string()));
            if let Err(err) = fs::write(in_file.path(), &configuration_json) {
                panic!("Error writing test json file \n{:?}", err);
            }

            let arguments = Arguments {
                input_file: String::from(in_file.path().to_str().unwrap()),
                output_file: String::from(out_file.path().to_str().unwrap()),
            };

            // do the compilation & check for errors
            match compile(&arguments) {
                Ok(_) => {}
                Err(err) => {
                    error!(
                        "Failed to parse request, json structure as \n{}",
                        configuration_json
                    );
                    panic!("Unexpected error running compiler \n{:?}", err)
                }
            }
        }
    }

    // test helper for generating correct JSON input data
    fn get_correct_json_input(arch_features_file_path: Option<String>) -> String {
        let file_path: String;
        match arch_features_file_path {
            None => file_path = String::from("/tmp/cpuid-test.json"),
            Some(arch_file_path) => file_path = arch_file_path,
        }
        format!(
            r#"
        {{
          "base_arch_features_template_path": "{}",
          "cpu_feature_overrides": [
            {{
              "name" : "ssbd",
              "is_enabled" : false
            }},
            {{
              "name" : "ibrs",
              "is_enabled" : true
            }},
            {{
              "name" : "sse4_2",
              "is_enabled" : false
            }}
          ]
        }}
        "#,
            file_path
        )
    }
}
