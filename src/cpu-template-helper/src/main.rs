// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use clap::{Parser, Subcommand};

mod dump;

const CPU_TEMPLATE_HELPER_VERSION: &str = env!("FIRECRACKER_VERSION");

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Dump CPU configuration in custom CPU template format.
    Dump {
        /// Path of config file.
        #[arg(short, long = "config-file", value_name = "CONFIG")]
        config_file: PathBuf,

        /// Path of output file.
        #[arg(
            short,
            long = "output-file",
            value_name = "OUTPUT",
            default_value = "cpu_config.json"
        )]
        output_file: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Dump {
            config_file,
            output_file,
        } => dump::dump(config_file, output_file),
    };
}
