// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::{read_to_string, write};
use std::path::PathBuf;

use clap::{Parser, Subcommand};

mod dump;

const EXIT_CODE_ERROR: i32 = 1;

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("Failed to operate file: {0}")]
    FileIo(#[from] std::io::Error),
    #[error("Failed to dump CPU configuration: {0}")]
    DumpCpuConfig(#[from] dump::Error),
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
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Dump { config, output } => {
            let config = read_to_string(config)?;
            let dump_result = dump::dump(config)?;
            write(output, dump_result)?;
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
