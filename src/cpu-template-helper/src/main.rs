// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::{Parser, Subcommand};

const EXIT_CODE_ERROR: i32 = 1;

#[derive(Debug, thiserror::Error)]
enum Error {}

type Result<T> = std::result::Result<T, Error>;

#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {}

// TODO: remove the following allowance of clippy warnings.
#[allow(unreachable_code)]
fn run(cli: Cli) -> Result<()> {
    match cli.command {};

    Ok(())
}

// TODO: remove the following allowance of clippy warnings.
#[allow(unused_variables, unreachable_code)]
fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        eprintln!("Error: {}", e);
        std::process::exit(EXIT_CODE_ERROR);
    }
}
