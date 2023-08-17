// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::{Parser, Subcommand};

#[cfg(target_arch = "aarch64")]
mod edit_vmstate;
mod info;
mod utils;

#[cfg(target_arch = "aarch64")]
use edit_vmstate::{edit_vmstate_command, EditVmStateError, EditVmStateSubCommand};
use info::{info_vmstate_command, InfoVmStateError, InfoVmStateSubCommand};

#[derive(Debug, thiserror::Error)]
enum SnapEditorError {
    #[cfg(target_arch = "aarch64")]
    #[error("Error during editing vmstate file: {0}")]
    EditVmState(#[from] EditVmStateError),
    #[error("Error during getting info from a vmstate file: {0}")]
    InfoVmState(#[from] InfoVmStateError),
}

#[derive(Debug, Parser)]
#[command(version = format!("v{}", env!("FIRECRACKER_VERSION")))]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[cfg(target_arch = "aarch64")]
    #[command(subcommand)]
    EditVmstate(EditVmStateSubCommand),
    #[command(subcommand)]
    InfoVmstate(InfoVmStateSubCommand),
}

fn main_exec() -> Result<(), SnapEditorError> {
    let cli = Cli::parse();

    match cli.command {
        #[cfg(target_arch = "aarch64")]
        Command::EditVmstate(command) => edit_vmstate_command(command)?,
        Command::InfoVmstate(command) => info_vmstate_command(command)?,
    }

    Ok(())
}

fn main() -> Result<(), SnapEditorError> {
    let result = main_exec();
    if let Err(e) = result {
        eprintln!("{}", e);
        Err(e)
    } else {
        Ok(())
    }
}
