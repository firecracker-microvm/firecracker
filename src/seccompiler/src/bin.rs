// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use seccompiler::{CompilationError, compile_bpf};

const DEFAULT_OUTPUT_FILENAME: &str = "seccomp_binary_filter.out";

#[derive(Debug, Parser)]
#[command(version = format!("v{}", env!("CARGO_PKG_VERSION")))]
struct Cli {
    #[arg(
        short,
        long,
        help = "The computer architecture where the BPF program runs. Supported architectures: \
                x86_64, aarch64."
    )]
    target_arch: String,
    #[arg(short, long, help = "File path of the JSON input.")]
    input_file: String,
    #[arg(short, long, help = "Optional path of the output file.", default_value = DEFAULT_OUTPUT_FILENAME)]
    output_file: String,
    #[arg(
        short,
        long,
        help = "Deprecated! Transforms the filters into basic filters. Drops all argument checks \
                and rule-level actions. Not recommended."
    )]
    basic: bool,
}

fn main() -> Result<(), CompilationError> {
    let cli = Cli::parse();
    compile_bpf(
        &cli.input_file,
        &cli.target_arch,
        &cli.output_file,
        cli.basic,
    )
}
