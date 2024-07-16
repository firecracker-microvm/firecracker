#!/bin/sh

# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# We avoid checks which require building firecracker due to the issues this introduces when
# attempting to interact with the repository from an enviroment in which you cannot build
# firecracker.

# This will only fail when a staged file does not contain an appropriate license
# when formatting is incorrect this will automaticalt rectify it.

# Exit immediately when encountering a non-zero command
set -e

# Audit code base
cargo audit
# For every staged file
for i in $(git diff --name-only --cached --diff-filter=d); do
    echo $i
    # Get the extension
    filename=$(basename -- "$i")
    extension="${filename##*.}"
    if [ "$extension" = "rs" ]; then
        # Read rustfmt config, replace '\n' with ','
        rustfmt_config="$(paste -sd, ./tests/fmt.toml)"
        # We first do a check run, this will fail when it finds a non-matching license.
        rustfmt $i --check --config $rustfmt_config
        # Run `cargo fmt` for this file
        rustfmt $i --config $rustfmt_config
    fi
    if [ "$extension" = "py" ]; then
        # Apply formatters for this file
        black $i
        isort $i
    fi
    if [ "$extension" = "md" ]; then
        mdformat $i
    fi
    # Add changes to this file (as a result of formatting) to the commit.
    git add $i
done

# Check if git-secrets is present.
if command -v git-secrets >/dev/null 2>&1; then
    # Ensure the AWS patterns are registered.
    git-secrets --register-aws
    # Scan for and report secrets.
    git-secrets --scan
else
    echo "WARNING: git-secrets is not on PATH. Automated secrets scanning could not be performed."
fi
