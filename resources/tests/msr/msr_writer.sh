#!/usr/bin/env bash

# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Helper script used to write MSR values from a text file

set -eu

input_file=$1

if [ -z "${input_file}" ] ; then
    >&2 echo "Usage: ${0} <input_file>"
    exit 1
fi

if [ ! -f "${input_file}" ] ; then
    >&2 echo "File ${input_file} does not exist"
    exit 1
fi

while read -r reg val ; do
    wrmsr ${reg} ${val}
done < ${input_file}
