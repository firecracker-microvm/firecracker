#!/usr/bin/env bash

# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Helper script used to read MSR values from ranges known to contain MSRs.

print_msr() {
    local msr_hex=$(printf "%#x" $1)
    # Record only when the given MSR index is implemented.
    if output=$(rdmsr $msr_hex 2>> /dev/null); then
        echo "$msr_hex,0x$output"
    fi
}

# Header
echo "MSR_ADDR,VALUE"

# 0x0..0xFFF
for((msr=16#0;msr<=16#FFF;msr++))
do
    print_msr $msr
done

# 0x10000..0x10FFF
for((msr=16#10000;msr<=16#10FFF;msr++))
do
    print_msr $msr
done

# 0xC0000000..0xC0011030
for((msr=16#C0000000;msr<=16#C0011030;msr++))
do
    print_msr $msr
done

# extra MSRs we want to test for
print_msr 0x400000000
print_msr 0x2000000000
print_msr 0x4000000000
print_msr 0x8000000000
print_msr 0x1000000000000
print_msr 0x3c000000000000
print_msr 0x80000000000000
print_msr 0x40000000000000
