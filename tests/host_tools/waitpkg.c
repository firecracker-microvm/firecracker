// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// This is a sample code to attempt to use WAITPKG (UMONITOR / UWAIT / TPAUSE
// instructions). It is used to test that attemping to use it generates #UD.

#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>

void umwait(volatile int *addr) {
    _umonitor((void *)addr);
    printf("address monitoring hardware armed\n");
    uint64_t timeout = 1000000000ULL;
    uint32_t control = 0;
    uint8_t cflag = _umwait(control, timeout);
    printf("cflag = %d\n", cflag);
}

int main() {
    int a = 0;
    umwait(&a);
    return 0;
}
