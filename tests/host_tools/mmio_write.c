// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// This is a binary, used by the Firecracker integration tests,
// to test that a MMIO config space rewrite with invalid data
// (data length too small) will not update the config space.
// It can be run inside the guest and we expect to not trigger
// any panic.

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>


int main(int argc, char *argv[]) {
    int fd;
    unsigned char *p;
    int ret = 0;
    int config_start;
    int64_t config_offset = 0x00000000;
    int64_t mmio_start_address = 0x00000000;

    fd = open("/dev/mem", O_RDWR);
    if (fd < 0) {
        perror("Failed to open /dev/mem.");
        return 1;
    }

    #ifdef X86_64
        mmio_start_address = 0xD0000000;
        // The offset in MMIO space where the config space
        // for the net device starts.
        // Net device config space offset. From 0xD0000000
        // to 0xD0001000 is the MMIO space for the root device
        // (block device).
        config_offset = 0x00001100;
    #endif
    #ifdef AARCH64
        // From 0x40000000 to 0x40001000 is a space reserved
        // for the boot time.
        mmio_start_address = 0x40001000;
        // The offset in MMIO space where the config space
        // for the net device starts. It is different than
        // the one for X86, because here the first MMIO device
        // is the serial console (from 0x40000000 to 0x40001000).
        config_offset = 0x00002100;
    #endif

    p = mmap(NULL, 0x3000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, mmio_start_address);
    if (p == MAP_FAILED) {
        perror("Failed to mmap /dev/mem.");
        return 2;
    }

    // A MMIO device config space starts at the `config_offset` offset.
    config_start = p[config_offset];
    // This wil trigger a MMIO config space rewrite, but because it is
    // an invalid (partial) write, the config space should not be modified.
    p[config_offset] += 4;
    sleep(0.5);

    // Check if the MMIO config space was not updated.
    if (p[config_offset] != config_start) {
        perror("Unexpected MMIO config space update.");
        return 1;
    }

    printf("Finished.\n");
    return ret;
}
