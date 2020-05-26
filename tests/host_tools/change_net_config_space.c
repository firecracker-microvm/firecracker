// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// This is used by the `test_net_config_space.py` integration test, which writes
// into the microVM configured network device config space a new MAC address.

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

int show_usage() {
    printf("Usage: ./change_net_config_space.bin [dev_addr_start] [mac_addr]\n");
    printf("Example:\n");
    printf("> ./change_net_config_space.bin 0xd00001000 0x060504030201\n");
    return 0;
}

int main(int argc, char *argv[]) {
    int fd, i, offset;
    uint8_t *map_base;
    volatile uint8_t *virt_addr;

    uint64_t mapped_size, page_size, offset_in_page, target;
    uint64_t width = 6;

    uint64_t config_offset = 0x100;
    uint64_t device_start_addr = 0x00000000;
    uint64_t mac = 0;

    if (argc != 3) {
        return show_usage();
    }

    device_start_addr = strtoull(argv[1], NULL, 0);
    mac = strtoull(argv[2], NULL, 0);

    fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0) {
        perror("Failed to open '/dev/mem'.");
        return 1;
    }

    target = device_start_addr + config_offset;
    // Get the page size.
    mapped_size = page_size = getpagesize();
    // Get the target address physical frame page offset.
    offset_in_page = (unsigned) target & (page_size - 1);
    /* If the data length goes out of the current page,
     * double the needed map size. */
    if (offset_in_page + width > page_size) {
        /* This access spans pages.
         * Must map two pages to make it possible. */
        mapped_size *= 2;
    }

    // Map the `/dev/mem` to virtual memory.
    map_base = mmap(NULL,
            mapped_size,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            fd,
            target & ~(off_t)(page_size - 1));
    if (map_base == MAP_FAILED) {
            perror("Failed to mmap '/dev/mem'.");
            return 2;
    }

    // Write in the network device config space a new MAC.
    virt_addr = (volatile uint8_t*) (map_base + offset_in_page);
    *virt_addr = (uint8_t) (mac >> 40);
    printf("%02x", *virt_addr);

    for (i = 1; i <= 5; i++) {
        *(virt_addr + i) = (uint8_t) (mac >> (5 - i) * 8);
        printf(":%02x", *(virt_addr + i));
    }

    // Deallocate resources.
    munmap(map_base, mapped_size);
    close(fd);

    return 0;
}
