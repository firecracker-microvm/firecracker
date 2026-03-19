// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Minimal /dev/mem read/write tool for integration tests.
//
// Usage:
//   devmem read  <addr> <width>
//   devmem write <addr> <width> <value>
//
// <addr>:  physical address (hex or decimal)
// <width>: access width in bytes (1, 2, or 4)
// <value>: value to write (hex or decimal, write only)
//
// On read, prints the value as a hex number to stdout.
// On write, writes the value then reads back and prints it.
// Exit code 0 on success, non-zero on failure.

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr,
                "Usage: %s read  <addr> <width>\n"
                "       %s write <addr> <width> <value>\n",
                argv[0], argv[0]);
        return 1;
    }

    int is_write = strcmp(argv[1], "write") == 0;
    if (is_write && argc < 5) {
        fprintf(stderr, "write mode requires a value argument\n");
        return 1;
    }

    uint64_t addr = strtoull(argv[2], NULL, 0);
    int width = atoi(argv[3]);
    uint64_t value = is_write ? strtoull(argv[4], NULL, 0) : 0;

    if (width != 1 && width != 2 && width != 4) {
        fprintf(stderr, "width must be 1, 2, or 4\n");
        return 1;
    }

    int fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0) {
        perror("open /dev/mem");
        return 1;
    }

    uint64_t page_size = getpagesize();
    uint64_t page_addr = addr & ~(page_size - 1);
    uint64_t offset_in_page = addr & (page_size - 1);
    uint64_t map_size = page_size;
    if (offset_in_page + width > page_size)
        map_size *= 2;

    void *map = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                     fd, page_addr);
    if (map == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }

    volatile void *ptr = (volatile char *)map + offset_in_page;

    if (is_write) {
        switch (width) {
        case 1: *(volatile uint8_t *)ptr  = (uint8_t)value;  break;
        case 2: *(volatile uint16_t *)ptr = (uint16_t)value; break;
        case 4: *(volatile uint32_t *)ptr = (uint32_t)value; break;
        }
    }

    uint32_t result = 0;
    switch (width) {
    case 1: result = *(volatile uint8_t *)ptr;  break;
    case 2: result = *(volatile uint16_t *)ptr; break;
    case 4: result = *(volatile uint32_t *)ptr; break;
    }

    printf("0x%x\n", result);

    munmap(map, map_size);
    close(fd);
    return 0;
}
