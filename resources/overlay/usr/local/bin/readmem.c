// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// This is a balloon device helper tool, which allocates an amount of
// memory, given as the first starting parameter, and then tries to find
// 4 consecutive occurences of an integer, given as the second starting
// parameter, in that memory chunk. The program returns 1 if it succeeds
// in finding these occurences, 0 otherwise. After performing a deflate
// operation on the balloon device, we run this program with the second
// starting parameter equal to `1`, which is the value we are using to
// write in memory when dirtying it with `fillmem`. If the memory is
// indeed scrubbed, we won't be able to find any 4 consecutive occurences
// of the integer `1` in newly allocated memory.

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define MB (1024 * 1024)


int read_mem(int mb_count, int value) {
    int i;
    char *ptr = NULL;
    int *cur = NULL;
    int buf[4] = { value };

    do {
        ptr = mmap(
            NULL,
            mb_count * MB * sizeof(char),
            PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE,
            -1,
            0
        );
    } while (ptr == MAP_FAILED);
        
    cur = (int *) ptr;
    // We will go through all the memory allocated with an `int` pointer,
    // so we have to divide the amount of bytes available by the size of
    // `int`. Furthermore, we compare 4 `int`s at a time, so we will
    // divide the upper limit of the loop by 4 and also increment the index
    // by 4.
    for (i = 0; i < (mb_count * MB * sizeof(char)) / (4 * sizeof(int)); i += 4) {
        if (memcmp(cur, buf, 4 * sizeof(int)) == 0) {
            return 1;
        }
    }

    return 0;
}


int main(int argc, char *const argv[]) {

    if (argc != 3) {
        printf("Usage: ./readmem mb_count value\n");
        return -1;
    }
    
    int mb_count = atoi(argv[1]);
    int value = atoi(argv[2]);

    return read_mem(mb_count, value);
}
