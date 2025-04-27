// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Helper program for triggering fast page faults after UFFD snapshot restore.
// Allocates a 128M memory area using mmap, touches every page in it using memset and then
// calls `sigwait` to wait for a SIGUSR1 signal. Upon receiving this signal,
// set the entire memory area to 1, to trigger fast page fault.
// The idea is that an integration test takes a snapshot while the process is
// waiting for the SIGUSR1 signal, and then sends the signal after restoring.
// This way, the `memset` will trigger a fast page fault for every page in
// the memory region.

#include <stdio.h>    // perror, fopen, fprintf
#include <signal.h>   // sigwait and friends
#include <string.h>   // memset
#include <sys/mman.h> // mmap
#include <time.h>     // clock_gettime
#include <fcntl.h>    // open

#define MEM_SIZE_MIB (128 * 1024 * 1024)
#define NANOS_PER_SEC 1000000000
#define PAGE_SIZE 4096

void touch_memory(void *mem, size_t size, char val) {
    void *end = mem + size;
    for (; mem < end; mem += PAGE_SIZE) {
        *((char *)mem) = val;
    }
}

int main() {
    sigset_t set;
    int signal;
    void *ptr;
    struct timespec start, end;
    long duration_nanos;
    FILE *out_file;

    sigemptyset(&set);
    if (sigaddset(&set, SIGUSR1) == -1) {
        perror("sigaddset");
        return 1;
    }
    if (sigprocmask(SIG_BLOCK, &set, NULL) == -1)  {
        perror("sigprocmask");
        return 1;
    }

    ptr = mmap(NULL, MEM_SIZE_MIB, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    if (MAP_FAILED == ptr) {
        perror("mmap");
        return 1;
    }

    touch_memory(ptr, MEM_SIZE_MIB, 1);

    sigwait(&set, &signal);

    clock_gettime(CLOCK_BOOTTIME, &start);
    touch_memory(ptr, MEM_SIZE_MIB, 2);
    clock_gettime(CLOCK_BOOTTIME, &end);

    duration_nanos = (end.tv_sec - start.tv_sec) * NANOS_PER_SEC + end.tv_nsec - start.tv_nsec;

    out_file = fopen("/tmp/fast_page_fault_helper.out", "w");
    if (out_file == NULL) {
        perror("fopen");
        return 1;
    }

    fprintf(out_file, "%ld", duration_nanos);
    if (fclose(out_file)) {
        perror("fclose");
        return 1;
    }

    return 0;
}