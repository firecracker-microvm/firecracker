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

#include <stdio.h>    // perror
#include <signal.h>   // sigwait and friends
#include <string.h>   // memset
#include <sys/mman.h> // mmap

#define MEM_SIZE_MIB (128 * 1024 * 1024)

int main(int argc, char *const argv[]) {
    sigset_t set;
    int signal;
    void *ptr;

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

    memset(ptr, 1, MEM_SIZE_MIB);

    sigwait(&set, &signal);

    memset(ptr, 2, MEM_SIZE_MIB);

    return 0;
}