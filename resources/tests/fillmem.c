// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>


#define MB (1024 * 1024)


int fill_mem(int mb_count) {
    int i, j;
    char *ptr = NULL;
    for(j = 0; j < mb_count; j++) {
        do {
            // We can't map the whole chunk of memory at once because
            // in case the system is already in a memory pressured
            // state and we are trying to achieve a process death by
            // OOM killer, a large allocation is far less likely to
            // succeed than more granular ones.
            ptr = mmap(
                NULL,
                MB * sizeof(char),
                PROT_READ | PROT_WRITE,
                MAP_ANONYMOUS | MAP_PRIVATE,
                -1,
                0
            );
        } while (ptr == MAP_FAILED);
        memset(ptr, 1, MB * sizeof(char));
    }

    return 0;
}


int main(int argc, char *const argv[]) {

    if (argc != 2) {
        printf("Usage: ./fillmem mb_count\n");
        return -1;
    }
    
    int mb_count = atoi(argv[1]);

    int pid = fork();
    if (pid == 0) {
        return fill_mem(mb_count);
    } else {
        int status;
        wait(&status);
        int fd = open("/tmp/fillmem_output.txt", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IXUSR);
        if (fd < 0) {
            return -1;
        }

        if (WIFSIGNALED(status)) {
            char buf[200];
            sprintf(buf, "OOM Killer stopped the program with signal %d, exit code %d\n", WTERMSIG(status), WEXITSTATUS(status));
            write(fd, buf, strlen(buf) + 1);
        } else {
            write(fd, "Memory filling was successful\n", 31);
        }

        close(fd);
        return 0;
    }
}
