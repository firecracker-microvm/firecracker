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
        ptr = NULL;
        while (ptr == NULL) {
            // We can't map the whole chunk of memory at once because
            // on aarch64 when we try to allocate a large amount of
            // memory to OOM the system, it often results in the
            // process getting killed by a SIGSEGV instead of the
            // expected SIGKILL.
            ptr = mmap(
                NULL,
                MB * sizeof(char),
                PROT_READ | PROT_WRITE,
                MAP_ANONYMOUS | MAP_PRIVATE,
                -1,
                0
            );
        }
        memset(ptr, 1, MB * sizeof(char));
    }
}


int main(int argc, char *const argv[]) {

    if (argc != 2) {
        printf("Usage: ./fillmem mb_count\n");
        return -1;
    }
    
    int mb_count = atoi(argv[1]);

    int pid = fork();
    if (pid == 0) {
        fill_mem(mb_count);
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
            close(fd);

            return 0;
        }

        write(fd, "Memory filling was successful\n", 31);
        return 0;
    }

    return -2;
}
