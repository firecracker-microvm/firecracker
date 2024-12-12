// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// This is used by `test_seccomp_validate.py`

#include <linux/types.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/stat.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>


void install_bpf_filter(char *bpf_file) {
    int fd = open(bpf_file, O_RDONLY);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }
    struct stat sb;
    if (fstat(fd, &sb) == -1) {
        perror("stat");
        exit(EXIT_FAILURE);
    }
    size_t size = sb.st_size;
    struct sock_filter *filterbuf = (struct sock_filter*)malloc(size);
    if (read(fd, filterbuf, size) == -1) {
        perror("read");
        exit(EXIT_FAILURE);
    }

    /* Install seccomp filter */
    size_t insn_len = size / sizeof(struct sock_filter);
    struct sock_fprog prog = {
        .len = (unsigned short)(insn_len),
        .filter = filterbuf,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl(NO_NEW_PRIVS)");
        exit(EXIT_FAILURE);
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
        perror("prctl(SECCOMP)");
        exit(EXIT_FAILURE);
    }
}


int main(int argc, char **argv) {
    /* parse arguments */
    if (argc < 3) {
        fprintf(stderr, "Usage: %s BPF_FILE ARG0..\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    char *bpf_file = argv[1];
    long syscall_id = atoi(argv[2]);
    long arg0, arg1, arg2, arg3;
    arg0 = arg1 = arg2 = arg3 = 0L;
    if (argc > 3) arg0 = atol(argv[3]);
    if (argc > 4) arg1 = atol(argv[4]);
    if (argc > 5) arg2 = atol(argv[5]);
    if (argc > 6) arg3 = atol(argv[6]);

    /* read seccomp filter from file */
    if (strcmp(bpf_file, "/dev/null") != 0) {
        install_bpf_filter(bpf_file);
    }

    long res = syscall(syscall_id, arg0, arg1, arg2, arg3);
    return EXIT_SUCCESS;
}
