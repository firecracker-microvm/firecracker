// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/*
 * This is a very simple tool, used by the testing system to clone/exec into
 * the jailer.
 * All it does is
 * - clone() into a new PID namespace, then
 * - have the child process exec() into the binary received via command line,
 *   and
 * - have the parent process print the child PID to stdout.
 *
 * Usage: ./newpid_cloner <binary_to_execute> <arg1> <arg2> ...
 * Example: ./newpid_cloner /bin/firecracker --api-sock /var/run/fire.sock
 *
 */

#define _GNU_SOURCE

#include <sched.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>


#define CHILD_STACK_SIZE 4096


int child_main(void *arg) {
    char **argv = (char**)arg;
    execv(argv[0], argv);
}

int main(int argc, char *const argv[]) {

    char child_stack[CHILD_STACK_SIZE];
    int child_pid = child_pid = clone(
        child_main,
        (char*)child_stack + CHILD_STACK_SIZE,
        CLONE_NEWPID,
        ((char **)argv) + 1
    );

    printf("%d", child_pid);
    return (child_pid != -1) ? 0 : errno;
}
