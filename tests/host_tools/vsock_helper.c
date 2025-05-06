// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// This is a vsock helper tool, used by the Firecracker integration tests,
// to - well - test the virtio vsock device. It can be used to
// run a vsock echo client, that reads data from STDIN, sends it to an
// echo server, then forwards the server's reply to STDOUT.

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <linux/vm_sockets.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>


#define BUF_SIZE (16 * 1024)
#define SERVER_ACCEPT_BACKLOG 128


int print_usage() {
    fprintf(stderr, "Usage: ./vsock-helper echo <cid> <port>\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  echo          connect to an echo server, listening on CID:port.\n");
    fprintf(stderr, "                STDIN will be piped through to the echo server, and\n");
    fprintf(stderr, "                data coming from the server will pe sent to STDOUT.\n");
    fprintf(stderr, "\n");
    return -1;
}

int xfer(int src_fd, int dst_fd) {
    char buf[BUF_SIZE];
    int count =  read(src_fd, buf, sizeof(buf));

    if (!count) return 0;
    if (count < 0) return -1;

    int offset = 0;
    do {
        int written;
        written = write(dst_fd, &buf[offset], count - offset);
        if (written <= 0) return -1;
        offset += written;
    } while (offset < count);

    return offset;
}


int run_echo(uint32_t cid, uint32_t port) {

    int sock = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket()");
        return -1;
    }

    struct sockaddr_vm vsock_addr = {
        .svm_family = AF_VSOCK,
        .svm_port = port,
        .svm_cid = cid
    };
    if (connect(sock, (struct sockaddr*)&vsock_addr, sizeof(vsock_addr)) < 0) {
        perror("connect()");
        return -1;
    }

    for (;;) {
        int ping_cnt = xfer(STDIN_FILENO, sock);
        if (!ping_cnt) break;
        if (ping_cnt < 0) return -1;

        int pong_cnt = 0;
        while (pong_cnt < ping_cnt) {
            int res = xfer(sock, STDOUT_FILENO);
            if (res <= 0) return -1;
            pong_cnt += res;
        }
    }

    return close(sock);
}


int main(int argc, char **argv) {

    if (argc < 3) {
        return print_usage();
    }

    if (strcmp(argv[1], "echo") == 0) {
        if (argc != 4) {
            return print_usage();
        }
        uint32_t cid = atoi(argv[2]);
        uint32_t port = atoi(argv[3]);
        if (!cid || !port) {
            return print_usage();
        }
        return run_echo(cid, port);
    }

    return print_usage();
}
