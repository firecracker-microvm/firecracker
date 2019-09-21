// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// This is a vsock helper tool, used by the Firecracker integration tests,
// to - well - test the virtio vsock device. It can be used to:
// 1. Run a forking echo server, that echoes back any data received from
//    a client; and
// 2. Run a vsock echo client, that reads data from STDIN, sends it to an
//    echo server, then forwards the server's reply to STDOUT.

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
    fprintf(stderr, "Usage: ./vsock-helper {echosrv [-d] <port> | echo <cid> <port>}\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  echosrv       start a vsock echo server. The server will accept\n");
    fprintf(stderr, "                any incoming connection, and echo back any data\n");
    fprintf(stderr, "                received on it.\n");
    fprintf(stderr, "                -d can be used to daemonize the server.\n");
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


int run_echosrv(uint32_t port) {

    struct sockaddr_vm vsock_addr = {
        .svm_family = AF_VSOCK,
        .svm_port = port,
        .svm_cid = VMADDR_CID_ANY
    };

    int srv_sock = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (srv_sock < 0) {
        perror("socket()");
        return -1;
    }

    int res = bind(srv_sock, (struct sockaddr*)&vsock_addr, sizeof(struct sockaddr_vm));
    if (res) {
        perror("bind()");
        return -1;
    }

    res = listen(srv_sock, SERVER_ACCEPT_BACKLOG);
    if (res) {
        perror("listen()");
        return -1;
    }

    for (;;) {
        struct sockaddr cl_addr;
        socklen_t sockaddr_len = sizeof(cl_addr);
        int cl_sock = accept(srv_sock, &cl_addr, &sockaddr_len);
        if (cl_sock < 0) {
            perror("accept()");
            continue;
        }

        int pid = fork();
        if (pid < 0) {
            perror("fork()");
            close(cl_sock);
            continue;
        }

        if (!pid) {
            int res;
            do {
                res = xfer(cl_sock, cl_sock);
            } while (res > 0);
            return res >= 0 ? 0 : -1;
        }

        close(cl_sock);
        int cstatus;
        waitpid(-1, &cstatus, WNOHANG);
        printf("New client forked...\n");
    }

	return 0;
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

    return 0;
}


int main(int argc, char **argv) {

    if (argc < 3) {
        return print_usage();
    }

    if (strcmp(argv[1], "echosrv") == 0) {
        uint32_t port;
        if (strcmp(argv[2], "-d") == 0) {
            if (argc < 4) {
                return print_usage();
            }
            port = atoi(argv[3]);
            if (!port) {
                return print_usage();
            }
            int pid = fork();
            if (pid < 0) return -1;
            if (pid) {
                printf("Forked vsock echo daemon listening on port %d\n", port);
                return 0;
            }
            setsid();
            close(STDIN_FILENO);
            close(STDOUT_FILENO);
        }
        else {
            port = atoi(argv[2]);
            if (!port) {
                return print_usage();
            }
        }
        return run_echosrv(port);
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
