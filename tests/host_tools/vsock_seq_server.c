// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/vm_sockets.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <pthread.h>
#include <signal.h>

#define BUF_SIZE 16384

volatile sig_atomic_t running = 1;
volatile int listener_sockfd;

void log_info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stdout, "[INFO]  ");
    vfprintf(stdout, fmt, args);
    fprintf(stdout, "\n");
    va_end(args);
    fflush(stdout);
}

void log_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "[ERROR] ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

int print_usage() {
    fprintf(stderr, "Usage: ./vsock_seq_server serve <port> [af_vsock|af_unix] [path]\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  serve          start a SEQPACKET echo server on :port.\n");
    fprintf(stderr, "                 Data received from the client is echoed back.\n");
    fprintf(stderr, "  af_vsock|af_unix  socket family to use (default: af_vsock)\n");
    fprintf(stderr, "  path           socket path for af_unix (optional; omit for no address)\n");
    fprintf(stderr, "\n");
    return -1;
}

void *handle_conn(void *connfd_ptr) {
    int connfd = *(int *)(connfd_ptr);
    free(connfd_ptr);
    char buf[BUF_SIZE];
    ssize_t n;

    // echo back whatever you received into the connection again
    while ((n = recv(connfd, buf, sizeof(buf), 0)) > 0) {
        log_info("received %zd bytes", n);

        if (send(connfd, buf, n, 0) < 0) {
            log_error("send: %s", strerror(errno));
            break;
        }
    }

    if (n == 0) {
        log_info("connection closed by peer");
    }
    else if (n < 0) {
        log_error("recv: %s (errno=%d)", strerror(errno), errno);
    }

    close(connfd);
    return NULL;
}

int run_seq_server(int port, int family, const char *path)
{
    int sockfd, connfd;

    sockfd = socket(family, SOCK_SEQPACKET, 0);
    if (sockfd < 0) {
        log_error("socket: %s", strerror(errno));
        exit(1);
    }

    listener_sockfd = sockfd;

    if (family == AF_VSOCK) {
        struct sockaddr_vm addr;
        memset(&addr, 0, sizeof(addr));
        addr.svm_family = AF_VSOCK;
        addr.svm_port = port;
        addr.svm_cid = VMADDR_CID_ANY;

        if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            log_error("bind: %s", strerror(errno));
            close(sockfd);
            exit(1);
        }
    } else if (family == AF_UNIX && path != NULL) {
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

        if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            log_error("bind: %s", strerror(errno));
            close(sockfd);
            exit(1);
        }
    }

    if (listen(sockfd, 5) < 0) {
        log_error("listen: %s", strerror(errno));
        close(sockfd);
        exit(1);
    }

    log_info("SEQPACKET server listening on port %d (family=%s%s%s)",
             port,
             family == AF_VSOCK ? "af_vsock" : "af_unix",
             path ? " path=" : "",
             path ? path : "");

    while (running) {
        connfd = accept(sockfd, NULL, NULL);
        if (connfd < 0) {
            if (errno == EINTR) break;  // accept interrupted by signal
            log_error("accept: %s", strerror(errno));
            exit(1);
        }

        log_info("connection accepted (fd=%d)", connfd);

        int *connfd_ptr = malloc(sizeof(int));
        *connfd_ptr = connfd;

        pthread_t tid;
        pthread_create(&tid, NULL, handle_conn, connfd_ptr);
        pthread_detach(tid);
    };

    close(sockfd);
    return 0;
}

void stop_server_loop(int sig) {
    running = 0;
    close(listener_sockfd);
}

int main(int argc, char **argv) {
    signal(SIGTERM, stop_server_loop);
    signal(SIGINT, stop_server_loop);

    if (argc < 2) {
        return print_usage();
    }

    if (strcmp(argv[1], "serve") == 0) {
        if (argc < 3) {
            return print_usage();
        }

        int port = atoi(argv[2]);
        if (!port) {
            return print_usage();
        }

        int family = AF_VSOCK;
        const char *path = NULL;

        if (argc >= 4) {
            if (strcmp(argv[3], "af_unix") == 0) {
                family = AF_UNIX;
            } else if (strcmp(argv[3], "af_vsock") == 0) {
                family = AF_VSOCK;
            } else {
                return print_usage();
            }
        }

        if (argc >= 5) {
            path = argv[4];
        }

        return run_seq_server(port, family, path);
    }

    return print_usage();
}
