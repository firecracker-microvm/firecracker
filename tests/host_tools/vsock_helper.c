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
#include <sys/un.h>
#include <linux/vm_sockets.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>


#define BUF_SIZE (16 * 1024)
#define SERVER_ACCEPT_BACKLOG 128


int print_usage() {
    fprintf(stderr, "Usage: ./vsock-helper <command> <args>\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "  echo <cid> <port>\n");
    fprintf(stderr, "      Connect to echo server at CID:port. Pipe STDIN to server,\n");
    fprintf(stderr, "      server response to STDOUT.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  ping <cid> <port> <count> <delay>\n");
    fprintf(stderr, "      Send <count> ping messages to echo server at CID:port.\n");
    fprintf(stderr, "      <delay> is the delay in seconds between pings (float).\n");
    fprintf(stderr, "      Prints RTT for each ping in microseconds.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  ping-uds <uds_path> <port> <count> <delay>\n");
    fprintf(stderr, "      Send <count> ping messages to echo server at <uds_path>:port.\n");
    fprintf(stderr, "      Uses Unix Domain Socket with Firecracker CONNECT protocol.\n");
    fprintf(stderr, "      <delay> is the delay in seconds between pings (float).\n");
    fprintf(stderr, "      Prints RTT for each ping in microseconds.\n");
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


int run_ping(uint32_t cid, uint32_t port, int count, double delay_sec) {

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
        close(sock);
        return -1;
    }

    char ping_msg[64];
    memset(ping_msg, 'A', sizeof(ping_msg));

    struct timespec delay_ts;
    delay_ts.tv_sec = (time_t)delay_sec;
    delay_ts.tv_nsec = (long)((delay_sec - (time_t)delay_sec) * 1000000000);

    for (int seq = 1; seq <= count; seq++) {
        struct timespec start, end;

        if (clock_gettime(CLOCK_MONOTONIC, &start) < 0) {
            perror("clock_gettime(start)");
            close(sock);
            return -1;
        }

        ssize_t sent = write(sock, ping_msg, sizeof(ping_msg));
        if (sent != sizeof(ping_msg)) {
            perror("write()");
            close(sock);
            return -1;
        }

        char pong_buf[64];
        size_t total_received = 0;
        while (total_received < sizeof(ping_msg)) {
            ssize_t received = read(sock, pong_buf + total_received,
                                    sizeof(ping_msg) - total_received);
            if (received <= 0) {
                perror("read()");
                close(sock);
                return -1;
            }
            total_received += received;
        }

        if (clock_gettime(CLOCK_MONOTONIC, &end) < 0) {
            perror("clock_gettime(end)");
            close(sock);
            return -1;
        }

        long long start_us = start.tv_sec * 1000000LL + start.tv_nsec / 1000;
        long long end_us = end.tv_sec * 1000000LL + end.tv_nsec / 1000;
        long long rtt_us = end_us - start_us;

        printf("rtt=%.3f us seq=%d\n", (double)rtt_us, seq);
        fflush(stdout);

        if (seq < count && delay_sec > 0) {
            nanosleep(&delay_ts, NULL);
        }
    }

    close(sock);
    return 0;
}


int run_ping_uds(const char *uds_path, uint32_t port, int count, double delay_sec) {

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket()");
        return -1;
    }

    struct sockaddr_un unix_addr;
    memset(&unix_addr, 0, sizeof(unix_addr));
    unix_addr.sun_family = AF_UNIX;
    strncpy(unix_addr.sun_path, uds_path, sizeof(unix_addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr*)&unix_addr, sizeof(unix_addr)) < 0) {
        perror("connect()");
        close(sock);
        return -1;
    }

    char connect_msg[64];
    int connect_len = snprintf(connect_msg, sizeof(connect_msg), "CONNECT %u\n", port);
    if (connect_len < 0 || connect_len >= sizeof(connect_msg)) {
        fprintf(stderr, "Error formatting CONNECT message\n");
        close(sock);
        return -1;
    }

    ssize_t sent = write(sock, connect_msg, connect_len);
    if (sent != connect_len) {
        perror("write(CONNECT)");
        close(sock);
        return -1;
    }

    char ack_buf[32];
    ssize_t ack_received = read(sock, ack_buf, sizeof(ack_buf) - 1);
    if (ack_received <= 0) {
        perror("read(ack)");
        close(sock);
        return -1;
    }
    ack_buf[ack_received] = '\0';

    if (strncmp(ack_buf, "OK ", 3) != 0) {
        fprintf(stderr, "Invalid acknowledgment: %s\n", ack_buf);
        close(sock);
        return -1;
    }

    char ping_msg[64];
    memset(ping_msg, 'A', sizeof(ping_msg));

    struct timespec delay_ts;
    delay_ts.tv_sec = (time_t)delay_sec;
    delay_ts.tv_nsec = (long)((delay_sec - (time_t)delay_sec) * 1000000000);

    for (int seq = 1; seq <= count; seq++) {
        struct timespec start, end;

        if (clock_gettime(CLOCK_MONOTONIC, &start) < 0) {
            perror("clock_gettime(start)");
            close(sock);
            return -1;
        }

        sent = write(sock, ping_msg, sizeof(ping_msg));
        if (sent != sizeof(ping_msg)) {
            perror("write()");
            close(sock);
            return -1;
        }

        char pong_buf[64];
        size_t total_received = 0;
        while (total_received < sizeof(ping_msg)) {
            ssize_t received = read(sock, pong_buf + total_received,
                                    sizeof(ping_msg) - total_received);
            if (received <= 0) {
                perror("read()");
                close(sock);
                return -1;
            }
            total_received += received;
        }

        if (clock_gettime(CLOCK_MONOTONIC, &end) < 0) {
            perror("clock_gettime(end)");
            close(sock);
            return -1;
        }

        long long start_us = start.tv_sec * 1000000LL + start.tv_nsec / 1000;
        long long end_us = end.tv_sec * 1000000LL + end.tv_nsec / 1000;
        long long rtt_us = end_us - start_us;

        printf("rtt=%.3f us seq=%d\n", (double)rtt_us, seq);
        fflush(stdout);

        if (seq < count && delay_sec > 0) {
            nanosleep(&delay_ts, NULL);
        }
    }

    close(sock);
    return 0;
}


int main(int argc, char **argv) {

    if (argc < 2) {
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

    if (strcmp(argv[1], "ping") == 0) {
        if (argc != 6) {
            return print_usage();
        }
        uint32_t cid = atoi(argv[2]);
        uint32_t port = atoi(argv[3]);
        int count = atoi(argv[4]);
        double delay = atof(argv[5]);

        if (!cid || !port || count <= 0 || delay < 0) {
            return print_usage();
        }
        return run_ping(cid, port, count, delay);
    }

    if (strcmp(argv[1], "ping-uds") == 0) {
        if (argc != 6) {
            return print_usage();
        }
        const char *uds_path = argv[2];
        uint32_t port = atoi(argv[3]);
        int count = atoi(argv[4]);
        double delay = atof(argv[5]);

        if (!port || count <= 0 || delay < 0) {
            return print_usage();
        }
        return run_ping_uds(uds_path, port, count, delay);
    }

    return print_usage();
}
