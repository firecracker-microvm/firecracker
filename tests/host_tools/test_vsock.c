#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SERVER_PORT     1100

static const int msg = 1235;

int print_usage() {
    printf("Usage: ./vsock_test { client <server_cid> | server }\n");
    return -1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return print_usage();
    }

    struct sockaddr_vm vsock_addr = {
        .svm_family = AF_VSOCK,
        .svm_port = SERVER_PORT,
    };

    int vsock = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (vsock < 0) {
        perror("socket()");
        return -1;
    }

    if (strcmp(argv[1], "client") == 0) {
        if (argc < 3) {
            return print_usage();
        }

        vsock_addr.svm_cid = atoi(argv[2]);

        if (connect(vsock, (struct sockaddr*)&vsock_addr, sizeof(vsock_addr)) != 0) {
            perror("connect");
            return -1;
        }

        int val;
        // Since we're only reading an int, we assume any successful read got the
        // entire value from the other side.
        if (read(vsock, &val, sizeof(val)) < 0) {
            perror("read");
            return -1;
        }

        printf("%d\n", val);
    }
    else if (strcmp(argv[1], "server") == 0) {
        vsock_addr.svm_cid = VMADDR_CID_ANY;

        if (bind(vsock, (struct sockaddr*)&vsock_addr, sizeof(vsock_addr)) != 0) {
            perror("bind");
            return -1;
        }

        if (listen(vsock, 1) != 0) {
            perror("listen");
            return -1;
        }

        struct sockaddr_vm client_addr;
        socklen_t socklen_client = sizeof(client_addr);

        int client_vsock = accept(vsock, (struct sockaddr*)&client_addr, &socklen_client);

        if (client_vsock < 0) {
            perror("accept");
            return -1;
        }

        // Since we're only writing an int, we assume any successful write sent the
        // entire value to the other side.
        if (write(client_vsock, &msg, sizeof(int)) < 0) {
            perror("write");
            return -1;
        }
    }
    else {
        return print_usage();
    }

    return 0;
}
