// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define SYSGENID_DEV_PATH		"/dev/sysgenid"
#define SYSGENID_IOCTL			0xE4
#define SYSGENID_TRIGGER_GEN_UPDATE	_IO(SYSGENID_IOCTL, 3)

int open_sysgenid(mode_t mode)
{
	int fd = open(SYSGENID_DEV_PATH, mode);
	if (fd == -1) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	return fd;
}

void read_and_write_sysgenid(int fd)
{
	uint32_t gen;
	ssize_t bytes;

	/* Get a new SysGenID */
	bytes = read(fd, &gen, sizeof(gen));
	if (bytes == -1) {
		perror("read");
		exit(EXIT_FAILURE);
	} else if (bytes < sizeof(gen)) {
		fprintf(
			stderr,
			"Partial read not expected: %zd bytes read\n",
			bytes
		);
		exit(EXIT_FAILURE);
	}
	printf("SysGenID: %u\n", gen);
	fflush(stdout);

	/* Ack the new SysGenID */
	bytes = write(fd, &gen, sizeof(gen));
	if (bytes == -1) {
		perror("write");
		exit(EXIT_FAILURE);
	} else if (bytes < sizeof(gen)) {
		fprintf(
			stderr,
			"Partial write not expected: %zd bytes written\n",
			bytes
		);
		exit(EXIT_FAILURE);
	}
}

void blocking_read_sysgenid(void)
{
	/* Open in blocking mode */
	int fd = open_sysgenid(O_RDWR);

	for (;;) {
		/* read() blocks until SysGenID is bumped */
		read_and_write_sysgenid(fd);
	}
}

void poll_and_nonblocking_read_sysgenid(void)
{
	/* Open in non-blocking mode */
	int fd = open_sysgenid(O_RDWR | O_NONBLOCK);
	struct pollfd pfd = {
		.fd = fd,
		.events = POLLIN,
	};

	for (;;) {
		/* poll() blocks until SysGenID is bumped */
		int ret = poll(&pfd, 1, -1);
		if (ret == -1) {
			perror("poll");
			exit(EXIT_FAILURE);
		} else if (ret == 0) {
			fprintf(stderr, "poll() timed out unexpectedly\n");
			exit(EXIT_FAILURE);
		}

		/* read() should not fail with EAGAIN */
		read_and_write_sysgenid(fd);
	}
}

void mmap_sysgenid(void)
{
	uint32_t last_gen = (uint32_t)-1;
	int fd = open_sysgenid(O_RDWR);
	void *p = mmap(NULL, sizeof(uint32_t), PROT_READ, MAP_SHARED, fd, 0);

	for (;;) {
		uint32_t gen = *(volatile uint32_t *)p;
		if (gen != last_gen) {
			printf("SysGenID: %u\n", gen);
			fflush(stdout);
			last_gen = gen;
		}
	}
}

void bump_sysgenid(void)
{
	int fd = open_sysgenid(O_RDWR);

	if (ioctl(fd, SYSGENID_TRIGGER_GEN_UPDATE, 0UL) == -1) {
		perror("ioctl");
		exit(EXIT_FAILURE);
	}

	close(fd);
}

void print_help_message(void)
{
	fprintf(stderr, "Usage: sysgenid <MODE>\n");
	fprintf(stderr, "Available modes:\n");
	fprintf(stderr, "   -r\tRead SysGenID via blocking read()\n");
	fprintf(stderr, "   -p\tRead SysGenID via poll() / non-blocking read()\n");
	fprintf(stderr, "   -m\tRead SysGenID via mmap()\n");
	fprintf(stderr, "   -b\tBump SysGenID\n");
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		print_help_message();
		exit(EXIT_FAILURE);
	}

	if (!strncmp(argv[1], "-r", 2))
		blocking_read_sysgenid();
	else if (!strncmp(argv[1], "-p", 2))
		poll_and_nonblocking_read_sysgenid();
	else if (!strncmp(argv[1], "-m", 2))
		mmap_sysgenid();
	else if (!strncmp(argv[1], "-b", 2))
		bump_sysgenid();
	else {
		print_help_message();
		exit(EXIT_FAILURE);
	}

	return 0;
}
