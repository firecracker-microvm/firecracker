// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/mount.h>

/*
 * We try to trigger ENOSYS by mapping a file into memory and then tries to
 * load the content from an offset in the file bigger than its length into a
 * register asm volatile ("ldr %0, [%1], 4" : "=r" (ret), "+r" (buf));
 */

int main()
{
	int ret, fd;
	char *buf;

	// Assume /dev is mounted
	fprintf(stderr, "open /dev/mem\n");
	fd = open("/dev/mem", O_RDWR);
	assert(fd > 0);

	buf = mmap(NULL, 65536, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0xf0000);
	assert(buf != MAP_FAILED);

	fprintf(stderr, "try to ldr\n");
	asm volatile("ldr %0, [%1], 4" : "=r" (ret), "+r" (buf));

	fprintf(stderr, "success\n");
	return 0;
}
