// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "vmclock-abi.h"

const char *VMCLOCK_DEV_PATH = "/dev/vmclock0";

int get_vmclock_handle(struct vmclock_abi **vmclock)
{
  int fd = open(VMCLOCK_DEV_PATH, 0);
  if (fd == -1)
    goto out_err;

  void *ptr = mmap(NULL, sizeof(struct vmclock_abi), PROT_READ, MAP_SHARED, fd, 0);
  if (ptr == MAP_FAILED)
    goto out_err_mmap;

  *vmclock = ptr;
  return 0;

out_err_mmap:
  close(fd);
out_err:
  return errno;
}

#define READ_VMCLOCK_FIELD_FN(type, field)                 \
type read##_##field (struct vmclock_abi *vmclock) {        \
  type ret;                                                \
  while (1) {                                              \
    type seq = vmclock->seq_count & ~1ULL;                 \
                                                           \
    /* This matches a write fence in the VMM */            \
    atomic_thread_fence(memory_order_acquire);             \
                                                           \
    ret = vmclock->field;                                  \
                                                           \
    /* This matches a write fence in the VMM */            \
    atomic_thread_fence(memory_order_acquire);             \
    if (seq == vmclock->seq_count)                         \
      break;                                               \
  }                                                        \
                                                           \
  return ret;                                              \
}

READ_VMCLOCK_FIELD_FN(uint64_t, disruption_marker);

int main()
{
  struct vmclock_abi *vmclock;

  int err = get_vmclock_handle(&vmclock);
  if (err) {
    printf("Could not mmap vmclock struct: %s\n", strerror(err));
    exit(1);
  }

  printf("VMCLOCK_MAGIC: 0x%x\n", vmclock->magic);
  printf("VMCLOCK_SIZE: 0x%x\n", vmclock->size);
  printf("VMCLOCK_VERSION: %u\n", vmclock->version);
  printf("VMCLOCK_CLOCK_STATUS: %u\n", vmclock->clock_status);
  printf("VMCLOCK_COUNTER_ID: %u\n", vmclock->counter_id);
  printf("VMCLOCK_DISRUPTION_MARKER: %lu\n", read_disruption_marker(vmclock));

  return 0;
}
