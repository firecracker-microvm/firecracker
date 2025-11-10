// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "vmclock-abi.h"

const char *VMCLOCK_DEV_PATH = "/dev/vmclock0";

int open_vmclock(void)
{
  int fd = open(VMCLOCK_DEV_PATH, 0);
  if (fd == -1) {
    perror("open");
    exit(1);
  }

  return fd;
}

struct vmclock_abi *get_vmclock_handle(int fd)
{
  void *ptr = mmap(NULL, sizeof(struct vmclock_abi), PROT_READ, MAP_SHARED, fd, 0);
  if (ptr == MAP_FAILED) {
    perror("mmap");
    exit(1);
  }

  return ptr;
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
READ_VMCLOCK_FIELD_FN(uint64_t, vm_generation_counter);

/*
 * Read `vmclock_abi` structure using a file descriptor pointing to
 * `/dev/vmclock0`.
 */
void read_vmclock(int fd, struct vmclock_abi *vmclock)
{
  int ret;

  /*
   * Use `pread()`, since the device doesn't implement lseek(), so
   * we can't reset `fp`.
   */
  ret = pread(fd, vmclock, sizeof(*vmclock), 0);
  if (ret < 0) {
    perror("read");
    exit(1);
  } else if (ret < (int) sizeof(*vmclock)) {
    fprintf(stderr, "We don't handle partial writes (%d). Exiting!\n", ret);
    exit(1);
  }
}

void print_vmclock(struct vmclock_abi *vmclock)
{
  if (vmclock->flags & VMCLOCK_FLAG_VM_GEN_COUNTER_PRESENT) {
    printf("VMCLOCK_FLAG_VM_GEN_COUNTER_PRESENT: true\n");
  } else {
    printf("VMCLOCK_FLAG_VM_GEN_COUNTER_PRESENT: false\n");
  }

  if (vmclock->flags & VMCLOCK_FLAG_NOTIFICATION_PRESENT) {
    printf("VMCLOCK_FLAG_NOTIFICATION_PRESENT: true\n");
  } else {
    printf("VMCLOCK_FLAG_NOTIFICATION_PRESENT: false\n");
  }

  printf("VMCLOCK_MAGIC: 0x%x\n", vmclock->magic);
  printf("VMCLOCK_SIZE: 0x%x\n", vmclock->size);
  printf("VMCLOCK_VERSION: %u\n", vmclock->version);
  printf("VMCLOCK_CLOCK_STATUS: %u\n", vmclock->clock_status);
  printf("VMCLOCK_COUNTER_ID: %u\n", vmclock->counter_id);
  printf("VMCLOCK_DISRUPTION_MARKER: %lu\n", read_disruption_marker(vmclock));
  printf("VMCLOCK_VM_GENERATION_COUNTER: %lu\n", read_vm_generation_counter(vmclock));
  fflush(stdout);
}

void run_poll(int fd) 
{
  struct vmclock_abi vmclock;
  int epfd, ret, nfds;
  struct epoll_event ev;

  read_vmclock(fd, &vmclock);
  print_vmclock(&vmclock);

  epfd = epoll_create(1);
  if (epfd < 0) {
    perror("epoll_create");
    exit(1);
  }

  ev.events = EPOLLIN | EPOLLRDNORM;
  ev.data.fd = fd;
  ret = epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
  if (ret < 0) {
    perror("epoll_add");
    exit(1);
  }
  
  while (1) {
    nfds = epoll_wait(epfd, &ev, 1, -1);
    if (nfds < 0) {
      perror("epoll_wait");
      exit(1);
    }

    if (ev.data.fd != fd) {
      fprintf(stderr, "Unknown file descriptor %d\n", ev.data.fd);
      exit(1);
    }

    if (ev.events & EPOLLHUP) {
      fprintf(stderr, "Device does not support notifications. Stop polling\n");
      exit(1);
    } else if (ev.events & EPOLLIN) {
      fprintf(stdout, "Got VMClock notification\n");
      read_vmclock(fd, &vmclock);
      print_vmclock(&vmclock);
    }
  }
}

void print_help_message()
{
    fprintf(stderr, "usage: vmclock MODE\n");
    fprintf(stderr, "Available modes:\n");
    fprintf(stderr, "   -r\tRead vmclock_abi using read()\n");
    fprintf(stderr, "   -m\tRead vmclock_abi using mmap()\n");
    fprintf(stderr, "   -p\tPoll VMClock for changes\n");
}

int main(int argc, char *argv[])
{
  int fd;
  struct vmclock_abi vmclock, *vmclock_ptr;

  if (argc != 2) {
    print_help_message();
    exit(1);
  }

  fd = open_vmclock();

  if (!strncmp(argv[1], "-r", 3)) {
    printf("Reading VMClock with read()\n");
    read_vmclock(fd, &vmclock);
    print_vmclock(&vmclock);
  } else if (!strncmp(argv[1], "-m", 3)) {
    printf("Reading VMClock with mmap()\n");
    vmclock_ptr = get_vmclock_handle(fd);
    print_vmclock(vmclock_ptr);
  } else if (!strncmp(argv[1], "-p", 3)) {
    printf("Polling VMClock\n");
    run_poll(fd);
  } else {
    print_help_message();
    exit(1);
  }

  return 0;
}
